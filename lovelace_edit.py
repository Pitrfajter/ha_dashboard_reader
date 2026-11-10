"""Opt-in, SHA-gated Lovelace card edits through Home Assistant storage API."""
import copy
import hashlib
import json
import re
import time
from pathlib import Path

import voluptuous as vol
from homeassistant.components.llm import LLMTools
from homeassistant.helpers.llm import Tool, ToolAnnotations, ToolResult

CONFIRM = "APPLY_APPROVED_LOVELACE_CARD_CHANGE"
RESTORE = "RESTORE_APPROVED_LOVELACE_BACKUP"
HASH = vol.Match(r"[0-9a-f]{64}")
NAME = re.compile(r"lovelace\.[A-Za-z0-9_-]+\Z")
BACKUP = re.compile(r"lovelace_backup_[0-9]+\.json\Z")
READ = ToolAnnotations(read_only=True, destructive=False, idempotent=True, open_world=False)
WRITE = ToolAnnotations(read_only=False, destructive=True, idempotent=False, open_world=False)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode()).hexdigest()


def storage(hass, name):
    if not NAME.fullmatch(name):
        raise ValueError("Only named storage-mode Lovelace dashboards are supported")
    # Use the public Lovelace dashboard manager rather than editing .storage files.
    manager = hass.data.get("lovelace")
    if manager is None:
        raise ValueError("Lovelace manager is unavailable")
    url_path = name.removeprefix("lovelace.")
    dashboards = getattr(manager, "dashboards", {})
    dashboard = dashboards.get(url_path)
    if dashboard is None or not hasattr(dashboard, "async_save"):
        raise ValueError("Dashboard is not available through the Lovelace storage API")
    if dashboard.__class__.__name__ != "LovelaceStorage":
        raise ValueError("Only storage-mode dashboards may be edited")
    return dashboard


def locate(config, view_index, card_index):
    views = config.get("views", [])
    if type(view_index) is not int or view_index < 0 or view_index >= len(views):
        raise ValueError("Invalid view index")
    view = views[view_index]
    if not isinstance(view.get("cards", []), list):
        raise ValueError("Invalid cards list")
    cards = view.get("cards", [])
    if card_index < 0 or card_index > len(cards):
        raise ValueError("Card index out of range; sections are not supported for edits")
    return cards


def load_draft(hass, filename):
    # Only JSON card drafts. No paths, symlinks, or YAML custom constructors.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\.json", filename):
        raise ValueError("Expected JSON draft basename")
    root = Path(hass.config.config_dir) / "dashboard_reader" / "drafts"
    if root.is_symlink():
        raise ValueError("Unsafe draft directory")
    path = root / filename
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 200000:
        raise ValueError("Draft unavailable or too large")
    card = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(card, dict) or not isinstance(card.get("type"), str):
        raise ValueError("Draft must contain one Lovelace card object")
    return card


def backup_path(hass, filename):
    if not BACKUP.fullmatch(filename):
        raise ValueError("Invalid backup name")
    root = Path(hass.config.config_dir) / "dashboard_reader" / "lovelace_backups"
    if root.is_symlink():
        raise ValueError("Unsafe backup directory")
    root.mkdir(parents=True, exist_ok=True)
    path = root / filename
    if path.is_symlink():
        raise ValueError("Unsafe backup file")
    return path


PARAMS = {
    vol.Required("name"): str,
    vol.Required("view_index"): vol.All(int, vol.Range(min=0)),
    vol.Required("card_index"): vol.All(int, vol.Range(min=0)),
    vol.Required("draft_filename"): str,
    vol.Required("expected_dashboard_sha256"): HASH,
    vol.Required("expected_draft_sha256"): HASH,
}



class LovelaceCardStatus(Tool):
    name = "dashboard_reader__lovelace_card_status"
    title = "Read dashboard SHA and editable card counts"
    description = "Read-only status to prepare SHA-gated Lovelace card edits."
    integration = "dashboard_reader"
    annotations = READ
    parameters = vol.Schema({vol.Required("name"): str})

    async def async_call(self, hass, tool_input, llm_context):
        try:
            config = await storage(hass, tool_input.tool_args["name"]).async_load(False)
            return ToolResult(data={"dashboard_sha256": digest(config),
                                    "views": [{"index": i, "title": v.get("title", ""),
                                               "editable_cards": len(v.get("cards", [])),
                                               "sections": len(v.get("sections", []))}
                                              for i, v in enumerate(config.get("views", []))]})
        except (ValueError, OSError, TypeError, KeyError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)

class PrepareLovelaceCardChange(Tool):
    name = "dashboard_reader__prepare_lovelace_card_change"
    title = "Preview safe Lovelace card replacement"
    description = "Read-only preview of one card replacement; checks dashboard and draft hashes."
    integration = "dashboard_reader"
    annotations = READ
    parameters = vol.Schema(PARAMS)

    async def async_call(self, hass, tool_input, llm_context):
        try:
            args = tool_input.tool_args
            config = await storage(hass, args["name"]).async_load(False)
            current_hash = digest(config)
            card = load_draft(hass, args["draft_filename"])
            if current_hash != args["expected_dashboard_sha256"] or digest(card) != args["expected_draft_sha256"]:
                raise ValueError("SHA256 mismatch")
            cards = locate(config, args["view_index"], args["card_index"])
            return ToolResult(data={"ready_for_approval": True, "dashboard_sha256": current_hash,
                                    "operation": "append" if args["card_index"] == len(cards) else "replace",
                                    "old_card_sha256": digest(cards[args["card_index"]]) if args["card_index"] < len(cards) else None,
                                    "new_card_sha256": digest(card),
                                    "draft_filename": args["draft_filename"]})
        except (ValueError, OSError, TypeError, KeyError, json.JSONDecodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


class ApplyLovelaceCardChange(Tool):
    name = "dashboard_reader__apply_lovelace_card_change"
    title = "Apply approved Lovelace card replacement"
    description = "DANGEROUS: replace one card via Lovelace storage API, with SHA gate and immutable backup."
    integration = "dashboard_reader"
    annotations = WRITE
    parameters = vol.Schema({**PARAMS, vol.Required("confirmation"): vol.In((CONFIRM,))})

    async def async_call(self, hass, tool_input, llm_context):
        try:
            args = tool_input.tool_args
            dashboard = storage(hass, args["name"])
            original = await dashboard.async_load(False)
            if digest(original) != args["expected_dashboard_sha256"]:
                raise ValueError("Dashboard changed; refusing write")
            card = load_draft(hass, args["draft_filename"])
            if digest(card) != args["expected_draft_sha256"]:
                raise ValueError("Draft changed; refusing write")
            updated = copy.deepcopy(original)
            cards = locate(updated, args["view_index"], args["card_index"])
            if args["card_index"] == len(cards):
                cards.append(card)
            else:
                cards[args["card_index"]] = card
            name = "lovelace_backup_" + str(time.time_ns()) + ".json"
            path = backup_path(hass, name)
            record = {"dashboard": args["name"], "before": original,
                      "old_sha256": digest(original), "new_sha256": digest(updated)}
            with path.open("x", encoding="utf-8") as handle:
                json.dump(record, handle, ensure_ascii=False)
            await dashboard.async_save(updated)
            return ToolResult(data={"installed": True, "backup": name,
                                    "dashboard_sha256": digest(updated)})
        except (ValueError, OSError, TypeError, KeyError, json.JSONDecodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


class RestoreLovelaceCardBackup(Tool):
    name = "dashboard_reader__restore_lovelace_card_backup"
    title = "Restore approved Lovelace dashboard backup"
    description = "DANGEROUS: restore backup only if current dashboard matches the applied SHA."
    integration = "dashboard_reader"
    annotations = WRITE
    parameters = vol.Schema({
        vol.Required("backup"): str,
        vol.Required("expected_current_sha256"): HASH,
        vol.Required("confirmation"): vol.In((RESTORE,)),
    })

    async def async_call(self, hass, tool_input, llm_context):
        try:
            args = tool_input.tool_args
            record = json.loads(backup_path(hass, args["backup"]).read_text(encoding="utf-8"))
            dashboard = storage(hass, record["dashboard"])
            current = await dashboard.async_load(False)
            if digest(current) != args["expected_current_sha256"] or digest(current) != record["new_sha256"]:
                raise ValueError("Dashboard changed; refusing restore")
            if digest(record["before"]) != record["old_sha256"]:
                raise ValueError("Backup integrity check failed")
            await dashboard.async_save(record["before"])
            return ToolResult(data={"restored": True, "dashboard_sha256": record["old_sha256"]})
        except (ValueError, OSError, TypeError, KeyError, json.JSONDecodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)
