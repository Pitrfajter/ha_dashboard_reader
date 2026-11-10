"""Safe Lovelace dashboard inspection and export tools for Home Assistant."""

import hashlib
import urllib.request
import urllib.parse
import ipaddress
import socket
import os
import tempfile
import copy

import yaml
import json
import re
import time
from pathlib import Path

import voluptuous as vol
from homeassistant.components.llm import LLMTools
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.llm import (
    LLMContext, Tool, ToolAnnotations, ToolInput, ToolResult,
)

DOMAIN = "dashboard_reader"
MAX_FILE_BYTES = 2_000_000
MAX_RESPONSE_CHARS = 1_000_000
MAX_EXPORT_BYTES = 2_000_000
CHUNK_LIMIT = 12000

READ_ONLY = ToolAnnotations(
    read_only=True, destructive=False, idempotent=True, open_world=False
)
EXPORT_ANNOTATIONS = ToolAnnotations(
    read_only=False, destructive=False, idempotent=False, open_world=False
)
SECRET_KEYS = re.compile(
    r"password|passwd|secret|token|api[_-]?key|authorization|"
    r"credential|client[_-]?secret|access[_-]?key|private[_-]?key|cookie",
    re.IGNORECASE,
)
SECRET_VALUES = re.compile(
    r"(?i)(bearer\s+)[^\s\"']+|"
    r"([?&](?:token|key|password|secret|access_token|api_key)=)[^&\s\"']+"
)
# Credentials in URL userinfo (including percent-encoded passwords) must never
# be returned, even when embedded in YAML commands or quoted strings.
URL_USERINFO = re.compile(
    r"(?i)(\b[a-z][a-z0-9+.-]*://)([^\s\"\'<>\\]+?)@(?=[^\s\"\'<>/\\]+)"
)


def redact_inline_secrets(value: str) -> str:
    """Mask inline credentials before returning any configuration text."""
    value = URL_USERINFO.sub(lambda m: m.group(1) + "[REDACTED]@", value)
    return SECRET_VALUES.sub(
        lambda m: (m.group(1) or m.group(2)) + "[REDACTED]", value
    )

EXPORT_NAME = re.compile(r"[A-Za-z0-9_.-]+\.json\Z")


def sanitize(value, depth=0):
    """Redact common secrets and limit nesting."""
    if depth > 30:
        return "[DEPTH LIMIT]"
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if SECRET_KEYS.search(str(key))
            else sanitize(item, depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize(item, depth + 1) for item in value]
    if isinstance(value, str):
        return redact_inline_secrets(value)
    return value


def dashboard_files(hass):
    storage = Path(hass.config.config_dir) / ".storage"
    return {
        path.name: path for path in storage.glob("lovelace.*")
        if path.is_file() and not path.is_symlink()
    }


def load_dashboard(hass, name):
    files = dashboard_files(hass)
    if name not in files:
        raise ValueError("Dashboard not found")
    path = files[name]
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Dashboard file too large")
    with path.open("r", encoding="utf-8") as stream:
        data = json.load(stream)
    config = data.get("data", {}).get("config", {})
    if not isinstance(config, dict):
        raise ValueError("Invalid dashboard configuration")
    return config


def get_view_cards(view):
    cards = list(view.get("cards", []))
    for section in view.get("sections", []):
        cards.extend(section.get("cards", []))
    return cards


def get_card(hass, name, view_index, card_index):
    config = load_dashboard(hass, name)
    views = config.get("views", [])
    if view_index >= len(views):
        raise ValueError("View index out of range")
    cards = get_view_cards(views[view_index])
    if card_index >= len(cards):
        raise ValueError("Card index out of range")
    return cards[card_index]


def safe_result(data):
    cleaned = sanitize(data)
    encoded = json.dumps(cleaned, ensure_ascii=False)
    if len(encoded) > MAX_RESPONSE_CHARS:
        return {
            "error": "Response too large",
            "message": "Use dashboard_reader__get_fragment to read in chunks.",
            "characters": len(encoded),
        }
    return cleaned


def exports_dir(hass):
    return Path(hass.config.config_dir) / "dashboard_reader" / "exports"


def validated_export(hass, filename):
    """Restrict reads to regular JSON files in the dedicated exports directory."""
    if not EXPORT_NAME.fullmatch(filename) or filename in (".", ".."):
        raise ValueError("Invalid export filename")
    root = exports_dir(hass)
    if root.is_symlink():
        raise ValueError("Export directory cannot be a symlink")
    path = root / filename
    if path.is_symlink() or not path.is_file():
        raise ValueError("Export not found or invalid file type")
    if path.stat().st_size > MAX_EXPORT_BYTES:
        raise ValueError("Export file too large")
    return path


def read_export(hass, filename):
    path = validated_export(hass, filename)
    with path.open("r", encoding="utf-8") as stream:
        content = stream.read(MAX_EXPORT_BYTES + 1)
    if len(content.encode("utf-8")) > MAX_EXPORT_BYTES:
        raise ValueError("Export file too large")
    # Validate the file and redact again, including externally modified exports.
    value = sanitize(json.loads(content))
    return json.dumps(value, ensure_ascii=False, indent=2)


class ListDashboards(Tool):
    name = "dashboard_reader__list"
    title = "List dashboards"
    description = "List Lovelace dashboard storage filenames."
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({})

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        files = await hass.async_add_executor_job(dashboard_files, hass)
        return ToolResult(data={"dashboards": sorted(files)})


class ReadDashboard(Tool):
    name = "dashboard_reader__read"
    title = "Inspect dashboard"
    description = "List dashboard views and card counts using its storage filename."
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({vol.Required("name"): str})

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        name = tool_input.tool_args["name"]

        def read():
            config = load_dashboard(hass, name)
            return {
                "dashboard": name,
                "views": [
                    {"index": index, "title": view.get("title", ""),
                     "cards": len(get_view_cards(view))}
                    for index, view in enumerate(config.get("views", []))
                ],
            }
        try:
            return ToolResult(data=safe_result(
                await hass.async_add_executor_job(read)))
        except (ValueError, OSError, TypeError, json.JSONDecodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


CARD_PARAMS = {
    vol.Required("name"): str,
    vol.Required("view_index"): vol.All(int, vol.Range(min=0)),
    vol.Required("card_index"): vol.All(int, vol.Range(min=0)),
}


class GetCard(Tool):
    name = "dashboard_reader__get_card"
    title = "Read Lovelace card"
    description = (
        "Read a card using zero-based view and card indices. "
        "Sections are flattened in stored order. Redacted and size-limited."
    )
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema(CARD_PARAMS)

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        args = tool_input.tool_args

        def read():
            return {
                "dashboard": args["name"],
                "view_index": args["view_index"],
                "card_index": args["card_index"],
                "configuration": get_card(
                    hass, args["name"], args["view_index"], args["card_index"]
                ),
            }
        try:
            return ToolResult(data=safe_result(
                await hass.async_add_executor_job(read)))
        except (ValueError, OSError, TypeError, json.JSONDecodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


class GetFragment(Tool):
    name = "dashboard_reader__get_fragment"
    title = "Read Lovelace card fragment"
    description = (
        "Read a card subtree at a path of dictionary keys or list indices. "
        "Offset and limit split long JSON text; max 12000 characters per call."
    )
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({
        **CARD_PARAMS,
        vol.Optional("path", default=[]): [
            vol.Any(str, vol.All(int, vol.Range(min=0)))
        ],
        vol.Optional("offset", default=0): vol.All(int, vol.Range(min=0)),
        vol.Optional("limit", default=8000): vol.All(
            int, vol.Range(min=1, max=CHUNK_LIMIT)
        ),
    })

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        args = tool_input.tool_args

        def read():
            value = get_card(
                hass, args["name"], args["view_index"], args["card_index"]
            )
            for part in args.get("path", []):
                if isinstance(value, dict) and isinstance(part, str):
                    if part not in value:
                        raise ValueError("Key not found")
                    value = value[part]
                elif isinstance(value, list) and type(part) is int:
                    if part >= len(value):
                        raise ValueError("Index out of range")
                    value = value[part]
                else:
                    raise ValueError("Invalid path")
            encoded = json.dumps(sanitize(value), ensure_ascii=False, indent=2)
            offset, limit = args.get("offset", 0), args.get("limit", 8000)
            next_offset = min(offset + limit, len(encoded))
            return {
                "dashboard": args["name"],
                "view_index": args["view_index"],
                "card_index": args["card_index"],
                "path": args.get("path", []),
                "offset": offset,
                "limit": limit,
                "total_characters": len(encoded),
                "has_more": next_offset < len(encoded),
                "next_offset": next_offset if next_offset < len(encoded) else None,
                "chunk": encoded[offset:offset + limit],
            }
        try:
            return ToolResult(data=await hass.async_add_executor_job(read))
        except (ValueError, OSError, TypeError, json.JSONDecodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


class ExportCard(Tool):
    name = "dashboard_reader__export_card"
    title = "Export Lovelace card to JSON file"
    description = (
        "Export a redacted Lovelace card to /config/dashboard_reader/exports/. "
        "Original dashboard is unchanged. File stays on Home Assistant."
    )
    integration = DOMAIN
    annotations = EXPORT_ANNOTATIONS
    parameters = vol.Schema(CARD_PARAMS)

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        args = tool_input.tool_args

        def export():
            card = sanitize(get_card(
                hass, args["name"], args["view_index"], args["card_index"]
            ))
            encoded = json.dumps(card, ensure_ascii=False, indent=2)
            if len(encoded) > MAX_RESPONSE_CHARS:
                raise ValueError("Card exceeds 1,000,000 characters")
            root = exports_dir(hass)
            if root.is_symlink():
                raise ValueError("Export directory cannot be a symlink")
            root.mkdir(parents=True, exist_ok=True)
            safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", args["name"])
            filename = (
                f"{safe_name}_view{args['view_index']}_card"
                f"{args['card_index']}_{time.time_ns()}.json"
            )
            path = root / filename
            with path.open("x", encoding="utf-8") as stream:
                stream.write(encoded)
            return {
                "exported": True,
                "filename": filename,
                "path": str(path),
                "characters": len(encoded),
                "sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
                "redacted": True,
                "note": "File stays on Home Assistant; use read_export for chunks.",
            }
        try:
            return ToolResult(data=await hass.async_add_executor_job(export))
        except (ValueError, OSError, TypeError, json.JSONDecodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


class ListExports(Tool):
    name = "dashboard_reader__list_exports"
    title = "List exported Lovelace JSON files"
    description = "List available JSON files in the dedicated dashboard exports folder."
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({})

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        def listing():
            root = exports_dir(hass)
            if root.is_symlink():
                raise ValueError("Export directory cannot be a symlink")
            if not root.exists():
                return {"exports": []}
            items = []
            for path in root.iterdir():
                if not EXPORT_NAME.fullmatch(path.name) or path.is_symlink() or not path.is_file():
                    continue
                size = path.stat().st_size
                if size <= MAX_EXPORT_BYTES:
                    items.append({"filename": path.name, "bytes": size})
            return {"exports": sorted(items, key=lambda item: item["filename"])}
        try:
            return ToolResult(data=await hass.async_add_executor_job(listing))
        except (ValueError, OSError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


class ReadExport(Tool):
    name = "dashboard_reader__read_export"
    title = "Read an exported Lovelace JSON file"
    description = (
        "Read a redacted JSON export by filename (not absolute path). "
        "Returns text chunks of at most 12000 characters with SHA256 and offsets. "
        "The file is not automatically attached or downloaded to ChatGPT."
    )
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({
        vol.Required("filename"): str,
        vol.Optional("offset", default=0): vol.All(int, vol.Range(min=0)),
        vol.Optional("limit", default=8000): vol.All(
            int, vol.Range(min=1, max=CHUNK_LIMIT)
        ),
    })

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        args = tool_input.tool_args

        def read():
            encoded = read_export(hass, args["filename"])
            if len(encoded) > MAX_RESPONSE_CHARS:
                raise ValueError("Export exceeds 1,000,000 characters")
            offset, limit = args.get("offset", 0), args.get("limit", 8000)
            next_offset = min(offset + limit, len(encoded))
            return {
                "filename": args["filename"],
                "offset": offset,
                "limit": limit,
                "total_characters": len(encoded),
                "has_more": next_offset < len(encoded),
                "next_offset": next_offset if next_offset < len(encoded) else None,
                "sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
                "chunk": encoded[offset:offset + limit],
            }
        try:
            return ToolResult(data=await hass.async_add_executor_job(read))
        except (ValueError, OSError, TypeError, json.JSONDecodeError, UnicodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)



# Drafts are deliberately isolated from .storage, scripts.yaml and configuration.yaml.
DRAFT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\.(?:yaml|yml|json)\Z")
MAX_DRAFT_BYTES = 2_000_000


def drafts_dir(hass):
    return Path(hass.config.config_dir) / "dashboard_reader" / "drafts"


def draft_path(hass, filename, must_exist=False):
    if not isinstance(filename, str) or not DRAFT_NAME.fullmatch(filename):
        raise ValueError("Invalid draft filename; use a .yaml, .yml or .json basename")
    root = drafts_dir(hass)
    if root.is_symlink():
        raise ValueError("Draft directory must not be a symlink")
    path = root / filename
    if path.is_symlink():
        raise ValueError("Draft must not be a symlink")
    if must_exist and not path.is_file():
        raise ValueError("Draft not found")
    if path.exists() and not path.is_file():
        raise ValueError("Draft is not a regular file")
    return path


def hash_text(content):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def read_draft_text(hass, filename):
    path = draft_path(hass, filename, must_exist=True)
    if path.stat().st_size > MAX_DRAFT_BYTES:
        raise ValueError("Draft too large")
    with path.open("r", encoding="utf-8") as stream:
        content = stream.read(MAX_DRAFT_BYTES + 1)
    if len(content.encode("utf-8")) > MAX_DRAFT_BYTES:
        raise ValueError("Draft too large")
    return content


def atomic_write_draft(hass, filename, content, *, expected_sha256=None,
                       create_only=False):
    if len(content.encode("utf-8")) > MAX_DRAFT_BYTES:
        raise ValueError("Draft too large")
    path = draft_path(hass, filename)
    if create_only and path.exists():
        raise ValueError("Draft already exists")
    if expected_sha256 is not None:
        if not path.exists() or hash_text(read_draft_text(hass, filename)) != expected_sha256:
            raise ValueError("Draft changed since it was read (SHA256 mismatch)")
    root = path.parent
    root.mkdir(parents=True, exist_ok=True)
    # Atomic replacement avoids half-written drafts; never writes to original HA configs.
    fd, tmp = tempfile.mkstemp(prefix=".draft_", dir=str(root))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
        if path.is_symlink():
            raise ValueError("Draft must not be a symlink")
        if create_only and path.exists():
            raise ValueError("Draft already exists")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return {"filename": filename, "path": str(path),
            "characters": len(content), "sha256": hash_text(content),
            "note": "Draft stored on Home Assistant, not automatically attached to ChatGPT"}


def serialize_draft(value, filename):
    if filename.endswith(".json"):
        return json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    return yaml.safe_dump(value, allow_unicode=True, sort_keys=False, width=120)


class ListDrafts(Tool):
    name = "dashboard_reader__list_drafts"
    title = "List safe draft files"
    description = "List generated YAML/JSON drafts, never live HA configuration files."
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({})

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        def run():
            root = drafts_dir(hass)
            if root.is_symlink():
                raise ValueError("Draft directory must not be a symlink")
            if not root.exists():
                return {"drafts": []}
            return {"drafts": sorted(
                ({"filename": path.name, "bytes": path.stat().st_size}
                 for path in root.iterdir()
                 if DRAFT_NAME.fullmatch(path.name) and path.is_file()
                 and not path.is_symlink() and path.stat().st_size <= MAX_DRAFT_BYTES),
                key=lambda item: item["filename"])}
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


class ReadDraft(Tool):
    name = "dashboard_reader__read_draft"
    title = "Read a YAML or JSON draft in chunks"
    description = "Read a draft from the isolated drafts directory, 12000 characters per call."
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({
        vol.Required("filename"): str,
        vol.Optional("offset", default=0): vol.All(int, vol.Range(min=0)),
        vol.Optional("limit", default=8000): vol.All(int, vol.Range(min=1, max=CHUNK_LIMIT)),
    })

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        args = tool_input.tool_args
        def run():
            content = read_draft_text(hass, args["filename"])
            start = args.get("offset", 0)
            end = min(start + args.get("limit", 8000), len(content))
            return {"filename": args["filename"], "offset": start,
                    "total_characters": len(content),
                    "sha256": hash_text(content),
                    "chunk": content[start:end], "has_more": end < len(content),
                    "next_offset": end if end < len(content) else None}
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError, UnicodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


class CreateCardDraft(Tool):
    name = "dashboard_reader__create_card_draft"
    title = "Create complete YAML or JSON draft from a Lovelace card"
    description = (
        "Create a redacted full card draft in /config/dashboard_reader/drafts/. "
        "Uses zero-based view and card indices. Never modifies the live dashboard. "
        "Filename must be new and end in .yaml, .yml or .json."
    )
    integration = DOMAIN
    annotations = EXPORT_ANNOTATIONS
    parameters = vol.Schema({
        **CARD_PARAMS, vol.Required("filename"): str,
    })

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        args = tool_input.tool_args
        def run():
            value = sanitize(get_card(hass, args["name"],
                                      args["view_index"], args["card_index"]))
            return atomic_write_draft(
                hass, args["filename"], serialize_draft(value, args["filename"]),
                create_only=True,
            )
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError, TypeError, yaml.YAMLError,
                json.JSONDecodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


class PatchCardDraft(Tool):
    name = "dashboard_reader__patch_card_draft"
    title = "Safely replace one value in an existing card draft"
    description = (
        "Replace an existing key or list item inside a YAML/JSON draft. "
        "Requires SHA256 of the draft to prevent accidental overwrites. "
        "Only draft files can be changed; live Lovelace is untouched. "
        "Path example: ['cards', 2, 'cards', 0, 'tap_action']."
    )
    integration = DOMAIN
    annotations = ToolAnnotations(read_only=False, destructive=False,
                                  idempotent=False, open_world=False)
    parameters = vol.Schema({
        vol.Required("filename"): str,
        vol.Required("expected_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("path"): [vol.Any(str, vol.All(int, vol.Range(min=0)))],
        vol.Required("value"): object,
    })

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        args = tool_input.tool_args
        def run():
            content = read_draft_text(hass, args["filename"])
            if hash_text(content) != args["expected_sha256"]:
                raise ValueError("Draft changed since it was read (SHA256 mismatch)")
            if args["filename"].endswith(".json"):
                value = json.loads(content)
            else:
                value = yaml.safe_load(content)
            path = args["path"]
            if not path:
                raise ValueError("Patch path cannot be empty")
            target = value
            for part in path[:-1]:
                if isinstance(target, dict) and isinstance(part, str) and part in target:
                    target = target[part]
                elif isinstance(target, list) and type(part) is int and part < len(target):
                    target = target[part]
                else:
                    raise ValueError("Patch path does not exist")
            last = path[-1]
            if isinstance(target, dict) and isinstance(last, str) and last in target:
                target[last] = sanitize(args["value"])
            elif isinstance(target, list) and type(last) is int and last < len(target):
                target[last] = sanitize(args["value"])
            else:
                raise ValueError("Patch target does not exist")
            return atomic_write_draft(
                hass, args["filename"], serialize_draft(value, args["filename"]),
                expected_sha256=args["expected_sha256"],
            )
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError, TypeError, yaml.YAMLError,
                json.JSONDecodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


class CreateTextDraft(Tool):
    name = "dashboard_reader__create_text_draft"
    title = "Create a new YAML or JSON draft from text"
    description = (
        "Create a new text draft up to 12000 characters in the isolated drafts folder. "
        "For larger drafts use append_text_draft with SHA256. Does not touch live HA files."
    )
    integration = DOMAIN
    annotations = EXPORT_ANNOTATIONS
    parameters = vol.Schema({
        vol.Required("filename"): str,
        vol.Required("content"): vol.All(str, vol.Length(max=CHUNK_LIMIT)),
    })

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        args = tool_input.tool_args
        def run():
            return atomic_write_draft(hass, args["filename"],
                                      args["content"], create_only=True)
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


class AppendTextDraft(Tool):
    name = "dashboard_reader__append_text_draft"
    title = "Append text to an existing YAML or JSON draft"
    description = (
        "Append up to 12000 characters, requiring current SHA256 for consistency. "
        "Only isolated drafts can be modified, not live HA configuration."
    )
    integration = DOMAIN
    annotations = EXPORT_ANNOTATIONS
    parameters = vol.Schema({
        vol.Required("filename"): str,
        vol.Required("expected_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("content"): vol.All(str, vol.Length(max=CHUNK_LIMIT)),
    })

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        args = tool_input.tool_args
        def run():
            existing = read_draft_text(hass, args["filename"])
            if hash_text(existing) != args["expected_sha256"]:
                raise ValueError("Draft changed since it was read (SHA256 mismatch)")
            return atomic_write_draft(
                hass, args["filename"], existing + args["content"],
                expected_sha256=args["expected_sha256"],
            )
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)



# Only these two configuration files can be inspected; no arbitrary filesystem reads.
CONFIG_READ_ALLOWLIST = frozenset(("scripts.yaml", "configuration.yaml"))
CONFIG_READ_MAX_BYTES = 1_000_000
SENSITIVE_LINE = re.compile(
    r"(?i)^([ \t-]*)([\w.-]*(?:password|passwd|secret|token|api_key|"
    r"authorization|credential|private_key|access_key|client_secret|cookie)"
    r"[\w.-]*)([ \t]*:)(.*)$"
)


def read_safe_config(hass, filename):
    """Read only explicitly permitted HA YAML files, masking sensitive values."""
    if filename not in CONFIG_READ_ALLOWLIST:
        raise ValueError("Only scripts.yaml and configuration.yaml are permitted")
    root = Path(hass.config.config_dir)
    path = root / filename
    if path.is_symlink() or not path.is_file():
        raise ValueError("Configuration file not found or is a symlink")
    if path.stat().st_size > CONFIG_READ_MAX_BYTES:
        raise ValueError("Configuration file exceeds safe size limit")
    content = path.read_text(encoding="utf-8")
    if len(content.encode("utf-8")) > CONFIG_READ_MAX_BYTES:
        raise ValueError("Configuration file exceeds safe size limit")
    # Keep structure readable without disclosing credential values. Also mask
    # lines nested beneath sensitive keys (e.g. multiline tokens/passwords).
    output = []
    hidden_indent = None
    for line in content.splitlines(keepends=True):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" \t"))
        if hidden_indent is not None:
            if not stripped or stripped.startswith("#"):
                output.append("\n" if line.endswith("\n") else "")
                continue
            if indent > hidden_indent:
                output.append(" " * indent + "[REDACTED]" + ("\n" if line.endswith("\n") else ""))
                continue
            hidden_indent = None
        match = SENSITIVE_LINE.match(line)
        if match:
            output.append(match.group(1) + match.group(2) + match.group(3) +
                          " [REDACTED]" + ("\n" if line.endswith("\n") else ""))
            if not match.group(4).strip():
                hidden_indent = indent
        else:
            output.append(redact_inline_secrets(line))
    return "".join(output)


class ReadHAConfig(Tool):
    name = "dashboard_reader__read_ha_config"
    title = "Read selected Home Assistant YAML configuration"
    description = (
        "Read-only, redacted, chunked inspection of scripts.yaml or "
        "configuration.yaml in the HA config directory. No other files allowed. "
        "Does not modify HA configuration."
    )
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({
        vol.Required("filename"): vol.In(("scripts.yaml", "configuration.yaml")),
        vol.Optional("offset", default=0): vol.All(int, vol.Range(min=0)),
        vol.Optional("limit", default=8000): vol.All(int, vol.Range(min=1, max=CHUNK_LIMIT)),
    })

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        args = tool_input.tool_args
        def run():
            content = read_safe_config(hass, args["filename"])
            # Return a separate hash of the unmodified file bytes for safe
            # compare-and-swap writes. Never return unredacted file contents.
            config_path = Path(hass.config.config_dir) / args["filename"]
            if config_path.is_symlink() or not config_path.is_file():
                raise ValueError("Configuration file not found or is a symlink")
            original_bytes = config_path.read_bytes()
            if len(original_bytes) > CONFIG_READ_MAX_BYTES:
                raise ValueError("Configuration file exceeds safe size limit")
            original_sha256 = _hash_bytes(original_bytes)
            start = args.get("offset", 0)
            end = min(start + args.get("limit", 8000), len(content))
            return {"filename": args["filename"], "offset": start,
                    "total_characters": len(content),
                    "sha256": hash_text(content),
                    "chunk": content[start:end], "has_more": end < len(content),
                    "next_offset": end if end < len(content) else None}
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError, UnicodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)



# Self-update is intentionally restricted to this integration's llm.py.
# Staging never changes the live integration. Applying requires an explicit
# user-approved confirmation, hashes for BOTH files, and creates a backup.
UPDATE_MAX_BYTES = 500_000
UPDATE_CONFIRM = "APPLY_DASHBOARD_READER_LLM_UPDATE"
ROLLBACK_CONFIRM = "RESTORE_DASHBOARD_READER_LLM_BACKUP"


def update_paths(hass):
    base = Path(hass.config.config_dir) / "custom_components" / DOMAIN
    return base / "llm.py", base / ".llm_update_staged.py", base / ".llm_update_backup.py"


def _safe_update_file(path, *, must_exist=False):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("Update file must be a regular file, not a symlink")
    if must_exist and not path.is_file():
        raise ValueError("Update file not found")
    if path.exists() and path.stat().st_size > UPDATE_MAX_BYTES:
        raise ValueError("Update file too large")


def _read_update_file(path):
    _safe_update_file(path, must_exist=True)
    data = path.read_bytes()
    if len(data) > UPDATE_MAX_BYTES:
        raise ValueError("Update file too large")
    return data


def _hash_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _check_python_source(data):
    source = data.decode("utf-8")
    if len(data) > UPDATE_MAX_BYTES:
        raise ValueError("Source exceeds update limit")
    compile(source, "llm.py", "exec")
    if 'dashboard_reader__' not in source or 'async_get_tools' not in source:
        raise ValueError("Not a recognizable dashboard_reader llm.py")


def _atomic_update_bytes(path, data):
    _safe_update_file(path)
    fd, temp = tempfile.mkstemp(prefix=".llm_update_", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _safe_update_file(path)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


class LLMUpdateStatus(Tool):
    name = "dashboard_reader__llm_update_status"
    title = "Inspect dashboard_reader self-update status"
    description = "Read hashes and sizes of only the live llm.py, staged update and backup. No file contents or changes."
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({})

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        def run():
            live, staged, backup = update_paths(hass)
            result = {}
            for label, path in (("live", live), ("staged", staged), ("backup", backup)):
                _safe_update_file(path)
                result[label] = ({"sha256": _hash_bytes(_read_update_file(path)),
                                  "bytes": path.stat().st_size} if path.exists() else None)
            return result
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


class StageLLMUpdate(Tool):
    name = "dashboard_reader__stage_llm_update"
    title = "Stage a dashboard_reader llm.py update in chunks"
    description = (
        "Write source text ONLY to the fixed .llm_update_staged.py file, not the live file. "
        "First chunk: offset=0, expected_sha256=64 zeroes. Subsequent chunks require "
        "the exact current staged byte size and SHA256. Max 12000 characters/chunk. "
        "Final source is syntax-checked when applying. Never send secrets."
    )
    integration = DOMAIN
    annotations = EXPORT_ANNOTATIONS
    parameters = vol.Schema({
        vol.Required("offset"): vol.All(int, vol.Range(min=0)),
        vol.Required("expected_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("content"): vol.All(str, vol.Length(min=1, max=CHUNK_LIMIT)),
    })

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        args = tool_input.tool_args
        def run():
            _, staged, _ = update_paths(hass)
            _safe_update_file(staged)
            existing = _read_update_file(staged) if staged.exists() else b""
            expected = args["expected_sha256"]
            if args["offset"] == 0 and expected == "0" * 64:
                # Only explicit initial chunk can replace an earlier staged update.
                existing = b""
            elif args["offset"] != len(existing) or expected != _hash_bytes(existing):
                raise ValueError("Staged offset or SHA256 mismatch")
            data = existing + args["content"].encode("utf-8")
            if len(data) > UPDATE_MAX_BYTES:
                raise ValueError("Staged update too large")
            _atomic_update_bytes(staged, data)
            return {"staged_bytes": len(data), "staged_sha256": _hash_bytes(data),
                    "live_unchanged": True}
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError, UnicodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


class ApplyLLMUpdate(Tool):
    name = "dashboard_reader__apply_llm_update"
    title = "Apply approved dashboard_reader llm.py update with backup"
    description = (
        "DANGEROUS: Replaces ONLY dashboard_reader/llm.py with staged Python code. "
        "Call ONLY after the user explicitly approves this specific update. "
        "Requires exact live and staged SHA256 and confirmation string "
        "APPLY_DASHBOARD_READER_LLM_UPDATE. Saves previous live file to "
        ".llm_update_backup.py; rejects an existing backup to avoid overwriting it. "
        "Does not reload Home Assistant."
    )
    integration = DOMAIN
    annotations = ToolAnnotations(read_only=False, destructive=True, idempotent=False, open_world=False)
    parameters = vol.Schema({
        vol.Required("expected_live_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("expected_staged_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("confirmation"): vol.In((UPDATE_CONFIRM,)),
    })

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        args = tool_input.tool_args
        def run():
            live, staged, backup = update_paths(hass)
            live_data = _read_update_file(live)
            staged_data = _read_update_file(staged)
            _safe_update_file(backup)
            if backup.exists():
                raise ValueError("Existing backup must be restored or manually archived first")
            if _hash_bytes(live_data) != args["expected_live_sha256"]:
                raise ValueError("Live SHA256 mismatch")
            if _hash_bytes(staged_data) != args["expected_staged_sha256"]:
                raise ValueError("Staged SHA256 mismatch")
            try:
                _check_python_source(staged_data)
            except (SyntaxError, UnicodeError) as exc:
                raise ValueError("Staged Python syntax/encoding invalid") from exc
            _atomic_update_bytes(backup, live_data)
            try:
                _atomic_update_bytes(live, staged_data)
            except OSError:
                _atomic_update_bytes(live, live_data)
                raise
            return {"updated": True, "live_sha256": _hash_bytes(staged_data),
                    "backup_sha256": _hash_bytes(live_data),
                    "note": "Restart Home Assistant to load the new llm.py"}
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


class RestoreLLMBackup(Tool):
    name = "dashboard_reader__restore_llm_backup"
    title = "Restore approved previous dashboard_reader llm.py"
    description = (
        "DANGEROUS: Restores ONLY dashboard_reader/llm.py from its dedicated backup. "
        "Call ONLY after explicit user approval. Requires exact live/backup hashes and "
        "confirmation RESTORE_DASHBOARD_READER_LLM_BACKUP. "
        "Backup remains available; Home Assistant restart is required."
    )
    integration = DOMAIN
    annotations = ToolAnnotations(read_only=False, destructive=True, idempotent=False, open_world=False)
    parameters = vol.Schema({
        vol.Required("expected_live_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("expected_backup_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("confirmation"): vol.In((ROLLBACK_CONFIRM,)),
    })

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        args = tool_input.tool_args
        def run():
            live, _, backup = update_paths(hass)
            live_data = _read_update_file(live)
            backup_data = _read_update_file(backup)
            if _hash_bytes(live_data) != args["expected_live_sha256"]:
                raise ValueError("Live SHA256 mismatch")
            if _hash_bytes(backup_data) != args["expected_backup_sha256"]:
                raise ValueError("Backup SHA256 mismatch")
            try:
                _check_python_source(backup_data)
            except (SyntaxError, UnicodeError) as exc:
                raise ValueError("Backup Python syntax/encoding invalid") from exc
            _atomic_update_bytes(live, backup_data)
            return {"restored": True, "live_sha256": _hash_bytes(backup_data),
                    "note": "Restart Home Assistant to load the restored llm.py"}
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)




# Deliberately narrow write access: append a NEW script from a local draft.
# Never replace existing script keys, other HA files, or arbitrary YAML.
SCRIPT_APPLY_CONFIRM = "APPEND_NEW_SCRIPT_TO_SCRIPTS_YAML"
SCRIPT_MAX_BYTES = 500_000


class AppendScriptFromDraft(Tool):
    name = "dashboard_reader__append_script_from_draft"
    title = "Append a new script from a draft to scripts.yaml (with backup)"
    description = (
        "DANGEROUS: Changes ONLY /config/scripts.yaml by adding one NEW top-level "
        "script from a previously created YAML draft. Existing script entries "
        "are preserved. Requires explicit user approval, exact SHA256 of "
        "scripts.yaml and the draft, and confirmation "
        "APPEND_NEW_SCRIPT_TO_SCRIPTS_YAML. Creates a timestamped backup "
        "before writing. Never edits configuration.yaml or existing scripts."
    )
    integration = DOMAIN
    annotations = ToolAnnotations(
        read_only=False, destructive=True, idempotent=False, open_world=False
    )
    parameters = vol.Schema({
        vol.Required("draft_filename"): str,
        vol.Required("expected_scripts_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("expected_draft_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("confirmation"): vol.In((SCRIPT_APPLY_CONFIRM,)),
    })

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        args = tool_input.tool_args

        def run():
            root = Path(hass.config.config_dir)
            scripts = root / "scripts.yaml"
            if scripts.is_symlink() or not scripts.is_file():
                raise ValueError("scripts.yaml missing or is a symlink")
            original = scripts.read_bytes()
            if len(original) > SCRIPT_MAX_BYTES:
                raise ValueError("scripts.yaml too large")
            if _hash_bytes(original) != args["expected_scripts_sha256"]:
                raise ValueError("scripts.yaml changed: SHA256 mismatch")
            draft = read_draft_text(hass, args["draft_filename"])
            if hash_text(draft) != args["expected_draft_sha256"]:
                raise ValueError("Draft changed: SHA256 mismatch")
            if not args["draft_filename"].endswith((".yaml", ".yml")):
                raise ValueError("Script draft must be YAML")
            current = yaml.safe_load(original.decode("utf-8")) or {}
            incoming = yaml.safe_load(draft)
            if not isinstance(current, dict) or not isinstance(incoming, dict) or len(incoming) != 1:
                raise ValueError("Expected exactly one top-level script in draft")
            script_id, definition = next(iter(incoming.items()))
            if not isinstance(script_id, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", script_id):
                raise ValueError("Invalid script ID")
            if script_id in current:
                raise ValueError("Script already exists; will not overwrite")
            if not isinstance(definition, dict) or not isinstance(definition.get("sequence"), list):
                raise ValueError("Script must have a sequence list")
            # Validate the appended snippet without reformatting existing YAML.
            addition = yaml.safe_dump({script_id: definition}, allow_unicode=True,
                                      sort_keys=False)
            separator = "" if original.endswith(b"\n") else "\n"
            updated = original + (separator + "\n" + addition).encode("utf-8")
            if len(updated) > SCRIPT_MAX_BYTES:
                raise ValueError("Updated scripts.yaml too large")
            backup_dir = root / "dashboard_reader" / "backups"
            if backup_dir.is_symlink():
                raise ValueError("Backup directory is a symlink")
            backup_dir.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
            backup = backup_dir / ("scripts_" + stamp + "_" + _hash_bytes(original)[:12] + ".yaml")
            if backup.exists() or backup.is_symlink():
                raise ValueError("Backup name collision")
            with backup.open("xb") as handle:
                handle.write(original)
                handle.flush()
                os.fsync(handle.fileno())
            fd, tmp = tempfile.mkstemp(prefix=".scripts_update_", dir=str(root))
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(updated)
                    handle.flush()
                    os.fsync(handle.fileno())
                if scripts.is_symlink() or _hash_bytes(scripts.read_bytes()) != _hash_bytes(original):
                    raise ValueError("scripts.yaml changed during update")
                os.chmod(tmp, scripts.stat().st_mode & 0o777)
                os.replace(tmp, scripts)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            return {"appended_script": script_id, "updated_sha256": _hash_bytes(updated),
                    "backup_path": str(backup), "backup_sha256": _hash_bytes(original),
                    "note": "Reload scripts in Home Assistant to activate"}

        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError, UnicodeError, yaml.YAMLError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)




class FetchLLMUpdate(Tool):
    """Download a complete update from a tightly scoped HTTPS source to staging."""
    name = "dashboard_reader__fetch_llm_update"
    description = (
        "Fetch a complete llm.py update from raw.githubusercontent.com via HTTPS "
        "into the staging file only. Requires expected SHA256 and rejects redirects, "
        "private networks and oversized files. Does not modify live llm.py."
    )
    integration = DOMAIN
    annotations = ToolAnnotations(
        read_only=False, destructive=False, idempotent=False, open_world=True
    )
    parameters = vol.Schema({
        vol.Required("url"): str,
        vol.Required("expected_sha256"): vol.Match(r"[0-9a-f]{64}"),
    })

    async def async_call(self, hass: HomeAssistant, tool_input: ToolInput,
                         llm_context: LLMContext) -> ToolResult:
        args = tool_input.tool_args

        def run():
            from urllib.error import HTTPError, URLError
            parsed = urllib.parse.urlsplit(args["url"])
            if (parsed.scheme != "https" or parsed.hostname != "raw.githubusercontent.com"
                    or parsed.port not in (None, 443) or parsed.username or parsed.password
                    or parsed.fragment or parsed.query):
                raise ValueError("Only direct raw.githubusercontent.com HTTPS URLs are allowed")
            # A fixed hostname and DNS/IP validation prevent fetching LAN endpoints.
            addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
            if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
                raise ValueError("Source address is not globally routable")
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    raise ValueError("Redirects are not allowed")
            opener = urllib.request.build_opener(NoRedirect)
            request = urllib.request.Request(args["url"], headers={"User-Agent": "dashboard-reader-update/1"})
            with opener.open(request, timeout=15) as response:
                if response.status != 200:
                    raise ValueError("Download failed")
                data = response.read(500_001)
            if not data or len(data) > 500_000:
                raise ValueError("Downloaded file is empty or too large")
            digest = hashlib.sha256(data).hexdigest()
            if digest != args["expected_sha256"]:
                raise ValueError("Downloaded SHA256 does not match")
            compile(data.decode("utf-8"), "llm.py", "exec")
            live, staged, backup = update_paths(hass)
            if staged.is_symlink():
                raise ValueError("Staging file is a symlink")
            if staged.exists():
                raise ValueError("Staging already exists; refusing to overwrite")
            with staged.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            return {"staged_sha256": digest, "bytes": len(data),
                    "note": "Only staged; use apply_llm_update after explicit approval"}

        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError, UnicodeError, SyntaxError, urllib.error.URLError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)




# General-purpose, allowlisted file transfer. Never accepts arbitrary paths.
TRANSFER_CONFIRM = "INSTALL_APPROVED_HA_FILE"
TRANSFER_LIMIT = 2_000_000
TRANSFER_TARGETS = {
    "scripts.yaml": "scripts.yaml",
    "dashboard_reader/llm.py": "custom_components/dashboard_reader/llm.py",
    "dashboard_reader/__init__.py": "custom_components/dashboard_reader/__init__.py",
    "dashboard_reader/manifest.json": "custom_components/dashboard_reader/manifest.json",
}


def _transfer_target(hass, name):
    if name not in TRANSFER_TARGETS:
        raise ValueError("Target is not allowlisted")
    root = Path(hass.config.config_dir).resolve()
    target = root / TRANSFER_TARGETS[name]
    if any(p.is_symlink() for p in (target, *target.parents) if p != root):
        raise ValueError("Symlink in target path")
    if not target.parent.is_dir():
        raise ValueError("Target directory missing")
    if target.exists() and not target.is_file():
        raise ValueError("Target is not a regular file")
    return target


def _validate_transfer(data, name):
    if len(data) > TRANSFER_LIMIT:
        raise ValueError("File exceeds 2 MB")
    content = data.decode("utf-8")
    if name.endswith(".py"):
        compile(content, name, "exec")
        if name == "dashboard_reader/llm.py":
            _check_python_source(data)
    elif name.endswith((".yaml", ".yml", ".json")):
        parsed = json.loads(content) if name.endswith(".json") else yaml.safe_load(content)
        if not isinstance(parsed, dict):
            raise ValueError("Expected top-level mapping")
        if name == "scripts.yaml" and not all(
            isinstance(k, str) and isinstance(v, dict) and isinstance(v.get("sequence"), list)
            for k, v in parsed.items()
        ):
            raise ValueError("Invalid scripts.yaml structure")
    else:
        raise ValueError("Unsupported file type")


class HAFileStatus(Tool):
    name = "dashboard_reader__file_status"
    description = "Read raw SHA256 and size for an allowlisted HA file, without revealing contents."
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({vol.Required("target"): vol.In(tuple(TRANSFER_TARGETS))})

    async def async_call(self, hass, tool_input, llm_context):
        def run():
            path = _transfer_target(hass, tool_input.tool_args["target"])
            if not path.exists():
                return {"exists": False, "sha256": "0" * 64, "bytes": 0}
            data = path.read_bytes()
            return {"exists": True, "sha256": _hash_bytes(data), "bytes": len(data)}
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (OSError, ValueError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


class InstallHADraftFile(Tool):
    name = "dashboard_reader__install_file_from_draft"
    description = (
        "DANGEROUS: Install a complete draft to one allowlisted HA file. "
        "Requires explicit user approval for this specific file, raw expected target "
        "SHA256, exact draft SHA256 and confirmation INSTALL_APPROVED_HA_FILE. "
        "Creates a non-overwriting backup; never reloads Home Assistant. "
        "For scripts.yaml prefer append_script_from_draft to preserve existing scripts."
    )
    integration = DOMAIN
    annotations = ToolAnnotations(read_only=False, destructive=True, idempotent=False, open_world=False)
    parameters = vol.Schema({
        vol.Required("target"): vol.In(tuple(TRANSFER_TARGETS)),
        vol.Required("draft_filename"): str,
        vol.Required("expected_target_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("expected_draft_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("confirmation"): vol.In((TRANSFER_CONFIRM,)),
    })

    async def async_call(self, hass, tool_input, llm_context):
        args = tool_input.tool_args
        def run():
            target = _transfer_target(hass, args["target"])
            old = target.read_bytes() if target.exists() else b""
            old_hash = _hash_bytes(old) if target.exists() else "0" * 64
            if old_hash != args["expected_target_sha256"]:
                raise ValueError("Target SHA256 mismatch")
            draft = read_draft_text(hass, args["draft_filename"])
            data = draft.encode("utf-8")
            if _hash_bytes(data) != args["expected_draft_sha256"]:
                raise ValueError("Draft SHA256 mismatch")
            _validate_transfer(data, args["target"])
            if data == old:
                return {"unchanged": True, "sha256": old_hash}
            backup_dir = Path(hass.config.config_dir) / "dashboard_reader" / "backups"
            if backup_dir.is_symlink():
                raise ValueError("Backup folder is a symlink")
            backup_dir.mkdir(parents=True, exist_ok=True)
            backup = backup_dir / ("file_" + args["target"].replace("/", "_") + "_" +
                                    time.strftime("%Y%m%d_%H%M%S", time.gmtime()) + "_" + old_hash[:12] + ".bak")
            if backup.exists() or backup.is_symlink():
                raise ValueError("Backup collision")
            if target.exists():
                with backup.open("xb") as f:
                    f.write(old)
                    f.flush()
                    os.fsync(f.fileno())
            if (target.read_bytes() if target.exists() else b"") != old:
                raise ValueError("Target changed during update")
            _atomic_update_bytes(target, data)
            return {"installed": True, "target": args["target"],
                    "sha256": _hash_bytes(data), "backup": str(backup) if old else None,
                    "note": "Reload relevant HA integration or scripts to activate"}
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError, UnicodeError, SyntaxError, yaml.YAMLError, json.JSONDecodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


RESTART_CONFIRM = "RESTART_HOME_ASSISTANT_APPROVED"


class RestartHomeAssistant(Tool):
    name = "dashboard_reader__restart_home_assistant"
    description = (
        "DANGEROUS: Restart Home Assistant Core. Use only when the user explicitly "
        "approves a restart. Requires exact confirmation RESTART_HOME_ASSISTANT_APPROVED. "
        "May interrupt automations, connected devices and this tool session."
    )
    integration = DOMAIN
    annotations = ToolAnnotations(read_only=False, destructive=True, idempotent=False, open_world=False)
    parameters = vol.Schema({
        vol.Required("confirmation"): vol.In((RESTART_CONFIRM,)),
    })

    async def async_call(self, hass, tool_input, llm_context):
        if tool_input.tool_args["confirmation"] != RESTART_CONFIRM:
            return ToolResult(data={"error": "Explicit restart confirmation required"}, error=True)
        try:
            await hass.services.async_call(
                "homeassistant", "restart", {}, blocking=False
            )
            return ToolResult(data={
                "restart_requested": True,
                "note": "Restart requested; connection may drop before completion",
            })
        except Exception as exc:
            return ToolResult(data={"error": str(exc)}, error=True)



# System panels are not all Lovelace dashboards. Read only explicitly approved
# configuration stores; never expose arbitrary .storage entries.
SYSTEM_PANEL_STORES = {
    "energy": "energy",
    "lovelace_default": "lovelace",
    "lovelace_dashboards": "lovelace_dashboards",
}
SYSTEM_PANEL_INFO = {
    "energy": "Energy dashboard configuration (sources, tariffs and costs)",
    "lovelace_default": "Built-in Overview Lovelace configuration, if stored",
    "lovelace_dashboards": "Registered Lovelace dashboard metadata",
    "map": "Dynamic panel; no standalone stored dashboard configuration",
    "history": "Dynamic panel; uses recorder history rather than a dashboard file",
    "logbook": "Dynamic panel; uses recorded events rather than a dashboard file",
    "statistics": "Dynamic diagnostics; use recorder statistics APIs",
}

def _read_system_panel(hass, panel):
    if panel not in SYSTEM_PANEL_STORES:
        raise ValueError("This system panel has no supported stored configuration")
    root = Path(hass.config.config_dir) / ".storage"
    if root.is_symlink():
        raise ValueError("Storage directory cannot be a symlink")
    path = root / SYSTEM_PANEL_STORES[panel]
    if path.is_symlink() or not path.is_file():
        return {"panel": panel, "available": False, "reason": "No stored configuration"}
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Stored configuration exceeds size limit")
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError("Invalid system panel configuration")
    # Only return the payload, never storage metadata or unrelated files.
    return {"panel": panel, "available": True,
            "configuration": sanitize(value.get("data", {}))}

class ListSystemPanels(Tool):
    name = "dashboard_reader__list_system_panels"
    title = "List supported Home Assistant system panels"
    description = "List built-in panels and indicate which configurations can be inspected. Read-only."
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({})

    async def async_call(self, hass, tool_input, llm_context):
        def run():
            result = []
            for panel, description in SYSTEM_PANEL_INFO.items():
                stored = panel in SYSTEM_PANEL_STORES
                if stored:
                    root = Path(hass.config.config_dir) / ".storage"
                    path = root / SYSTEM_PANEL_STORES[panel]
                    available = (not root.is_symlink() and not path.is_symlink()
                                 and path.is_file())
                else:
                    available = False
                result.append({"panel": panel, "description": description,
                               "stored_config_available": available,
                               "dynamic_panel": not stored})
            return {"panels": result}
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)

class ReadSystemPanel(Tool):
    name = "dashboard_reader__read_system_panel"
    title = "Read built-in system panel configuration"
    description = (
        "Read-only, redacted inspection of allowlisted Home Assistant system panel "
        "configuration: energy, lovelace_default or lovelace_dashboards. "
        "Never changes stored files. For long results use offset and limit."
    )
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({
        vol.Required("panel"): vol.In(tuple(SYSTEM_PANEL_STORES)),
        vol.Optional("offset", default=0): vol.All(int, vol.Range(min=0)),
        vol.Optional("limit", default=8000): vol.All(int, vol.Range(min=1, max=CHUNK_LIMIT)),
    })

    async def async_call(self, hass, tool_input, llm_context):
        args = tool_input.tool_args
        def run():
            result = _read_system_panel(hass, args["panel"])
            encoded = json.dumps(result, ensure_ascii=False, indent=2)
            if len(encoded) > MAX_RESPONSE_CHARS:
                raise ValueError("Response exceeds size limit")
            start = args["offset"]
            end = min(start + args["limit"], len(encoded))
            return {"panel": args["panel"], "offset": start,
                    "total_characters": len(encoded), "chunk": encoded[start:end],
                    "sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
                    "has_more": end < len(encoded),
                    "next_offset": end if end < len(encoded) else None}
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


# Explicitly staged system-dashboard changes. No arbitrary .storage writes.
SYSTEM_CHANGE_CONFIRM = "APPLY_APPROVED_SYSTEM_CHANGE"
SYSTEM_CHANGE_PREFIX = "system_change_"
SYSTEM_CHANGE_FILENAME = re.compile(r"system_change_[A-Za-z0-9_-]{1,60}\.json\Z")

def _system_change_file(hass, filename):
    if not isinstance(filename, str) or not SYSTEM_CHANGE_FILENAME.fullmatch(filename):
        raise ValueError("Invalid system change filename")
    return draft_path(hass, filename)

def _system_config_hash(value):
    return hash_text(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")))

def _system_change_diff(before, after):
    return {"before": sanitize(before), "after": sanitize(after)}

class PrepareSystemChange(Tool):
    name = "dashboard_reader__prepare_system_change"
    title = "Stage system dashboard configuration change"
    description = (
        "Stage a complete replacement of Energy preferences in an isolated draft. "
        "Read-only for live HA; requires exact current configuration SHA256 and "
        "unique draft filename. Never edits history or live dashboards."
    )
    integration = DOMAIN
    annotations = EXPORT_ANNOTATIONS
    parameters = vol.Schema({
        vol.Required("panel"): vol.In(("energy",)),
        vol.Required("filename"): vol.Match(r"system_change_[A-Za-z0-9_-]{1,60}\.json"),
        vol.Required("expected_config_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("configuration"): dict,
    })

    async def async_call(self, hass, tool_input, llm_context):
        args = tool_input.tool_args
        try:
            from homeassistant.components.energy.data import async_get_manager
            manager = await async_get_manager(hass)
            current = copy.deepcopy(manager.data or {})
            current_hash = _system_config_hash(current)
            if current_hash != args["expected_config_sha256"]:
                raise ValueError("Energy configuration changed; reread before staging")
            proposed = copy.deepcopy(args["configuration"])
            allowed = {"energy_sources", "device_consumption", "device_consumption_water"}
            if not proposed or set(proposed) - allowed:
                raise ValueError("Only supported Energy preference fields are allowed")
            if not isinstance(proposed.get("energy_sources", []), list):
                raise ValueError("energy_sources must be a list")
            if not isinstance(proposed.get("device_consumption", []), list):
                raise ValueError("device_consumption must be a list")
            if not isinstance(proposed.get("device_consumption_water", []), list):
                raise ValueError("device_consumption_water must be a list")
            # Merge partial preference update into a complete proposal for preview.
            final = copy.deepcopy(current)
            final.update(proposed)
            payload = {"panel": "energy", "base_sha256": current_hash,
                       "proposed": proposed, "preview": _system_change_diff(current, final)}
            encoded = json.dumps(payload, ensure_ascii=False, indent=2)
            result = await hass.async_add_executor_job(
                lambda: atomic_write_draft(hass, args["filename"], encoded, create_only=True))
            return ToolResult(data={"draft": result, "preview": sanitize(payload["preview"]),
                                    "requires_approval": True})
        except (ValueError, OSError, TypeError, ImportError, json.JSONDecodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)

class ApplySystemChange(Tool):
    name = "dashboard_reader__apply_system_change"
    title = "Apply explicitly approved Energy configuration"
    description = (
        "DANGEROUS: Apply staged Energy preferences using the official Energy manager. "
        "Only after explicit approval for this exact draft. Checks current SHA256, "
        "creates a backup draft, and never edits historical statistics."
    )
    integration = DOMAIN
    annotations = ToolAnnotations(read_only=False, destructive=True, idempotent=False, open_world=False)
    parameters = vol.Schema({
        vol.Required("filename"): vol.Match(r"system_change_[A-Za-z0-9_-]{1,60}\.json"),
        vol.Required("expected_draft_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("confirmation"): vol.In((SYSTEM_CHANGE_CONFIRM,)),
    })

    async def async_call(self, hass, tool_input, llm_context):
        args = tool_input.tool_args
        try:
            raw = await hass.async_add_executor_job(read_draft_text, hass, args["filename"])
            if hash_text(raw) != args["expected_draft_sha256"]:
                raise ValueError("Draft SHA256 mismatch")
            payload = json.loads(raw)
            if payload.get("panel") != "energy" or not isinstance(payload.get("proposed"), dict):
                raise ValueError("Invalid Energy change draft")
            from homeassistant.components.energy.data import async_get_manager
            manager = await async_get_manager(hass)
            current = copy.deepcopy(manager.data or {})
            if _system_config_hash(current) != payload.get("base_sha256"):
                raise ValueError("Live Energy configuration changed; refusing to overwrite")
            backup_name = "system_change_backup_" + str(time.time_ns()) + ".json"
            # Backup uses the same isolated drafts directory.
            backup = await hass.async_add_executor_job(
                lambda: atomic_write_draft(hass, backup_name,
                    json.dumps({"panel": "energy", "configuration": current},
                               ensure_ascii=False, indent=2), create_only=True))
            await manager.async_update(payload["proposed"])
            return ToolResult(data={"applied": True, "panel": "energy",
                                    "backup": backup, "new_sha256": _system_config_hash(manager.data or {}),
                                    "note": "Energy configuration updated; history unchanged"})
        except (ValueError, OSError, TypeError, ImportError, json.JSONDecodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)

class RestoreSystemBackup(Tool):
    name = "dashboard_reader__restore_system_backup"
    title = "Restore approved Energy configuration backup"
    description = (
        "DANGEROUS: Restore Energy preferences from a backup created by apply_system_change. "
        "Requires explicit approval and exact current SHA256."
    )
    integration = DOMAIN
    annotations = ToolAnnotations(read_only=False, destructive=True, idempotent=False, open_world=False)
    parameters = vol.Schema({
        vol.Required("filename"): vol.Match(r"system_change_backup_[0-9]+\.json"),
        vol.Required("expected_current_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("confirmation"): vol.In((SYSTEM_CHANGE_CONFIRM,)),
    })

    async def async_call(self, hass, tool_input, llm_context):
        args = tool_input.tool_args
        try:
            raw = await hass.async_add_executor_job(read_draft_text, hass, args["filename"])
            payload = json.loads(raw)
            if payload.get("panel") != "energy" or not isinstance(payload.get("configuration"), dict):
                raise ValueError("Invalid backup")
            from homeassistant.components.energy.data import async_get_manager
            manager = await async_get_manager(hass)
            if _system_config_hash(manager.data or {}) != args["expected_current_sha256"]:
                raise ValueError("Live Energy configuration changed; refusing restore")
            await manager.async_update(payload["configuration"])
            return ToolResult(data={"restored": True, "panel": "energy",
                                    "new_sha256": _system_config_hash(manager.data or {})})
        except (ValueError, OSError, TypeError, ImportError, json.JSONDecodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)

class EnergyConfigStatus(Tool):
    name = "dashboard_reader__energy_config_status"
    title = "Read live Energy preferences and revision hash"
    description = "Read current Energy manager preferences and SHA256, without changing anything."
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({})

    async def async_call(self, hass, tool_input, llm_context):
        try:
            from homeassistant.components.energy.data import async_get_manager
            manager = await async_get_manager(hass)
            config = copy.deepcopy(manager.data or {})
            return ToolResult(data=safe_result({
                "panel": "energy", "configuration": config,
                "sha256": _system_config_hash(config)}))
        except (ValueError, OSError, ImportError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


class ReadEnergyStatistics(Tool):
    name = "dashboard_reader__read_energy_statistics"
    title = "Read Home Assistant long-term energy statistics"
    description = (
        "Read-only long-term statistics by statistic_id, including external IDs "
        "such as tauron_importer:... . Returns bounded hourly or daily changes "
        "and recorded totals, without changing recorder data."
    )
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({
        vol.Required("statistic_ids"): vol.All(
            [vol.All(str, vol.Length(min=1, max=255))],
            vol.Length(min=1, max=8)),
        vol.Required("start_time"): vol.Datetime(),
        vol.Required("end_time"): vol.Datetime(),
        vol.Optional("period", default="day"): vol.In(("hour", "day", "month")),
    })

    async def async_call(self, hass, tool_input, llm_context):
        from datetime import datetime, timezone, timedelta
        from homeassistant.components.recorder import statistics, get_instance
        args = tool_input.tool_args
        try:
            start = args["start_time"]
            end = args["end_time"]
            if isinstance(start, str):
                start = datetime.fromisoformat(start.replace("Z", "+00:00"))
            if isinstance(end, str):
                end = datetime.fromisoformat(end.replace("Z", "+00:00"))
            if start.tzinfo is None or end.tzinfo is None:
                raise ValueError("Use timezone-aware ISO 8601 datetimes")
            start = start.astimezone(timezone.utc)
            end = end.astimezone(timezone.utc)
            if end <= start or end > datetime.now(timezone.utc) + timedelta(minutes=5):
                raise ValueError("Invalid time range")
            period = args.get("period", "day")
            max_days = {"hour": 7, "day": 90, "month": 730}[period]
            if end - start > timedelta(days=max_days):
                raise ValueError("Requested interval too long")
            ids = list(dict.fromkeys(args["statistic_ids"]))
            # Official recorder statistics API supports non-entity statistic IDs.
            values = await get_instance(hass).async_add_executor_job(
                statistics.statistics_during_period, hass,
                start, end, ids, period, None, {"sum", "state", "change"})
            output = {}
            for statistic_id in ids:
                rows = values.get(statistic_id, [])
                output[statistic_id] = [
                    {"start": row["start"].isoformat() if hasattr(row.get("start"), "isoformat") else row.get("start"),
                     "end": row["end"].isoformat() if hasattr(row.get("end"), "isoformat") else row.get("end"),
                     "sum": row.get("sum"), "state": row.get("state"), "change": row.get("change")}
                    for row in rows[:2200]
                ]
            return ToolResult(data=safe_result({"period": period, "statistics": output}))
        except (ValueError, TypeError, KeyError, ImportError, AttributeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


# Scoped /config text file manager. No symlinks, secrets, databases or .storage.
FILE_MGR_EXT = {".py", ".json", ".yaml", ".yml", ".js", ".ts", ".css", ".html",
                ".txt", ".md", ".xml", ".csv", ".toml", ".ini", ".cfg"}
FILE_MGR_BLOCKED = {".storage", ".git", ".ssh", "secrets.yaml", ".env",
                    "known_devices.yaml", "auth", "auth_provider.homeassistant",
                    "home-assistant_v2.db", "home-assistant_v2.db-shm",
                    "home-assistant_v2.db-wal"}
FILE_MGR_LIMIT = 400_000
FILE_MGR_CONFIRM = "APPLY_APPROVED_CONFIG_FILE_CHANGE"
FILE_MGR_RESTORE = "RESTORE_APPROVED_CONFIG_FILE_BACKUP"

def _managed_path(hass, relative, *, write=False):
    if not isinstance(relative, str) or not relative or "\x00" in relative or "\\" in relative:
        raise ValueError("Invalid relative /config path")
    p = Path(relative)
    if p.is_absolute() or any(x in ("", ".", "..") for x in p.parts):
        raise ValueError("Path must be relative to /config")
    if any(part.startswith(".") or part.lower() in FILE_MGR_BLOCKED or
           "secret" in part.lower() or "token" in part.lower() or
           "password" in part.lower() or "credential" in part.lower()
           for part in p.parts):
        raise ValueError("Protected path")
    if write and p.suffix.lower() not in FILE_MGR_EXT:
        raise ValueError("Unsupported editable file type")
    root = Path(hass.config.config_dir)
    if root.is_symlink():
        raise ValueError("Configuration root cannot be a symlink")
    dest = root
    for part in p.parts:
        dest = dest / part
        if dest.is_symlink():
            raise ValueError("Symlink paths are forbidden")
    if not dest.resolve(strict=False).is_relative_to(root.resolve()):
        raise ValueError("Path outside /config")
    return dest

def _managed_redact(content):
    """Conservatively redact entire lines that appear to contain credentials."""
    out = []
    for line in content.splitlines(keepends=True):
        if SECRET_KEYS.search(line) or re.search(r"(?i)authorization|bearer\\s|private.key|client.secret", line):
            out.append("[REDACTED SENSITIVE LINE]\\n" if line.endswith("\\n") else "[REDACTED SENSITIVE LINE]")
        else:
            out.append(redact_inline_secrets(line))
    return "".join(out)


def _managed_text(hass, relative):
    path = _managed_path(hass, relative)
    if path.suffix.lower() not in FILE_MGR_EXT or not path.is_file():
        raise ValueError("Not an allowed text file")
    if path.stat().st_size > FILE_MGR_LIMIT:
        raise ValueError("File too large")
    raw = path.read_bytes()
    if b"\x00" in raw:
        raise ValueError("Binary file")
    return raw.decode("utf-8"), hashlib.sha256(raw).hexdigest()

def _managed_validate(content, relative):
    ext = Path(relative).suffix.lower()
    if ext == ".py":
        compile(content, relative, "exec")
    elif ext == ".json":
        json.loads(content)
    elif ext in (".yaml", ".yml"):
        yaml.safe_load(content)

def _managed_backup_dir(hass):
    root = Path(hass.config.config_dir) / "dashboard_reader" / "file_backups"
    if root.is_symlink():
        raise ValueError("Backup directory is a symlink")
    root.mkdir(parents=True, exist_ok=True)
    return root

class ListConfigFiles(Tool):
    name = "dashboard_reader__list_files"
    title = "List text files inside /config"
    description = "Read-only directory listing inside /config, excluding sensitive paths."
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({
        vol.Optional("directory", default="custom_components"): str,
        vol.Optional("limit", default=100): vol.All(int, vol.Range(min=1, max=200)),
    })
    async def async_call(self, hass, tool_input, llm_context):
        args = tool_input.tool_args
        def run():
            directory = args["directory"]
            path = _managed_path(hass, directory)
            if not path.is_dir():
                raise ValueError("Directory not found")
            entries = []
            for child in sorted(path.iterdir(), key=lambda p: p.name.lower()):
                try:
                    rel = str(child.relative_to(hass.config.config_dir))
                    _managed_path(hass, rel)
                    if child.is_dir() or (child.is_file() and child.suffix.lower() in FILE_MGR_EXT):
                        entries.append({"path": rel, "type": "directory" if child.is_dir() else "file",
                                        "bytes": child.stat().st_size if child.is_file() else None})
                except (ValueError, OSError):
                    continue
                if len(entries) >= args["limit"]:
                    break
            return {"directory": directory, "entries": entries, "truncated": len(entries) >= args["limit"]}
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)

class ReadConfigFile(Tool):
    name = "dashboard_reader__read_file"
    title = "Read redacted /config text file"
    description = "Read-only chunked file content with raw SHA256; sensitive paths are blocked."
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({
        vol.Required("path"): str,
        vol.Optional("offset", default=0): vol.All(int, vol.Range(min=0)),
        vol.Optional("limit", default=8000): vol.All(int, vol.Range(min=1, max=12000)),
    })
    async def async_call(self, hass, tool_input, llm_context):
        args = tool_input.tool_args
        def run():
            content, sha = _managed_text(hass, args["path"])
            redacted = _managed_redact(content)
            start = args["offset"]
            end = min(start + args["limit"], len(redacted))
            return {"path": args["path"], "sha256": sha, "characters": len(redacted),
                    "chunk": redacted[start:end], "next_offset": end if end < len(redacted) else None}
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError, UnicodeError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)

class SearchConfigFiles(Tool):
    name = "dashboard_reader__search_files"
    title = "Search source files inside /config"
    description = "Search bounded UTF-8 text files; returns redacted matching lines, not secrets."
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({
        vol.Required("directory"): str,
        vol.Required("query"): vol.All(str, vol.Length(min=2, max=120)),
        vol.Optional("limit", default=30): vol.All(int, vol.Range(min=1, max=100)),
    })
    async def async_call(self, hass, tool_input, llm_context):
        args = tool_input.tool_args
        def run():
            root = _managed_path(hass, args["directory"])
            if not root.is_dir():
                raise ValueError("Directory not found")
            found = []
            scanned = 0
            for base, dirs, files in os.walk(root, followlinks=False):
                dirs[:] = [d for d in dirs if not (Path(base) / d).is_symlink()
                           and not d.startswith(".") and d.lower() not in FILE_MGR_BLOCKED]
                for filename in files:
                    rel = str((Path(base) / filename).relative_to(hass.config.config_dir))
                    try:
                        content, _ = _managed_text(hass, rel)
                    except (ValueError, OSError, UnicodeError):
                        continue
                    scanned += 1
                    for number, line in enumerate(content.splitlines(), 1):
                        if args["query"].lower() in line.lower():
                            found.append({"path": rel, "line": number,
                                          "text": _managed_redact(line[:350])})
                            if len(found) >= args["limit"]:
                                return {"matches": found, "scanned_files": scanned, "truncated": True}
                    if scanned >= 500:
                        return {"matches": found, "scanned_files": scanned, "truncated": True}
            return {"matches": found, "scanned_files": scanned, "truncated": False}
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)

class PrepareConfigFileChange(Tool):
    name = "dashboard_reader__prepare_file_change"
    title = "Prepare a reviewed /config file change"
    description = "Stages a complete replacement from an existing draft. Does not modify target."
    integration = DOMAIN
    annotations = READ_ONLY
    parameters = vol.Schema({
        vol.Required("path"): str,
        vol.Required("draft_filename"): str,
        vol.Required("expected_target_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("expected_draft_sha256"): vol.Match(r"[0-9a-f]{64}"),
    })
    async def async_call(self, hass, tool_input, llm_context):
        args = tool_input.tool_args
        def run():
            path = _managed_path(hass, args["path"], write=True)
            if path.exists() and not path.is_file():
                raise ValueError("Target is not a regular file")
            old = path.read_bytes() if path.is_file() else b""
            old_sha = hashlib.sha256(old).hexdigest() if path.exists() else "0" * 64
            if old_sha != args["expected_target_sha256"]:
                raise ValueError("Target SHA256 mismatch")
            draft = read_draft_text(hass, args["draft_filename"])
            if hash_text(draft) != args["expected_draft_sha256"]:
                raise ValueError("Draft SHA256 mismatch")
            if len(draft.encode("utf-8")) > FILE_MGR_LIMIT:
                raise ValueError("File too large")
            _managed_validate(draft, args["path"])
            return {"path": args["path"], "old_sha256": old_sha,
                    "new_sha256": hash_text(draft), "new_bytes": len(draft.encode("utf-8")),
                    "draft_filename": args["draft_filename"], "ready_for_approval": True}
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError, SyntaxError, UnicodeError, yaml.YAMLError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)

class ApplyConfigFileChange(Tool):
    name = "dashboard_reader__apply_file_change"
    title = "Apply an explicitly approved /config file change"
    description = "DANGEROUS: SHA256-gated atomic write with immutable backup; requires explicit approval."
    integration = DOMAIN
    annotations = ToolAnnotations(read_only=False, destructive=True, idempotent=False, open_world=False)
    parameters = vol.Schema({
        vol.Required("path"): str,
        vol.Required("draft_filename"): str,
        vol.Required("expected_target_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("expected_draft_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("confirmation"): vol.In((FILE_MGR_CONFIRM,)),
    })
    async def async_call(self, hass, tool_input, llm_context):
        args = tool_input.tool_args
        def run():
            path = _managed_path(hass, args["path"], write=True)
            if not path.parent.is_dir() or path.parent.is_symlink():
                raise ValueError("Parent directory must already exist and not be a symlink")
            old = path.read_bytes() if path.is_file() else b""
            old_sha = hashlib.sha256(old).hexdigest() if path.exists() else "0" * 64
            if old_sha != args["expected_target_sha256"]:
                raise ValueError("Target SHA256 mismatch")
            draft = read_draft_text(hass, args["draft_filename"])
            data = draft.encode("utf-8")
            if hashlib.sha256(data).hexdigest() != args["expected_draft_sha256"]:
                raise ValueError("Draft SHA256 mismatch")
            if len(data) > FILE_MGR_LIMIT:
                raise ValueError("File too large")
            _managed_validate(draft, args["path"])
            backup_dir = _managed_backup_dir(hass)
            backup_name = "backup_" + str(time.time_ns()) + ".json"
            backup_path = backup_dir / backup_name
            record = {"path": args["path"], "existed": path.exists(),
                      "old_sha256": old_sha, "new_sha256": hashlib.sha256(data).hexdigest(),
                      "old_content": old.decode("utf-8") if old else ""}
            with backup_path.open("x", encoding="utf-8") as handle:
                json.dump(record, handle, ensure_ascii=False)
            fd, temp = tempfile.mkstemp(prefix=".ha_edit_", dir=str(path.parent))
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                if path.is_symlink():
                    raise ValueError("Symlink appeared during write")
                os.replace(temp, path)
            finally:
                if os.path.exists(temp):
                    os.unlink(temp)
            return {"installed": True, "path": args["path"],
                    "sha256": record["new_sha256"], "backup": backup_name,
                    "restart_required": path.suffix.lower() == ".py"}
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError, SyntaxError, UnicodeError, yaml.YAMLError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)

class RestoreConfigFileBackup(Tool):
    name = "dashboard_reader__restore_file_backup"
    title = "Restore explicitly approved /config backup"
    description = "DANGEROUS: Restore backed-up file only if current SHA256 matches applied version."
    integration = DOMAIN
    annotations = ToolAnnotations(read_only=False, destructive=True, idempotent=False, open_world=False)
    parameters = vol.Schema({
        vol.Required("backup"): vol.Match(r"backup_[0-9]+\.json"),
        vol.Required("expected_current_sha256"): vol.Match(r"[0-9a-f]{64}"),
        vol.Required("confirmation"): vol.In((FILE_MGR_RESTORE,)),
    })
    async def async_call(self, hass, tool_input, llm_context):
        args = tool_input.tool_args
        def run():
            backup = _managed_backup_dir(hass) / args["backup"]
            if backup.is_symlink() or not backup.is_file():
                raise ValueError("Backup not found")
            record = json.loads(backup.read_text(encoding="utf-8"))
            path = _managed_path(hass, record["path"], write=True)
            current = path.read_bytes() if path.is_file() else b""
            sha = hashlib.sha256(current).hexdigest() if path.exists() else "0" * 64
            if sha != args["expected_current_sha256"] or sha != record["new_sha256"]:
                raise ValueError("File changed after update; refusing restore")
            old = record["old_content"].encode("utf-8")
            if hashlib.sha256(old).hexdigest() != record["old_sha256"] and record["existed"]:
                raise ValueError("Corrupted backup")
            if not record["existed"]:
                path.unlink()
            else:
                fd, temp = tempfile.mkstemp(prefix=".ha_restore_", dir=str(path.parent))
                try:
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(old)
                    os.replace(temp, path)
                finally:
                    if os.path.exists(temp):
                        os.unlink(temp)
            return {"restored": True, "path": record["path"], "sha256": record["old_sha256"]}
        try:
            return ToolResult(data=await hass.async_add_executor_job(run))
        except (ValueError, OSError, UnicodeError, KeyError) as exc:
            return ToolResult(data={"error": str(exc)}, error=True)


@callback
def async_get_tools(hass: HomeAssistant, llm_context: LLMContext,
                    api_id: str) -> LLMTools:
    """Expose dashboard inspection and isolated draft tools."""
    return LLMTools(tools=[
        ListDashboards(), ReadDashboard(), GetCard(), GetFragment(),
        ListConfigFiles(), ReadConfigFile(), SearchConfigFiles(),
        PrepareConfigFileChange(), ApplyConfigFileChange(), RestoreConfigFileBackup(),
        ListSystemPanels(), ReadSystemPanel(), EnergyConfigStatus(), ReadEnergyStatistics(),
        PrepareSystemChange(), ApplySystemChange(), RestoreSystemBackup(),
        ExportCard(), ListExports(), ReadExport(),
        ListDrafts(), ReadDraft(), CreateCardDraft(), PatchCardDraft(),
        CreateTextDraft(), AppendTextDraft(), ReadHAConfig(),
        LLMUpdateStatus(), StageLLMUpdate(), FetchLLMUpdate(), ApplyLLMUpdate(), RestoreLLMBackup(),
        AppendScriptFromDraft(), HAFileStatus(), InstallHADraftFile(), RestartHomeAssistant(),
    ])
