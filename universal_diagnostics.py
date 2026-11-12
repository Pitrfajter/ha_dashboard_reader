"""Read-only, bounded diagnostics for Home Assistant integrations.

No arbitrary URL fetching or credential extraction. Adapter-specific network reads
must be registered explicitly and use an integration-owned authenticated client.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping
import re

MAX_ENTITIES = 80
MAX_ATTRIBUTES = 12
MAX_VALUE = 180
SUPPORTED = ("http", "mqtt", "zigbee", "ha_state")
_SAFE_ID = re.compile(r"^[a-z0-9_]+(?:\.[a-z0-9_]+)?$")


@dataclass(frozen=True)
class Adapter:
    name: str
    protocol: str
    discover: Callable[[Any], Mapping[str, Any]]
    read: Callable[[Any, str], Mapping[str, Any]]
    resources: frozenset[str]


ADAPTERS: dict[str, Adapter] = {}


def register_adapter(adapter: Adapter) -> None:
    if not _SAFE_ID.fullmatch(adapter.name):
        raise ValueError("Invalid adapter identifier")
    if adapter.protocol not in SUPPORTED:
        raise ValueError("Unsupported protocol")
    if not adapter.resources:
        raise ValueError("Adapter must explicitly allowlist resources")
    ADAPTERS[adapter.name] = adapter


def discover(hass: Any) -> dict[str, Any]:
    """Describe supported adapters; no network calls or secrets."""
    return {
        "adapters": [
            {"name": a.name, "protocol": a.protocol,
             "resources": sorted(a.resources)}
            for a in sorted(ADAPTERS.values(), key=lambda x: x.name)
        ],
        "state_fallback": True,
        "note": "Unregistered local/cloud endpoints are unavailable, not probed.",
    }


def inspect(hass: Any, adapter_name: str, resource: str) -> dict[str, Any]:
    """Call only an explicitly registered, allowlisted adapter."""
    adapter = ADAPTERS.get(adapter_name)
    if adapter is None:
        return {"supported": False, "reason": "adapter_not_registered"}
    if resource not in adapter.resources:
        return {"supported": False, "reason": "resource_not_allowlisted"}
    result = adapter.read(hass, resource)
    # Adapter contract: return scalar operational readings, never raw payloads.
    allowed = {"status", "value", "unit", "timestamp", "source", "supported"}
    return {k: _scalar(v) for k, v in result.items() if k in allowed}


def _scalar(value: Any) -> str | int | float | bool | None:
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:MAX_VALUE]


def snapshot(hass: Any, entity_ids: list[str]) -> dict[str, Any]:
    """Bounded HA state snapshot for REST/MQTT/Zigbee backed entities."""
    if len(entity_ids) > MAX_ENTITIES:
        raise ValueError("Too many entities")
    result = {}
    for entity_id in entity_ids:
        if not _SAFE_ID.fullmatch(entity_id) or "." not in entity_id:
            raise ValueError("Invalid entity id")
        state = hass.states.get(entity_id)
        if state is None:
            result[entity_id] = {"available": False}
            continue
        result[entity_id] = {
            "available": state.state not in ("unavailable", "unknown"),
            "state": _scalar(state.state),
            "updated": state.last_updated.isoformat(),
            # Attributes may contain credentials, URLs, or arbitrary data:
            # do not export them in generic diagnostics.
        }
    return {"captured_at": datetime.now(timezone.utc).isoformat(),
            "entities": result}


def compare(hass: Any, adapter_name: str, resource: str,
            entity_id: str) -> dict[str, Any]:
    reading = inspect(hass, adapter_name, resource)
    state = snapshot(hass, [entity_id])["entities"][entity_id]
    if reading.get("supported") is False:
        return {"comparable": False, "reason": reading["reason"], "entity": state}
    if "value" not in reading or not state.get("available"):
        return {"comparable": False, "reason": "missing_value", "entity": state}
    return {"comparable": True, "api_value": reading["value"],
            "entity_value": state["state"],
            "equal_as_text": str(reading["value"]) == str(state["state"])}


def monitor_diff(before: Mapping[str, Any],
                 after: Mapping[str, Any]) -> dict[str, Any]:
    """Compare two explicitly captured snapshots; no background polling."""
    a = before.get("entities", {})
    b = after.get("entities", {})
    keys = sorted(set(a) | set(b))
    return {"changes": [
        {"entity_id": key, "before": a.get(key), "after": b.get(key)}
        for key in keys if a.get(key) != b.get(key)
    ], "before_at": before.get("captured_at"),
       "after_at": after.get("captured_at")}


def protocol_candidates(hass: Any, protocol: str) -> dict[str, Any]:
    """List loaded entity platforms only, without accessing broker credentials."""
    if protocol not in ("mqtt", "zigbee", "http"):
        raise ValueError("Unsupported protocol")
    patterns = {
        "mqtt": ("mqtt",),
        "zigbee": ("zha", "zigbee2mqtt"),
        "http": ("rest", "bosch_homecom"),
    }
    candidates = []
    for state in hass.states.async_all():
        if any(p in state.entity_id for p in patterns[protocol]):
            candidates.append(state.entity_id)
            if len(candidates) >= MAX_ENTITIES:
                break
    return {"protocol": protocol, "candidates": candidates,
            "note": "Heuristic IDs only; absence does not prove protocol unavailable."}
