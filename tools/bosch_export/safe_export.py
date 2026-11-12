"""Read-only, fail-closed inventory of Home Assistant custom integration source.

This module never exports source text, makes network calls, or writes files.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

ALLOWED_SUFFIXES = {".py", ".json", ".yaml", ".yml"}
SKIP_DIRS = {"__pycache__", ".git", ".pytest_cache", ".mypy_cache", "venv", ".venv"}
SKIP_FILES = {"secrets.yaml", "configuration.yaml", ".env", "auth", "token"}
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 12_000_000
SUSPICIOUS = (
    re.compile(rb"(?i)(?:access_token|refresh_token|client_secret|api_key|password|private_key|authorization|passwd)\s*[=:]\s*[\"']?[^\s\"']{5,}"),
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"(?i)[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@"),
)


def inspect_integration(config_dir: str, integration: str = "bosch_homecom") -> dict:
    """Return metadata only, never file contents or matched secret values."""
    if not re.fullmatch(r"[a-z][a-z0-9_]*", integration):
        raise ValueError("Invalid integration name")
    target = Path(config_dir) / "custom_components" / integration
    if target.is_symlink() or not target.is_dir():
        raise ValueError("Integration folder missing or symlinked")
    result = {"integration": integration, "files": [], "blocked_count": 0,
              "skipped_count": 0, "ready": False}
    total = 0
    for path in sorted(target.rglob("*")):
        rel = path.relative_to(target)
        if path.is_symlink():
            result["blocked_count"] += 1
            continue
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if not path.is_file():
            continue
        if path.name.lower() in SKIP_FILES or path.suffix.lower() not in ALLOWED_SUFFIXES:
            result["skipped_count"] += 1
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES or total + size > MAX_TOTAL_BYTES:
            result["blocked_count"] += 1
            continue
        raw = path.read_bytes()
        total += len(raw)
        blocked = any(pattern.search(raw) for pattern in SUSPICIOUS)
        result["files"].append({"path": rel.as_posix(), "bytes": len(raw),
                                "sha256": hashlib.sha256(raw).hexdigest(),
                                "blocked": blocked})
        result["blocked_count"] += int(blocked)
    result["ready"] = bool(result["files"]) and result["blocked_count"] == 0
    return result
