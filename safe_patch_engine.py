"""Deterministic, SHA-gated patch planning for dashboard_reader upgrades.

This module has no network, filesystem writes, HA restart or shell execution.
The caller must use the existing approved staging/backup installer.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Sequence
import difflib

ALLOWED_ROOTS = ("custom_components/",)
MAX_SOURCE_BYTES = 2_000_000
MAX_OPERATIONS = 24
MAX_DIFF_LINES = 400


@dataclass(frozen=True)
class Replacement:
    old: str
    new: str
    occurrences: int = 1


def validate_path(path: str) -> str:
    if not isinstance(path, str) or "\\" in path or "\x00" in path:
        raise ValueError("Invalid path")
    parts = PurePosixPath(path).parts
    if not parts or any(p in ("..", ".") for p in path.split("/")):
        raise ValueError("Traversal forbidden")
    if not path.startswith(ALLOWED_ROOTS) or len(parts) < 3:
        raise ValueError("Outside allowed integration root")
    if parts[-1].startswith(".") or parts[-1] in ("secrets.yaml",):
        raise ValueError("Sensitive path")
    if PurePosixPath(path).suffix not in (".py", ".json", ".yaml", ".yml"):
        raise ValueError("Unsupported extension")
    return path


def digest(source: str) -> str:
    return sha256(source.encode("utf-8")).hexdigest()


def prepare_patch(path: str, source: str, expected_sha256: str,
                  replacements: Sequence[Replacement]) -> dict:
    validate_path(path)
    if not isinstance(source, str) or len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("Source too large")
    if digest(source) != expected_sha256:
        raise ValueError("Source SHA mismatch")
    if not replacements or len(replacements) > MAX_OPERATIONS:
        raise ValueError("Invalid number of replacements")
    updated = source
    for item in replacements:
        if not item.old or item.occurrences < 1:
            raise ValueError("Invalid replacement")
        if updated.count(item.old) != item.occurrences:
            raise ValueError("Replacement context mismatch")
        updated = updated.replace(item.old, item.new)
    if len(updated.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("Patched source too large")
    if path.endswith(".py"):
        compile(updated, path, "exec")
    diff = list(difflib.unified_diff(
        source.splitlines(), updated.splitlines(),
        fromfile="before/" + path, tofile="after/" + path, lineterm=""
    ))
    return {
        "path": path, "before_sha256": digest(source),
        "after_sha256": digest(updated),
        "changed": updated != source,
        "diff_preview": diff[:MAX_DIFF_LINES],
        "diff_truncated": len(diff) > MAX_DIFF_LINES,
        "content": updated,
        "installation": "NOT_INSTALLED",
        "approval_required": True,
    }
