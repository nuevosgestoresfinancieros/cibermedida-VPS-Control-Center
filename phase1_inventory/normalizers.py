"""Normalize bounded command outputs into schema-shaped fragments."""

from __future__ import annotations

from typing import Any

from .executor import CommandResult


def metadata(command_id: str, status: str = "collected", sensitivity: str = "internal", error: dict[str, str] | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {
        "collection_status": status,
        "sensitivity_level": sensitivity,
        "source_refs": [{"id": command_id, "command_id": command_id, "description": None}],
    }
    if error:
        value["errors"] = [error]
    return value


def normalize_disk_usage(result: CommandResult) -> list[dict[str, Any]]:
    if result.error_code or result.returncode not in (0, None):
        return []
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    volumes: list[dict[str, Any]] = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 7:
            continue
        source, filesystem, size, used, available, _percent, mount = parts[:7]
        volumes.append({
            "metadata": metadata(result.command_id),
            "mount": mount,
            "filesystem": filesystem,
            "size_bytes": _to_int(size),
            "used_bytes": _to_int(used),
            "available_bytes": _to_int(available),
        })
    return volumes


def normalize_memory(result: CommandResult) -> dict[str, dict[str, Any]]:
    memory = _empty_memory("system.memory")
    swap = _empty_memory("system.memory")
    if result.error_code or result.returncode not in (0, None):
        return {"memory": memory, "swap": swap}
    for line in result.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        label = parts[0].rstrip(":")
        if label == "Mem" and len(parts) >= 7:
            item = {
                "metadata": metadata(result.command_id),
                "total_bytes": _to_int(parts[1]),
                "used_bytes": _to_int(parts[2]),
                "available_bytes": _to_int(parts[6]),
            }
        elif label == "Swap" and len(parts) >= 4:
            item = {
                "metadata": metadata(result.command_id),
                "total_bytes": _to_int(parts[1]),
                "used_bytes": _to_int(parts[2]),
                "available_bytes": _to_int(parts[3]),
            }
        else:
            continue
        if label == "Mem":
            memory = item
        else:
            swap = item
    return {"memory": memory, "swap": swap}


def normalize_uptime(result: CommandResult) -> str | None:
    if result.error_code or result.returncode not in (0, None):
        return None
    return " ".join(result.stdout.split()) or None


def normalize_git_status(result: CommandResult) -> dict[str, Any]:
    repo = _empty_repository("git.status")
    if result.error_code or result.returncode not in (0, None):
        return repo
    lines = result.stdout.splitlines()
    branch = None
    dirty = False
    if lines and lines[0].startswith("## "):
        branch = lines[0][3:].split("...")[0]
    if len(lines) > 1:
        dirty = True
    repo.update({"branch": branch, "dirty": dirty})
    return repo


def _empty_memory(command_id: str) -> dict[str, Any]:
    return {"metadata": metadata(command_id, "unknown"), "total_bytes": None, "used_bytes": None, "available_bytes": None}


def _empty_repository(command_id: str) -> dict[str, Any]:
    return {
        "metadata": metadata(command_id),
        "path": None,
        "remote": None,
        "branch": None,
        "head_commit": None,
        "dirty": None,
    }


def _to_int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None
