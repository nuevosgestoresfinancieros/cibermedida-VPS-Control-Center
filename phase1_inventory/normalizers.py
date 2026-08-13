"""Normalize bounded command outputs into schema-shaped fragments."""

from __future__ import annotations

import json
import re
from typing import Any

from .executor import CommandResult

HEX_SHORT_RE = re.compile(r"^[0-9a-fA-F]{1,12}$")


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


def normalize_os_release(result: CommandResult) -> dict[str, Any]:
    os_release = {
        "metadata": metadata("system.os_release", "unknown"),
        "name": None,
        "version": None,
        "codename": None,
        "kernel": None,
        "architecture": None,
    }
    if result.error_code or result.returncode not in (0, None):
        return os_release
    parsed = _parse_key_value_lines(result.stdout)
    os_release.update(
        {
            "metadata": metadata(result.command_id),
            "name": parsed.get("NAME"),
            "version": parsed.get("VERSION_ID"),
            "codename": parsed.get("VERSION_CODENAME"),
        }
    )
    return os_release


def normalize_kernel(result: CommandResult) -> str | None:
    if result.error_code or result.returncode not in (0, None):
        return None
    value = result.stdout.strip()
    return value or None


def normalize_architecture(result: CommandResult) -> str | None:
    if result.error_code or result.returncode not in (0, None):
        return None
    value = result.stdout.strip()
    return value or None


def normalize_cpu_summary(result: CommandResult) -> dict[str, Any]:
    cpu = _empty_cpu("system.cpu_summary")
    if result.error_code or result.returncode not in (0, None):
        return cpu
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return _empty_cpu("system.cpu_summary", error=_parse_error("system.cpu_summary output could not be parsed"))
    lscpu_items = payload.get("lscpu") if isinstance(payload, dict) else None
    if not isinstance(lscpu_items, list):
        return _empty_cpu("system.cpu_summary", error=_parse_error("system.cpu_summary output did not contain an lscpu array"))
    fields = {
        str(item.get("field", "")).rstrip(":"): item.get("data")
        for item in lscpu_items
        if isinstance(item, dict)
    }
    logical_cpus = _to_int(str(fields.get("CPU(s)", "")))
    sockets = _to_int(str(fields.get("Socket(s)", "")))
    cores_per_socket = _to_int(str(fields.get("Core(s) per socket", "")))
    threads_per_core = _to_int(str(fields.get("Thread(s) per core", "")))
    cpu.update(
        {
            "metadata": metadata(result.command_id),
            "model": fields.get("Model name"),
            "architecture": fields.get("Architecture"),
            "cores": (sockets * cores_per_socket) if sockets is not None and cores_per_socket is not None else None,
            "threads": logical_cpus,
            "logical_cpus": logical_cpus,
            "sockets": sockets,
            "cores_per_socket": cores_per_socket,
            "threads_per_core": threads_per_core,
        }
    )
    return cpu


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
    repo.update({"metadata": metadata(result.command_id), "branch": branch, "dirty": dirty})
    return repo


def normalize_git_head_commit(result: CommandResult) -> str | None:
    if result.error_code or result.returncode not in (0, None):
        return None
    value = result.stdout.strip()
    if not HEX_SHORT_RE.fullmatch(value):
        return None
    return value.lower()


def normalize_repository(status_result: CommandResult | None, head_result: CommandResult | None) -> dict[str, Any]:
    repo = normalize_git_status(status_result) if status_result else _empty_repository("git.status")
    if head_result:
        repo["head_commit"] = normalize_git_head_commit(head_result)
    return repo


def _empty_memory(command_id: str) -> dict[str, Any]:
    return {"metadata": metadata(command_id, "unknown"), "total_bytes": None, "used_bytes": None, "available_bytes": None}


def _empty_cpu(command_id: str, error: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "metadata": metadata(command_id, "unknown", error=error),
        "model": None,
        "architecture": None,
        "cores": None,
        "threads": None,
        "logical_cpus": None,
        "sockets": None,
        "cores_per_socket": None,
        "threads_per_core": None,
    }


def _empty_repository(command_id: str) -> dict[str, Any]:
    return {
        "metadata": metadata(command_id, "unknown"),
        "path": None,
        "remote": None,
        "branch": None,
        "head_commit": None,
        "dirty": None,
    }


def _parse_key_value_lines(text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key] = value
    return parsed


def _parse_error(message: str) -> dict[str, str]:
    return {"code": "parse_error", "category": "parse_error", "message": message}


def _to_int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None
