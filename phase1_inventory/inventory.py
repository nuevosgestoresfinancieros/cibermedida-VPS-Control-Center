"""Build schema-shaped Phase 1 inventory documents in memory."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from .normalizers import (
    metadata,
    normalize_architecture,
    normalize_cpu_summary,
    normalize_disk_usage,
    normalize_kernel,
    normalize_memory,
    normalize_os_release,
    normalize_repository,
    normalize_uptime,
)
from .redaction import redact

COLLECTOR_VERSION = "0.1.0"
POLICY_VERSION = "phase-1-read-safe-0.1"


def build_inventory(results: Mapping[str, Any], host_alias: str | None = None) -> dict[str, Any]:
    memory_parts = normalize_memory(results["system.memory"]) if "system.memory" in results else None
    os_release = normalize_os_release(results["system.os_release"]) if "system.os_release" in results else _not_collected_os()
    if "system.kernel" in results:
        os_release["kernel"] = normalize_kernel(results["system.kernel"])
    if "system.architecture" in results:
        os_release["architecture"] = normalize_architecture(results["system.architecture"])
    cpu = normalize_cpu_summary(results["system.cpu_summary"]) if "system.cpu_summary" in results else _not_collected_cpu()
    repositories = []
    if "git.status" in results or "git.head_commit" in results:
        repositories.append(normalize_repository(results.get("git.status"), results.get("git.head_commit")))
    inventory = {
        "schema_version": "0.2.0",
        "collection": {
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "collector_version": COLLECTOR_VERSION,
            "mode": "read_only",
            "policy_version": POLICY_VERSION,
            "host_alias": host_alias,
        },
        "redaction": {"applied": True, "rules": [], "fields_redacted": []},
        "server": {
            "metadata": metadata("phase1.read_safe"),
            "hostname": None,
            "os": os_release,
            "cpu": cpu,
            "memory": memory_parts["memory"] if memory_parts else _not_collected_memory(),
            "swap": memory_parts["swap"] if memory_parts else _not_collected_memory(),
            "storage": normalize_disk_usage(results["system.disk_usage"]) if "system.disk_usage" in results else [],
            "uptime": normalize_uptime(results["system.uptime"]) if "system.uptime" in results else None,
        },
        "projects": [],
        "users": [],
        "services": [],
        "systemd": [],
        "apache": [],
        "pm2": [],
        "docker": [],
        "databases": [],
        "repositories": repositories,
        "domains": [],
        "certificates": [],
        "ports": [],
        "firewall": [],
        "backups": [],
        "runtimes": [],
        "operational_dependencies": [],
        "relationships": [],
        "errors": _result_errors(results),
    }
    redacted = redact(inventory)
    inventory = redacted.value
    inventory["redaction"] = {
        "applied": True,
        "rules": list(redacted.rules),
        "fields_redacted": list(redacted.fields_redacted),
    }
    return inventory


def _not_collected_meta(command_id: str, status: str = "not_collected") -> dict[str, Any]:
    return metadata(command_id, status=status, sensitivity="internal")


def _not_collected_os() -> dict[str, Any]:
    return {"metadata": _not_collected_meta("system.os_release"), "name": None, "version": None, "codename": None, "kernel": None, "architecture": None}


def _not_collected_cpu() -> dict[str, Any]:
    return {
        "metadata": _not_collected_meta("system.cpu"),
        "model": None,
        "architecture": None,
        "cores": None,
        "threads": None,
        "logical_cpus": None,
        "sockets": None,
        "cores_per_socket": None,
        "threads_per_core": None,
    }


def _not_collected_memory() -> dict[str, Any]:
    return {"metadata": _not_collected_meta("system.memory"), "total_bytes": None, "used_bytes": None, "available_bytes": None}


def _result_errors(results: Mapping[str, Any]) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    for command_id, result in results.items():
        if getattr(result, "error_code", None):
            errors.append({"code": result.error_code, "category": _error_category(result.error_code), "message": f"{command_id} failed without exposing command output"})
        elif getattr(result, "returncode", 0) not in (0, None):
            errors.append({"code": "nonzero_exit", "category": "unknown", "message": f"{command_id} exited with non-zero status"})
    return errors


def _error_category(code: str) -> str:
    if code in {"permission_denied", "command_unavailable"}:
        return code
    if code == "timeout":
        return "unknown"
    return "unknown"
