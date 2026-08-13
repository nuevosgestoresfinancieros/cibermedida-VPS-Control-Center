"""Internal collectors that do not fit the command executor model."""

from __future__ import annotations

from pathlib import Path

from .executor import CommandResult

OS_RELEASE_PATH = Path("/etc/os-release")
OS_RELEASE_ALLOWED_KEYS = frozenset({"NAME", "ID", "VERSION_ID", "VERSION_CODENAME"})


def collect_os_release() -> CommandResult:
    """Read only /etc/os-release and emit approved key/value lines."""
    try:
        raw = OS_RELEASE_PATH.read_text(encoding="utf-8")
    except PermissionError as exc:
        return CommandResult("system.os_release", None, "", str(exc), False, "permission_denied")
    except FileNotFoundError as exc:
        return CommandResult("system.os_release", None, "", str(exc), False, "command_unavailable")

    allowed: list[str] = []
    for line in raw.splitlines():
        parsed = _parse_os_release_line(line)
        if parsed is None:
            continue
        key, value = parsed
        if key in OS_RELEASE_ALLOWED_KEYS:
            allowed.append(f"{key}={value}")
    return CommandResult("system.os_release", 0, "\n".join(allowed) + ("\n" if allowed else ""), "")


def _parse_os_release_line(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return None
    key, value = stripped.split("=", 1)
    key = key.strip()
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return key, value
