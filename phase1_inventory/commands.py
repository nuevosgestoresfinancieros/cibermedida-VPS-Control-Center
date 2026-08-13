"""Structured command allowlist for Phase 1 READ_SAFE collection."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Sequence


class CommandClass(str, Enum):
    READ_SAFE = "READ_SAFE"
    READ_SENSITIVE = "READ_SENSITIVE"
    READ_PRIVILEGED = "READ_PRIVILEGED"
    FORBIDDEN = "FORBIDDEN"


@dataclass(frozen=True)
class CommandSpec:
    id: str
    command_class: CommandClass
    argv: tuple[str, ...]
    timeout_seconds: float
    description: str
    requires_sudo: bool = False


READ_SAFE_COMMANDS: Mapping[str, CommandSpec] = {
    "system.disk_usage": CommandSpec(
        id="system.disk_usage",
        command_class=CommandClass.READ_SAFE,
        argv=("df", "-B1", "--output=source,fstype,size,used,avail,pcent,target"),
        timeout_seconds=5,
        description="Filesystem usage summary",
    ),
    "system.memory": CommandSpec(
        id="system.memory",
        command_class=CommandClass.READ_SAFE,
        argv=("free", "-b"),
        timeout_seconds=5,
        description="Memory and swap usage summary",
    ),
    "system.uptime": CommandSpec(
        id="system.uptime",
        command_class=CommandClass.READ_SAFE,
        argv=("uptime",),
        timeout_seconds=5,
        description="Uptime and load summary",
    ),
    "system.kernel": CommandSpec(
        id="system.kernel",
        command_class=CommandClass.READ_SAFE,
        argv=("uname", "-r"),
        timeout_seconds=5,
        description="Kernel release",
    ),
    "system.architecture": CommandSpec(
        id="system.architecture",
        command_class=CommandClass.READ_SAFE,
        argv=("uname", "-m"),
        timeout_seconds=5,
        description="Machine architecture",
    ),
    "system.cpu_summary": CommandSpec(
        id="system.cpu_summary",
        command_class=CommandClass.READ_SAFE,
        argv=("lscpu", "-J"),
        timeout_seconds=5,
        description="CPU summary in JSON with approved fields only",
    ),
    "git.status": CommandSpec(
        id="git.status",
        command_class=CommandClass.READ_SAFE,
        argv=("git", "status", "--short", "--branch"),
        timeout_seconds=5,
        description="Repository branch and dirty status",
    ),
    "git.head_commit": CommandSpec(
        id="git.head_commit",
        command_class=CommandClass.READ_SAFE,
        argv=("git", "rev-parse", "--short=12", "HEAD"),
        timeout_seconds=5,
        description="Current repository HEAD short hash",
    ),
}

BLOCKED_COMMANDS: Mapping[str, CommandSpec] = {
    "system.ports": CommandSpec(
        id="system.ports",
        command_class=CommandClass.READ_SENSITIVE,
        argv=("ss", "-tulpnH"),
        timeout_seconds=5,
        description="Bounded port summary",
    ),
    "privileged.firewall_summary": CommandSpec(
        id="privileged.firewall_summary",
        command_class=CommandClass.READ_PRIVILEGED,
        argv=("ufw", "status", "numbered"),
        timeout_seconds=5,
        description="Privileged firewall summary",
        requires_sudo=True,
    ),
    "forbidden.docker_inspect": CommandSpec(
        id="forbidden.docker_inspect",
        command_class=CommandClass.FORBIDDEN,
        argv=("docker", "inspect"),
        timeout_seconds=5,
        description="Forbidden raw docker inspect",
    ),
}

COMMANDS: Mapping[str, CommandSpec] = {**READ_SAFE_COMMANDS, **BLOCKED_COMMANDS}


def get_command(command_id: str) -> CommandSpec:
    try:
        return COMMANDS[command_id]
    except KeyError as exc:
        raise KeyError(f"Unknown command id: {command_id}") from exc


def assert_argv_safe(argv: Sequence[str]) -> None:
    if not argv:
        raise ValueError("Command argv cannot be empty")
    if any(not isinstance(part, str) or not part for part in argv):
        raise ValueError("Command argv must contain non-empty strings")
    if argv[0] == "sudo" or "sudo" in argv:
        raise ValueError("sudo is not allowed in Phase 1 READ_SAFE commands")
