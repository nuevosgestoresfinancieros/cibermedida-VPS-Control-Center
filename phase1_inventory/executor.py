"""Restricted executor for predefined READ_SAFE command identifiers."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .commands import CommandClass, CommandSpec, assert_argv_safe, get_command

PROJECT_ROOT = Path("/var/www/cibermedida-vps-control-center")


@dataclass(frozen=True)
class CommandResult:
    command_id: str
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    error_code: str | None = None


class CommandRejectedError(ValueError):
    pass


class RestrictedExecutor:
    def execute(self, command_id: str) -> CommandResult:
        spec = get_command(command_id)
        self._ensure_read_safe(spec)
        assert_argv_safe(spec.argv)
        try:
            completed = subprocess.run(
                list(spec.argv),
                cwd=self._cwd_for(spec),
                capture_output=True,
                text=True,
                timeout=spec.timeout_seconds,
                check=False,
                env={},
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(command_id, None, exc.stdout or "", exc.stderr or "", True, "timeout")
        except PermissionError as exc:
            return CommandResult(command_id, None, "", str(exc), False, "permission_denied")
        except FileNotFoundError as exc:
            return CommandResult(command_id, None, "", str(exc), False, "command_unavailable")
        return CommandResult(command_id, completed.returncode, completed.stdout, completed.stderr)

    @staticmethod
    def _ensure_read_safe(spec: CommandSpec) -> None:
        if spec.command_class is not CommandClass.READ_SAFE:
            raise CommandRejectedError(f"Command {spec.id} is {spec.command_class.value}, not READ_SAFE")
        if spec.requires_sudo:
            raise CommandRejectedError(f"Command {spec.id} requires sudo")

    def _cwd_for(self, spec: CommandSpec) -> Path | None:
        if spec.id.startswith("git."):
            return PROJECT_ROOT
        return None
