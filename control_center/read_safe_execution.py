"""Bounded READ_SAFE provider for the controlled-execution boundary."""

from __future__ import annotations

import time

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret
from phase1_inventory.commands import CommandClass, get_command
from phase1_inventory.executor import CommandResult, RestrictedExecutor

from .execution import ProviderEvidence
from .read_safe_monitoring import ReadSafeCommandRunner


class ReadSafeExecutionProvider:
    """Execute only predefined READ_SAFE commands and return no raw output."""

    name = "phase1-read-safe-execution"
    live_data = True

    def __init__(self, *, executor: ReadSafeCommandRunner | None = None) -> None:
        self.executor = executor or RestrictedExecutor()

    def run(self, *, actor: str, action: str, command_id: str) -> ProviderEvidence:
        del actor
        if action != "read":
            raise ValueError("READ_SAFE provider accepts only the read action")
        spec = get_command(command_id)
        if spec.command_class is not CommandClass.READ_SAFE or spec.requires_sudo:
            raise ValueError("command is outside the READ_SAFE provider scope")
        started = time.monotonic()
        result = self.executor.execute(command_id)
        if not isinstance(result, CommandResult) or result.returncode != 0 or result.timed_out or result.error_code:
            raise ValueError("READ_SAFE command failed")
        if contains_secret(result.stdout) or RAW_STREAM_PATTERN.search(result.stdout):
            raise ValueError("READ_SAFE output is unsafe")
        duration_ms = max(0, int((time.monotonic() - started) * 1000))
        return ProviderEvidence(
            provider=self.name,
            result="read_safe_metadata_collected",
            duration_ms=duration_ms,
        )


class SyntheticReadSafeExecutionProvider:
    """Validate READ_SAFE requests without invoking an executor."""

    name = "synthetic-read-safe-execution"
    live_data = False

    def run(self, *, actor: str, action: str, command_id: str) -> ProviderEvidence:
        del actor
        if action != "read":
            raise ValueError("READ_SAFE provider accepts only the read action")
        spec = get_command(command_id)
        if spec.command_class is not CommandClass.READ_SAFE or spec.requires_sudo:
            raise ValueError("command is outside the READ_SAFE provider scope")
        return ProviderEvidence(
            provider=self.name,
            result="synthetic_read_safe_metadata_collected",
            duration_ms=0,
        )
