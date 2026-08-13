"""READ_SAFE collection pipeline orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .commands import READ_SAFE_COMMANDS
from .executor import RestrictedExecutor
from .inventory import build_inventory
from .validation import secret_scan_inventory, validate_inventory

DEFAULT_READ_SAFE_COMMAND_IDS = tuple(READ_SAFE_COMMANDS.keys())


def collect_read_safe_inventory(schema_path: Path, command_ids: Iterable[str] = DEFAULT_READ_SAFE_COMMAND_IDS, cwd: Path | None = None) -> dict:
    executor = RestrictedExecutor(cwd=cwd)
    results = {command_id: executor.execute(command_id) for command_id in command_ids}
    inventory = build_inventory(results)
    validate_inventory(inventory, schema_path)
    secret_scan_inventory(inventory)
    return inventory
