"""READ_SAFE collection pipeline orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .commands import READ_SAFE_COMMANDS
from .collectors import collect_os_release
from .executor import RestrictedExecutor
from .inventory import build_inventory
from .validation import secret_scan_inventory, validate_inventory

INTERNAL_READ_SAFE_COLLECTORS = {"system.os_release": collect_os_release}
DEFAULT_READ_SAFE_COMMAND_IDS = ("system.os_release", *READ_SAFE_COMMANDS.keys())


def collect_read_safe_inventory(schema_path: Path, command_ids: Iterable[str] = DEFAULT_READ_SAFE_COMMAND_IDS) -> dict:
    executor = RestrictedExecutor()
    results = {}
    for command_id in command_ids:
        if command_id in INTERNAL_READ_SAFE_COLLECTORS:
            results[command_id] = INTERNAL_READ_SAFE_COLLECTORS[command_id]()
        else:
            results[command_id] = executor.execute(command_id)
    inventory = build_inventory(results)
    validate_inventory(inventory, schema_path)
    secret_scan_inventory(inventory)
    return inventory
