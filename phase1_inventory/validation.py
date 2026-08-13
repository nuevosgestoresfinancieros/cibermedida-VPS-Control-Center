"""Schema validation and persistence gate helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .redaction import scan_for_secrets


class PersistenceDisabledError(RuntimeError):
    pass


def load_schema(schema_path: Path) -> dict[str, Any]:
    with schema_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate_inventory(inventory: dict[str, Any], schema_path: Path) -> None:
    schema = load_schema(schema_path)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(inventory)


def secret_scan_inventory(inventory: dict[str, Any]) -> None:
    scan_for_secrets(inventory)


def persist_inventory(inventory: dict[str, Any], destination: Path, enabled: bool = False) -> None:
    if not enabled:
        raise PersistenceDisabledError("Inventory persistence is disabled by default")
    secret_scan_inventory(inventory)
    destination.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
