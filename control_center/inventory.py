"""Explicit READ_SAFE inventory boundary for the Control Center.

The service keeps the latest validated inventory in memory only.  A provider
must be enabled explicitly; no provider is discovered or executed by default.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret
from phase1_inventory.executor import CommandResult
from phase1_inventory.inventory import build_inventory
from phase1_inventory.pipeline import collect_read_safe_inventory
from phase1_inventory.validation import secret_scan_inventory, validate_inventory

from .audit import MetadataAuditLog
from .auth import AuthService, Permission
from .state import JsonMetadataStore


class InventoryProvider(Protocol):
    """Provider that returns one already bounded, schema-shaped inventory."""

    name: str
    live_data: bool

    def collect(self) -> dict[str, Any]:
        ...


class InventoryCollectionState(str, Enum):
    NOT_COLLECTED = "not_collected"
    COLLECTED = "collected"
    FAILED = "failed"
    REJECTED = "rejected"


@dataclass(frozen=True)
class InventoryCollectionResult:
    state: InventoryCollectionState
    provider: str | None
    live_data: bool
    persisted: bool
    inventory: dict[str, Any] | None
    reason: str
    source: str = "declared"
    confidence: float = 0.0
    last_verified: str | None = None


class ReadSafeInventoryProvider:
    """Opt-in adapter for the existing Phase 1 READ_SAFE pipeline."""

    name = "phase1-read-safe-inventory"
    live_data = True

    def __init__(self, schema_path: str | Path) -> None:
        self.schema_path = Path(schema_path)
        if not self.schema_path.is_absolute() or self.schema_path.suffix != ".json":
            raise ValueError("inventory schema path must be an absolute JSON path")
        if not self.schema_path.is_file() or self.schema_path.is_symlink():
            raise ValueError("inventory schema path must be a regular file")

    def collect(self) -> dict[str, Any]:
        return collect_read_safe_inventory(self.schema_path)


class SyntheticInventoryProvider:
    """Safe schema fixture used only by the isolated laboratory profile."""

    name = "synthetic-read-safe-inventory"
    live_data = False

    def __init__(self, schema_path: str | Path) -> None:
        self.schema_path = Path(schema_path)
        if not self.schema_path.is_absolute() or self.schema_path.suffix != ".json":
            raise ValueError("inventory schema path must be an absolute JSON path")
        if not self.schema_path.is_file() or self.schema_path.is_symlink():
            raise ValueError("inventory schema path must be a regular file")

    def collect(self) -> dict[str, Any]:
        results = {
            "system.os_release": CommandResult(
                "system.os_release",
                0,
                "NAME=Laboratory OS\nID=cibermedida-lab\nVERSION_ID=1\nVERSION_CODENAME=lab\n",
                "",
            ),
            "system.kernel": CommandResult("system.kernel", 0, "laboratory-kernel\n", ""),
            "system.architecture": CommandResult("system.architecture", 0, "x86_64\n", ""),
            "system.cpu_summary": CommandResult(
                "system.cpu_summary",
                0,
                json.dumps(
                    {
                        "lscpu": [
                            {"field": "Architecture:", "data": "x86_64"},
                            {"field": "CPU(s):", "data": "4"},
                            {"field": "Thread(s) per core:", "data": "2"},
                            {"field": "Core(s) per socket:", "data": "2"},
                            {"field": "Socket(s):", "data": "1"},
                            {"field": "Model name:", "data": "Laboratory CPU"},
                        ]
                    }
                ),
                "",
            ),
            "system.memory": CommandResult(
                "system.memory",
                0,
                "total used free shared buff/cache available\nMem: 4096 1024 2048 0 1024 3072\nSwap: 1024 0 1024\n",
                "",
            ),
            "system.disk_usage": CommandResult(
                "system.disk_usage",
                0,
                "Filesystem Type 1B-blocks Used Available Use% Mounted on\nlabfs ext4 1000000 250000 750000 25% /\n",
                "",
            ),
            "system.uptime": CommandResult("system.uptime", 0, "up 1 day, load average: 0.10, 0.12, 0.15\n", ""),
            "git.status": CommandResult("git.status", 0, "## lab-fixture\n", ""),
            "git.head_commit": CommandResult("git.head_commit", 0, "abcdef123456\n", ""),
        }
        inventory = build_inventory(results, host_alias="laboratory")
        validate_inventory(inventory, self.schema_path)
        secret_scan_inventory(inventory)
        return inventory


class InventoryService:
    """Policy-gated in-memory inventory collection service."""

    def __init__(
        self,
        *,
        auth: AuthService,
        audit: MetadataAuditLog,
        provider: InventoryProvider | None = None,
        provider_enabled: bool = False,
        schema_path: str | Path | None = None,
        state_store: JsonMetadataStore | None = None,
    ) -> None:
        self.auth = auth
        self.audit = audit
        self.provider = provider
        self.provider_enabled = provider_enabled and provider is not None
        self.schema_path = Path(schema_path) if schema_path is not None else None
        self.state_store = state_store
        if self.schema_path is not None and (
            not self.schema_path.is_absolute()
            or self.schema_path.suffix != ".json"
            or not self.schema_path.is_file()
            or self.schema_path.is_symlink()
        ):
            raise ValueError("inventory schema path must be a regular absolute JSON file")
        self._latest: InventoryCollectionResult | None = None
        # A persisted snapshot is only visible when the matching provider is
        # explicitly enabled for this process. This prevents a stale inventory
        # from silently becoming the default data source.
        if self.provider_enabled and self.state_store is not None:
            records = self.state_store.load()
            if records:
                self._latest = _decode_result(
                    records[-1],
                    self.schema_path,
                    expected_provider=str(getattr(self.provider, "name", "injected")),
                    expected_live_data=bool(getattr(self.provider, "live_data", False)),
                )

    @property
    def latest(self) -> InventoryCollectionResult | None:
        return self._latest

    def collect(self, *, session_id: str) -> InventoryCollectionResult:
        user = self.auth.require(session_id, Permission.RUN_READ_SAFE)
        provider_name = getattr(self.provider, "name", None) if self.provider_enabled else None
        live_data = bool(self.provider_enabled and getattr(self.provider, "live_data", False))
        if not self.provider_enabled or self.provider is None:
            result = InventoryCollectionResult(
                state=InventoryCollectionState.NOT_COLLECTED,
                provider=None,
                live_data=False,
                persisted=False,
                inventory=None,
                reason="READ_SAFE inventory provider is disabled",
            )
        else:
            try:
                candidate = self.provider.collect()
                if not isinstance(candidate, dict):
                    raise ValueError("provider returned a non-object inventory")
                if self.schema_path is not None:
                    validate_inventory(candidate, self.schema_path)
                    secret_scan_inventory(candidate)
                if _unsafe_serialized(candidate):
                    raise ValueError("provider returned unsafe inventory metadata")
                result = InventoryCollectionResult(
                    state=InventoryCollectionState.COLLECTED,
                    provider=str(provider_name),
                    live_data=live_data,
                    persisted=self.state_store is not None,
                    inventory=candidate,
                    reason=(
                        "validated READ_SAFE inventory retained in memory and safe state"
                        if self.state_store is not None
                        else "validated READ_SAFE inventory retained in memory only"
                    ),
                    source="discovered" if live_data else "declared",
                    confidence=1.0,
                    last_verified=_now(),
                )
                if self.state_store is not None:
                    self.state_store.save([_encode_result(result)])
            except Exception:
                result = InventoryCollectionResult(
                    state=InventoryCollectionState.FAILED,
                    provider=str(provider_name),
                    live_data=live_data,
                    persisted=False,
                    inventory=None,
                    reason="inventory provider failed without exposing raw output",
                )
        self._latest = result
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project="control-center",
            action="inventory_collection_requested",
            risk="LOW",
            authorization="permission:RUN_READ_SAFE",
            result=result.state.value,
            metadata={
                "provider": result.provider or "none",
                "live_data": result.live_data,
                "persisted": result.persisted,
                "inventory_fields": len(result.inventory) if result.inventory is not None else 0,
                "source": result.source,
                "confidence": result.confidence,
                "last_verified": result.last_verified,
            },
        )
        return result

    def summary(self) -> dict[str, Any]:
        latest = self._latest
        if latest is None:
            return {
                "mode": "read_safe_provider_disabled",
                "liveData": False,
                "persisted": False,
                "status": InventoryCollectionState.NOT_COLLECTED.value,
                "provider": None,
                "message": "El inventario READ_SAFE requiere una habilitación explícita.",
                "source": "declared",
                "confidence": 0.0,
                "lastVerified": None,
            }
        return {
            "mode": "read_safe_provider" if latest.live_data else "synthetic_read_safe_provider",
            "liveData": latest.live_data,
            "persisted": latest.persisted,
            "status": latest.state.value,
            "provider": latest.provider,
            "message": latest.reason,
            "source": latest.source,
            "confidence": latest.confidence,
            "lastVerified": latest.last_verified,
        }


def _unsafe_serialized(value: object) -> bool:
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return contains_secret(serialized) or RAW_STREAM_PATTERN.search(serialized) is not None


def _encode_result(result: InventoryCollectionResult) -> dict[str, Any]:
    return {
        "state": result.state.value,
        "provider": result.provider,
        "live_data": result.live_data,
        "persisted": True,
        "inventory": result.inventory,
        "reason": result.reason,
        "source": result.source,
        "confidence": result.confidence,
        "last_verified": result.last_verified,
    }


def _decode_result(
    value: dict[str, Any],
    schema_path: Path | None,
    *,
    expected_provider: str,
    expected_live_data: bool,
) -> InventoryCollectionResult:
    if value.get("state") != InventoryCollectionState.COLLECTED.value or not isinstance(value.get("inventory"), dict):
        raise ValueError("inventory state record is invalid")
    inventory = value["inventory"]
    if schema_path is not None:
        validate_inventory(inventory, schema_path)
        secret_scan_inventory(inventory)
    if _unsafe_serialized(inventory):
        raise ValueError("inventory state contains unsafe metadata")
    provider = value.get("provider")
    if provider is not None and not isinstance(provider, str):
        raise ValueError("inventory provider metadata is invalid")
    if provider != expected_provider or bool(value.get("live_data", False)) is not expected_live_data:
        raise ValueError("inventory state provider does not match the enabled provider")
    return InventoryCollectionResult(
        state=InventoryCollectionState.COLLECTED,
        provider=provider,
        live_data=bool(value.get("live_data", False)),
        persisted=True,
        inventory=inventory,
        reason="validated READ_SAFE inventory restored from safe state",
        source=str(value.get("source", "discovered" if bool(value.get("live_data", False)) else "declared")),
        confidence=float(value.get("confidence", 1.0)),
        last_verified=value.get("last_verified") if isinstance(value.get("last_verified"), str) else None,
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
