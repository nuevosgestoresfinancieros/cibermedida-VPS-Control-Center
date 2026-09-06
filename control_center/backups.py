"""Controlled backup catalog with an in-memory provider for laboratory use."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Mapping, Protocol
from uuid import uuid4

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret

from .audit import MetadataAuditLog
from .auth import AuthService, Permission
from .state import JsonMetadataStore


class BackupType(str, Enum):
    CODE = "code"
    CONFIGURATION = "configuration"
    DATABASE = "database"
    APPLICATION = "application"
    PRE_DEPLOY = "pre_deploy"
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class BackupState(str, Enum):
    PREPARED = "prepared"
    VERIFIED = "verified"
    RESTORE_TESTED = "restore_tested"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class BackupRecord:
    backup_id: str
    project: str
    backup_type: BackupType
    source_label: str
    destination_label: str
    checksum: str
    created_at: str
    created_by: str
    state: BackupState
    verified_at: str | None = None
    restore_tested_at: str | None = None
    retention: str = "manual"
    server: str = "local-lab"
    environment: str = "laboratory"
    path: str | None = None
    size_bytes: int | None = None
    retention_until: str | None = None
    related_operation: str | None = None
    related_deployment: str | None = None
    verified: bool = False
    restore_tested: bool = False


@dataclass(frozen=True)
class BackupProviderEvidence:
    provider: str
    checksum: str
    result: str
    verified: bool = False


class BackupProvider(Protocol):
    name: str

    def prepare(
        self,
        *,
        project: str,
        backup_type: BackupType,
        source_label: str,
        destination_label: str,
    ) -> BackupProviderEvidence:
        ...

    def verify(self, *, record: BackupRecord) -> BackupProviderEvidence:
        ...

    def restore_test(self, *, record: BackupRecord) -> BackupProviderEvidence:
        ...


class BackupManager:
    """Tracks backup workflow without touching files or databases."""

    def __init__(
        self,
        *,
        auth: AuthService,
        audit: MetadataAuditLog,
        provider: BackupProvider | None = None,
        provider_enabled: bool = False,
        state_store: JsonMetadataStore | None = None,
    ) -> None:
        self.auth = auth
        self.audit = audit
        self.provider = provider
        self.provider_enabled = provider_enabled
        self.state_store = state_store
        self._records: dict[str, BackupRecord] = {}
        if self.state_store is not None:
            for raw_record in self.state_store.load():
                record = _decode_record(raw_record)
                if record.backup_id in self._records:
                    raise ValueError("backup state contains duplicate ids")
                self._records[record.backup_id] = record

    @property
    def records(self) -> tuple[BackupRecord, ...]:
        return tuple(self._records.values())

    def get(self, backup_id: str) -> BackupRecord:
        return self._get(backup_id)

    def is_verified(self, backup_id: str) -> bool:
        record = self._get(backup_id)
        return record.state in {BackupState.VERIFIED, BackupState.RESTORE_TESTED}

    def prepare(
        self,
        *,
        session_id: str,
        project: str,
        backup_type: BackupType,
        source_label: str,
        destination_label: str,
        retention: str = "manual",
        server: str = "local-lab",
        environment: str = "laboratory",
        path: str | None = None,
        size_bytes: int | None = None,
        retention_until: str | None = None,
        related_operation: str | None = None,
        related_deployment: str | None = None,
    ) -> BackupRecord:
        user = self.auth.require(session_id, Permission.CREATE_BACKUP)
        if not all(
            _safe_field(value)
            for value in (project, source_label, destination_label, retention, server, environment)
        ):
            raise ValueError("backup metadata is incomplete")
        for value in (path, retention_until, related_operation, related_deployment):
            if value is not None and not _safe_field(value):
                raise ValueError("backup metadata is unsafe")
        if size_bytes is not None and (isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes < 0):
            raise ValueError("backup size is invalid")
        backup_id = f"backup-{uuid4()}"
        checksum = hashlib.sha256(f"{backup_id}:{project}:{backup_type.value}".encode()).hexdigest()
        state = BackupState.PREPARED
        result = state.value
        if self.provider_enabled and self.provider is not None:
            try:
                evidence = self.provider.prepare(
                    project=project,
                    backup_type=backup_type,
                    source_label=source_label,
                    destination_label=destination_label,
                )
            except Exception:
                evidence = None
            if not _valid_evidence(evidence):
                state = BackupState.BLOCKED
                result = state.value
            else:
                checksum = evidence.checksum
                result = evidence.result
        record = BackupRecord(
            backup_id=backup_id,
            project=project,
            backup_type=backup_type,
            source_label=source_label,
            destination_label=destination_label,
            checksum=checksum,
            created_at=_now(),
            created_by=user.username,
            state=state,
            retention=retention,
            server=server,
            environment=environment,
            path=path,
            size_bytes=size_bytes,
            retention_until=retention_until,
            related_operation=related_operation,
            related_deployment=related_deployment,
            verified=False,
            restore_tested=False,
        )
        updated_records = dict(self._records)
        updated_records[backup_id] = record
        self._persist(updated_records)
        self._records = updated_records
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=project,
            action="backup_prepared",
            risk="HIGH",
            authorization="permission:CREATE_BACKUP",
            backup=backup_id,
            result=result,
        )
        return record

    def verify(self, *, session_id: str, backup_id: str) -> BackupRecord:
        user = self.auth.require(session_id, Permission.CREATE_BACKUP)
        record = self._get(backup_id)
        if record.state is not BackupState.PREPARED:
            raise ValueError("backup must be prepared before verification")
        verified = True
        result = BackupState.VERIFIED.value
        if self.provider_enabled and self.provider is not None:
            try:
                evidence = self.provider.verify(record=record)
            except Exception:
                evidence = None
            verified = _valid_evidence(evidence) and evidence.verified
            result = evidence.result if verified else BackupState.BLOCKED.value
        updated = BackupRecord(
            **{
                **record.__dict__,
                "state": BackupState.VERIFIED if verified else BackupState.BLOCKED,
                "verified_at": _now() if verified else None,
                "verified": verified,
            }
        )
        updated_records = dict(self._records)
        updated_records[backup_id] = updated
        self._persist(updated_records)
        self._records = updated_records
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=record.project,
            action="backup_verified",
            risk="HIGH",
            authorization="permission:CREATE_BACKUP",
            backup=backup_id,
            result=result,
        )
        return updated

    def restore_test(self, *, session_id: str, backup_id: str) -> BackupRecord:
        user = self.auth.require(session_id, Permission.CREATE_BACKUP)
        record = self._get(backup_id)
        if record.state is not BackupState.VERIFIED:
            raise ValueError("backup must be verified before restore test")
        tested = True
        result = BackupState.RESTORE_TESTED.value
        if self.provider_enabled and self.provider is not None:
            try:
                evidence = self.provider.restore_test(record=record)
            except Exception:
                evidence = None
            tested = _valid_evidence(evidence) and evidence.verified
            result = evidence.result if tested else BackupState.BLOCKED.value
        updated = BackupRecord(
            **{
                **record.__dict__,
                "state": BackupState.RESTORE_TESTED if tested else BackupState.BLOCKED,
                "restore_tested_at": _now() if tested else None,
                "verified": record.verified,
                "restore_tested": tested,
            }
        )
        updated_records = dict(self._records)
        updated_records[backup_id] = updated
        self._persist(updated_records)
        self._records = updated_records
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=record.project,
            action="backup_restore_tested",
            risk="HIGH",
            authorization="permission:CREATE_BACKUP",
            backup=backup_id,
            result=result,
        )
        return updated

    def _get(self, backup_id: str) -> BackupRecord:
        try:
            return self._records[backup_id]
        except KeyError as exc:
            raise ValueError("backup does not exist") from exc

    def _persist(self, records: Mapping[str, BackupRecord]) -> None:
        if self.state_store is not None:
            self.state_store.save(_encode_record(record) for record in records.values())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _valid_evidence(value: object) -> bool:
    if not isinstance(value, BackupProviderEvidence):
        return False
    fields = (value.provider, value.checksum, value.result)
    return all(
        isinstance(item, str)
        and item.strip()
        and len(item) <= 512
        and not contains_secret(item)
        and RAW_STREAM_PATTERN.search(item) is None
        for item in fields
    ) and isinstance(value.verified, bool)


def _encode_record(record: BackupRecord) -> dict[str, object]:
    return {
        "backup_id": record.backup_id,
        "project": record.project,
        "backup_type": record.backup_type.value,
        "source_label": record.source_label,
        "destination_label": record.destination_label,
        "checksum": record.checksum,
        "created_at": record.created_at,
        "created_by": record.created_by,
        "state": record.state.value,
        "verified_at": record.verified_at,
        "restore_tested_at": record.restore_tested_at,
        "retention": record.retention,
        "server": record.server,
        "environment": record.environment,
        "path": record.path,
        "size_bytes": record.size_bytes,
        "retention_until": record.retention_until,
        "related_operation": record.related_operation,
        "related_deployment": record.related_deployment,
        "verified": record.verified,
        "restore_tested": record.restore_tested,
    }


def _decode_record(value: Mapping[str, object]) -> BackupRecord:
    try:
        record = BackupRecord(
            backup_id=_required_field(value, "backup_id"),
            project=_required_field(value, "project"),
            backup_type=BackupType(value["backup_type"]),
            source_label=_required_field(value, "source_label"),
            destination_label=_required_field(value, "destination_label"),
            checksum=_required_field(value, "checksum", max_length=256),
            created_at=_required_field(value, "created_at"),
            created_by=_required_field(value, "created_by"),
            state=BackupState(value["state"]),
            verified_at=_optional_field(value, "verified_at"),
            restore_tested_at=_optional_field(value, "restore_tested_at"),
            retention=_required_field(value, "retention"),
            server=_required_field(value, "server") if value.get("server") is not None else "local-lab",
            environment=_required_field(value, "environment") if value.get("environment") is not None else "laboratory",
            path=_optional_field(value, "path"),
            size_bytes=_optional_size(value, "size_bytes"),
            retention_until=_optional_field(value, "retention_until"),
            related_operation=_optional_field(value, "related_operation"),
            related_deployment=_optional_field(value, "related_deployment"),
            verified=bool(value.get("verified", False)),
            restore_tested=bool(value.get("restore_tested", False)),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("backup state record is invalid") from exc
    return record


def _required_field(value: Mapping[str, object], key: str, *, max_length: int = 256) -> str:
    item = value[key]
    if not isinstance(item, str) or not item.strip() or len(item) > max_length or not _safe_field(item):
        raise ValueError(f"backup state field {key} is invalid")
    return item.strip()


def _optional_field(value: Mapping[str, object], key: str) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    return _required_field(value, key)


def _optional_size(value: Mapping[str, object], key: str) -> int | None:
    item = value.get(key)
    if item is None:
        return None
    if isinstance(item, bool) or not isinstance(item, int) or item < 0:
        raise ValueError(f"backup state field {key} is invalid")
    return item


def _safe_field(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= 256
        and not contains_secret(value)
        and RAW_STREAM_PATTERN.search(value) is None
        and not any(ord(character) < 32 for character in value)
    )
