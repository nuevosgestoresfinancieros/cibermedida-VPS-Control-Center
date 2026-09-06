"""Audit storage primitives for the Phase 2 Core Operator base."""

from __future__ import annotations

import json
import os
import re
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Protocol

try:
    import fcntl
except ImportError:  # pragma: no cover - the supported VPS runtime is Unix.
    fcntl = None  # type: ignore[assignment]

from .config import OperatorConfig
from .policy import RiskLevel
from .safe_logging import SECRET_PATTERNS, redact_text

RAW_STREAM_PATTERN = re.compile(r"(?i)\b(std(?:out|err))\s*[:=]")
DEFAULT_AUDIT_MAX_BYTES = 16 * 1024 * 1024
DEFAULT_AUDIT_RETENTION_FILES = 3
MAX_AUDIT_RETENTION_FILES = 16


class UnsafeAuditEventError(ValueError):
    pass


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    actor: str
    action: str
    risk_level: RiskLevel
    command_id: str | None
    result: str
    authorization_required: bool


class AuditStore(Protocol):
    @property
    def events(self) -> tuple[AuditEvent, ...]:
        ...

    def append(
        self,
        *,
        actor: str,
        action: str,
        risk_level: RiskLevel,
        command_id: str | None,
        result: str,
        authorization_required: bool,
    ) -> AuditEvent:
        ...


class InMemoryAuditStore:
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def append(
        self,
        *,
        actor: str,
        action: str,
        risk_level: RiskLevel,
        command_id: str | None,
        result: str,
        authorization_required: bool,
    ) -> AuditEvent:
        event = build_redacted_audit_event(
            actor=actor,
            action=action,
            risk_level=risk_level,
            command_id=command_id,
            result=result,
            authorization_required=authorization_required,
        )
        self._events.append(event)
        return event


class JsonlAuditStore:
    def __init__(self, *, config: OperatorConfig) -> None:
        config.validate()
        if not config.persistence_enabled or not config.audit_to_disk:
            raise ValueError("JSONL audit storage requires explicit disk persistence")
        config.validate()
        self.path = config.resolve_audit_path()
        self.max_bytes = config.audit_max_bytes
        self.retention_files = config.audit_retention_files
        self._events: list[AuditEvent] = list(self._load_events())

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def append(
        self,
        *,
        actor: str,
        action: str,
        risk_level: RiskLevel,
        command_id: str | None,
        result: str,
        authorization_required: bool,
    ) -> AuditEvent:
        fail_if_unsafe_for_persistence(actor, action, command_id, result)
        event = build_redacted_audit_event(
            actor=actor,
            action=action,
            risk_level=risk_level,
            command_id=command_id,
            result=result,
            authorization_required=authorization_required,
        )
        record = serialize_audit_event(event)
        fail_if_unsafe_for_persistence(
            record["actor"],
            record["action"],
            record["command_id"],
            record["result"],
        )
        line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        line_size = len(line.encode("utf-8"))
        if line_size > self.max_bytes:
            raise ValueError("audit event exceeds size limit")
        with _audit_file_lock(self.path, exclusive=True):
            current_size = self.path.stat().st_size if self.path.exists() else 0
            if current_size + line_size > self.max_bytes:
                _rotate_audit_files(self.path, self.retention_files)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(self.path, 0o600)
        self._events.append(event)
        return event

    def _load_events(self) -> tuple[AuditEvent, ...]:
        events: list[AuditEvent] = []
        try:
            with _audit_file_lock(self.path, exclusive=False):
                for path in _audit_read_paths(self.path, self.retention_files):
                    if not path.exists():
                        continue
                    _ensure_regular_audit_file(path)
                    if path.stat().st_size > self.max_bytes:
                        raise ValueError("audit store is too large")
                    with path.open("r", encoding="utf-8") as handle:
                        for line in handle:
                            if not line.strip():
                                continue
                            events.append(deserialize_audit_event(json.loads(line)))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("audit store cannot be loaded") from exc
        return tuple(events)


def build_redacted_audit_event(
    *,
    actor: str,
    action: str,
    risk_level: RiskLevel,
    command_id: str | None,
    result: str,
    authorization_required: bool,
) -> AuditEvent:
    return AuditEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        actor=redact_text(actor),
        action=redact_text(action),
        risk_level=risk_level,
        command_id=redact_text(command_id) if command_id else None,
        result=redact_text(result),
        authorization_required=authorization_required,
    )


def serialize_audit_event(event: AuditEvent) -> dict[str, object]:
    return {
        "timestamp": event.timestamp,
        "actor": event.actor,
        "action": event.action,
        "risk_level": event.risk_level.value,
        "command_id": event.command_id,
        "result": event.result,
        "authorization_required": event.authorization_required,
    }


def deserialize_audit_event(value: object) -> AuditEvent:
    """Decode one persisted event while preserving the metadata-only boundary."""

    if not isinstance(value, dict):
        raise ValueError("audit event must be an object")
    text_fields = ("timestamp", "actor", "action", "result")
    if any(not isinstance(value.get(field), str) or not value[field].strip() for field in text_fields):
        raise ValueError("audit event text fields are invalid")
    command_id = value.get("command_id")
    if command_id is not None and (not isinstance(command_id, str) or not command_id.strip()):
        raise ValueError("audit event command_id is invalid")
    risk_value = value.get("risk_level")
    try:
        risk_level = RiskLevel(risk_value)
    except (TypeError, ValueError) as exc:
        raise ValueError("audit event risk level is invalid") from exc
    authorization_required = value.get("authorization_required")
    if not isinstance(authorization_required, bool):
        raise ValueError("audit event authorization flag is invalid")
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
    fail_if_unsafe_for_persistence(
        value["actor"],
        value["action"],
        command_id,
        value["result"],
        serialized,
    )
    return AuditEvent(
        timestamp=value["timestamp"],
        actor=value["actor"],
        action=value["action"],
        risk_level=risk_level,
        command_id=command_id,
        result=value["result"],
        authorization_required=authorization_required,
    )


def fail_if_unsafe_for_persistence(*values: str | None) -> None:
    for value in values:
        if value is None:
            continue
        if contains_secret(value):
            raise UnsafeAuditEventError("audit event contains secret-like content")
        if RAW_STREAM_PATTERN.search(value):
            raise UnsafeAuditEventError("audit event contains raw stream-like content")


def contains_secret(value: str) -> bool:
    return any(pattern.search(value) for pattern in SECRET_PATTERNS)


@contextmanager
def _audit_file_lock(path: Path, *, exclusive: bool) -> Iterator[None]:
    """Coordinate JSONL readers/writers across threads and processes."""

    if fcntl is None:
        yield
        return
    lock_path = path.with_name(f".{path.name}.lock")
    try:
        with lock_path.open("a+", encoding="utf-8") as lock_handle:
            os.chmod(lock_path, 0o600)
            operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            fcntl.flock(lock_handle.fileno(), operation)
            try:
                yield
            finally:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
    except OSError as exc:
        raise ValueError("audit store lock cannot be acquired") from exc


def _audit_rotation_path(path: Path, index: int) -> Path:
    return path.with_name(f"{path.name}.{index}")


def _audit_read_paths(path: Path, retention_files: int) -> tuple[Path, ...]:
    rotated = tuple(_audit_rotation_path(path, index) for index in range(retention_files, 0, -1))
    return rotated + (path,)


def _ensure_regular_audit_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("audit rotation path must be a regular file")


def _rotate_audit_files(path: Path, retention_files: int) -> None:
    if path.exists():
        _ensure_regular_audit_file(path)
    oldest = _audit_rotation_path(path, retention_files)
    if oldest.exists():
        _ensure_regular_audit_file(oldest)
        oldest.unlink()
    for index in range(retention_files - 1, 0, -1):
        source = _audit_rotation_path(path, index)
        if not source.exists():
            continue
        _ensure_regular_audit_file(source)
        target = _audit_rotation_path(path, index + 1)
        os.replace(source, target)
        os.chmod(target, 0o600)
    if path.exists():
        target = _audit_rotation_path(path, 1)
        os.replace(path, target)
        os.chmod(target, 0o600)
