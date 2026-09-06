"""Metadata-only in-memory audit records for application workflows."""

from __future__ import annotations

import json
import fcntl
import os
import re
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Protocol
from uuid import uuid4

from core_operator.safe_logging import SECRET_PATTERNS, sanitize


RAW_STREAM_PATTERN = re.compile(r"(?i)\b(std(?:out|err))\s*[:=]")
DEFAULT_AUDIT_MAX_BYTES = 16 * 1024 * 1024
DEFAULT_AUDIT_RETENTION_FILES = 3
MAX_AUDIT_RETENTION_FILES = 16


@dataclass(frozen=True)
class AuditRecord:
    record_id: str
    timestamp: str
    user_id: str
    actor: str
    role: str
    agent: str
    project: str | None
    action: str
    risk: str
    command: str | None
    authorization: str
    backup: str | None
    commit: str | None
    result: str
    duration_ms: int | None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    operation_id: str | None = None
    plan: str | None = None
    approval: str | None = None
    commands: tuple[str, ...] = ()
    files: tuple[str, ...] = ()
    branch: str | None = None
    validation: str | None = None
    rollback: str | None = None


class AuditSink(Protocol):
    def write(self, record: AuditRecord) -> None:
        ...


class JsonlAuditSink:
    """Explicit metadata-only JSONL sink with bounded rotation and retention."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_bytes: int = DEFAULT_AUDIT_MAX_BYTES,
        retention_files: int = DEFAULT_AUDIT_RETENTION_FILES,
    ) -> None:
        self.path = _validate_audit_path(Path(path))
        if max_bytes < 1024:
            raise ValueError("audit max_bytes is too small")
        if retention_files < 1 or retention_files > MAX_AUDIT_RETENTION_FILES:
            raise ValueError("audit retention_files is invalid")
        self.max_bytes = max_bytes
        self.retention_files = retention_files
        self._lock = threading.Lock()

    def write(self, record: AuditRecord) -> None:
        payload = {
            "record_id": record.record_id,
            "timestamp": record.timestamp,
            "user_id": record.user_id,
            "actor": record.actor,
            "role": record.role,
            "agent": record.agent,
            "project": record.project,
            "action": record.action,
            "risk": record.risk,
            "command": record.command,
            "authorization": record.authorization,
            "backup": record.backup,
            "commit": record.commit,
            "result": record.result,
            "duration_ms": record.duration_ms,
            "metadata": dict(record.metadata),
            "operation_id": record.operation_id,
            "plan": record.plan,
            "approval": record.approval,
            "commands": list(record.commands),
            "files": list(record.files),
            "branch": record.branch,
            "validation": record.validation,
            "rollback": record.rollback,
        }
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if _contains_unsafe(serialized):
            raise ValueError("audit sink rejected unsafe metadata")
        line = serialized + "\n"
        line_size = len(line.encode("utf-8"))
        if line_size > self.max_bytes:
            raise ValueError("audit record exceeds size limit")
        with self._lock:
            with _audit_path_lock(self.path, exclusive=True):
                current_size = self.path.stat().st_size if self.path.exists() else 0
                if current_size + line_size > self.max_bytes:
                    _rotate_audit_files(self.path, self.retention_files)
                try:
                    with self.path.open("a", encoding="utf-8") as handle:
                        handle.write(line)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.chmod(self.path, 0o600)
                except OSError as exc:
                    raise ValueError("audit sink cannot be written") from exc

    def read(self) -> tuple[AuditRecord, ...]:
        """Reload retained metadata records in chronological file order."""

        records: list[AuditRecord] = []
        record_ids: set[str] = set()
        try:
            with _audit_path_lock(self.path, exclusive=False):
                for path in _audit_read_paths(self.path, self.retention_files):
                    if not path.exists():
                        continue
                    _ensure_regular_audit_file(path)
                    if path.stat().st_size > self.max_bytes:
                        raise ValueError("audit sink is too large")
                    with path.open("r", encoding="utf-8") as handle:
                        for line in handle:
                            if not line.strip():
                                continue
                            record = _decode_audit_record(json.loads(line))
                            if record.record_id in record_ids:
                                raise ValueError("audit sink contains duplicate record ids")
                            record_ids.add(record.record_id)
                            records.append(record)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("audit sink cannot be loaded") from exc
        return tuple(records)


class MetadataAuditLog:
    def __init__(self, *, sink: AuditSink | None = None) -> None:
        self.sink = sink
        self._records: list[AuditRecord] = list(sink.read()) if isinstance(sink, JsonlAuditSink) else []

    @property
    def records(self) -> tuple[AuditRecord, ...]:
        return tuple(self._records)

    def append(
        self,
        *,
        user_id: str,
        actor: str,
        role: str,
        action: str,
        result: str,
        risk: str = "LOW",
        agent: str = "control_center",
        project: str | None = None,
        command: str | None = None,
        authorization: str = "none",
        backup: str | None = None,
        commit: str | None = None,
        duration_ms: int | None = None,
        metadata: Mapping[str, Any] | None = None,
        operation_id: str | None = None,
        plan: str | None = None,
        approval: str | None = None,
        commands: tuple[str, ...] = (),
        files: tuple[str, ...] = (),
        branch: str | None = None,
        validation: str | None = None,
        rollback: str | None = None,
    ) -> AuditRecord:
        raw_values = [
            user_id, actor, role, agent, project, action, risk, command, authorization, backup, commit, result,
            operation_id, plan, approval, branch, validation, rollback,
            *commands, *files,
        ]
        raw_values.extend(str(value) for value in (metadata or {}).values())
        if any(_contains_secret(str(value)) or RAW_STREAM_PATTERN.search(str(value)) for value in raw_values if value is not None):
            raise ValueError("audit data contains secret-like or raw stream content")
        safe_metadata = sanitize(dict(metadata or {}))
        record = AuditRecord(
            record_id=str(uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=str(user_id),
            actor=str(actor),
            role=str(role),
            agent=str(agent),
            project=project,
            action=str(action),
            risk=str(risk),
            command=command,
            authorization=str(authorization),
            backup=backup,
            commit=commit,
            result=str(result),
            duration_ms=duration_ms,
            metadata=safe_metadata,
            operation_id=operation_id,
            plan=plan,
            approval=approval,
            commands=tuple(commands),
            files=tuple(files),
            branch=branch,
            validation=validation,
            rollback=rollback,
        )
        serialized = json.dumps(record.metadata, ensure_ascii=False)
        if _contains_secret(serialized) or RAW_STREAM_PATTERN.search(serialized):
            raise ValueError("audit metadata is unsafe")
        if self.sink is not None:
            self.sink.write(record)
        self._records.append(record)
        return record

    def query(self, *, user_id: str | None = None, action: str | None = None) -> tuple[AuditRecord, ...]:
        return tuple(
            record
            for record in self._records
            if (user_id is None or record.user_id == user_id)
            and (action is None or record.action == action)
        )


def _contains_secret(value: str) -> bool:
    return any(pattern.search(value) for pattern in SECRET_PATTERNS)


def _contains_unsafe(value: str) -> bool:
    return _contains_secret(value) or RAW_STREAM_PATTERN.search(value) is not None


def _decode_audit_record(value: object) -> AuditRecord:
    if not isinstance(value, dict):
        raise ValueError("audit record must be an object")
    metadata = value.get("metadata", {})
    optional_fields = (
        "project", "command", "backup", "commit", "operation_id", "plan", "approval",
        "branch", "validation", "rollback",
    )
    required_fields = (
        "record_id",
        "timestamp",
        "user_id",
        "actor",
        "role",
        "agent",
        "action",
        "risk",
        "authorization",
        "result",
    )
    if any(not isinstance(value.get(key), str) or not value[key].strip() for key in required_fields):
        raise ValueError("audit record text fields are invalid")
    if any(item is not None and (not isinstance(item, str) or not item.strip()) for item in (value.get(key) for key in optional_fields)):
        raise ValueError("audit record optional fields are invalid")
    duration_ms = value.get("duration_ms")
    if duration_ms is not None and (
        isinstance(duration_ms, bool)
        or not isinstance(duration_ms, int)
        or duration_ms < 0
        or duration_ms > 86_400_000
    ):
        raise ValueError("audit record duration is invalid")
    if not isinstance(metadata, dict):
        raise ValueError("audit record metadata is invalid")
    commands = value.get("commands", [])
    files = value.get("files", [])
    if (
        not isinstance(commands, list)
        or not isinstance(files, list)
        or any(not isinstance(item, str) or not item.strip() for item in (*commands, *files))
    ):
        raise ValueError("audit record command and file metadata is invalid")
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if _contains_unsafe(serialized):
        raise ValueError("audit record contains unsafe metadata")
    return AuditRecord(
        record_id=value["record_id"],
        timestamp=value["timestamp"],
        user_id=value["user_id"],
        actor=value["actor"],
        role=value["role"],
        agent=value["agent"],
        project=value.get("project"),
        action=value["action"],
        risk=value["risk"],
        command=value.get("command"),
        authorization=value["authorization"],
        backup=value.get("backup"),
        commit=value.get("commit"),
        result=value["result"],
        duration_ms=duration_ms,
        metadata=metadata,
        operation_id=value.get("operation_id"),
        plan=value.get("plan"),
        approval=value.get("approval"),
        commands=tuple(commands),
        files=tuple(files),
        branch=value.get("branch"),
        validation=value.get("validation"),
        rollback=value.get("rollback"),
    )


def _validate_audit_path(path: Path) -> Path:
    if not path.is_absolute() or path.suffix != ".jsonl" or path.name in {".env", "INVENTORY.json", "AGENTS.md"}:
        raise ValueError("unsafe audit path")
    if ".git" in path.parts or any(part.startswith(".env") for part in path.parts):
        raise ValueError("unsafe audit path")
    if path.is_symlink() or not path.parent.exists() or not path.parent.is_dir():
        raise ValueError("audit path parent directory must exist")
    return path


def _audit_rotation_path(path: Path, index: int) -> Path:
    return path.with_name(f"{path.name}.{index}")


def _audit_read_paths(path: Path, retention_files: int) -> tuple[Path, ...]:
    rotated = tuple(_audit_rotation_path(path, index) for index in range(retention_files, 0, -1))
    return rotated + (path,)


def _ensure_regular_audit_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("audit rotation path must be a regular file")


def _rotate_audit_files(path: Path, retention_files: int) -> None:
    """Move the current file into a bounded numbered history under the same lock."""

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


@contextmanager
def _audit_path_lock(path: Path, *, exclusive: bool) -> Iterator[None]:
    """Coordinate JSONL access across application processes."""

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
        raise ValueError("audit sink lock cannot be acquired") from exc
