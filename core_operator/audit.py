"""Audit storage primitives for the Phase 2 Core Operator base."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from .config import OperatorConfig
from .policy import RiskLevel
from .safe_logging import SECRET_PATTERNS, redact_text

RAW_STREAM_PATTERN = re.compile(r"(?i)\b(std(?:out|err))\s*[:=]")


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
        self.path = config.resolve_audit_path()
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
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        self._events.append(event)
        return event


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
