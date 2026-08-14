"""In-memory audit model for the Phase 2 Core Operator base."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .policy import RiskLevel
from .safe_logging import redact_text


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    actor: str
    action: str
    risk_level: RiskLevel
    command_id: str | None
    result: str
    authorization_required: bool


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
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            actor=redact_text(actor),
            action=redact_text(action),
            risk_level=risk_level,
            command_id=redact_text(command_id) if command_id else None,
            result=redact_text(result),
            authorization_required=authorization_required,
        )
        self._events.append(event)
        return event
