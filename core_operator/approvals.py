"""In-memory approval workflow for guarded Core Operator actions."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol
from uuid import uuid4

from .audit import AuditStore
from .policy import Decision, PolicyDecision, RiskLevel
from .safe_logging import redact_text


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass(frozen=True)
class ApprovalRequest:
    id: str
    timestamp: str
    actor: str
    action: str
    risk_level: RiskLevel
    command_id: str | None
    reason: str
    status: ApprovalStatus
    decided_by: str | None
    decided_at: str | None


@dataclass(frozen=True)
class ApprovalDecision:
    id: str
    timestamp: str
    actor: str
    action: str
    risk_level: RiskLevel
    command_id: str | None
    reason: str
    status: ApprovalStatus
    decided_by: str
    decided_at: str


class ApprovalStore(Protocol):
    @property
    def requests(self) -> tuple[ApprovalRequest, ...]:
        ...

    @property
    def pending_requests(self) -> tuple[ApprovalRequest, ...]:
        ...

    def get(self, request_id: str) -> ApprovalRequest:
        ...

    def create_pending(
        self,
        *,
        actor: str,
        action: str,
        risk_level: RiskLevel,
        reason: str,
        command_id: str | None = None,
    ) -> ApprovalRequest:
        ...

    def create_denied(
        self,
        *,
        actor: str,
        action: str,
        risk_level: RiskLevel,
        reason: str,
        command_id: str | None = None,
    ) -> ApprovalRequest:
        ...

    def approve(self, request_id: str, *, decided_by: str, reason: str = "approved") -> ApprovalDecision:
        ...

    def deny(self, request_id: str, *, decided_by: str, reason: str = "denied") -> ApprovalDecision:
        ...

    def apply_policy_decision(
        self,
        *,
        actor: str,
        action: str,
        policy_decision: PolicyDecision,
        command_id: str | None = None,
    ) -> ApprovalRequest | None:
        ...


class ApprovalStateError(ValueError):
    pass


class InMemoryApprovalStore:
    def __init__(self, *, audit: AuditStore | None = None) -> None:
        self.audit = audit
        self._requests: dict[str, ApprovalRequest] = {}

    @property
    def requests(self) -> tuple[ApprovalRequest, ...]:
        return tuple(self._requests.values())

    @property
    def pending_requests(self) -> tuple[ApprovalRequest, ...]:
        return tuple(request for request in self._requests.values() if request.status is ApprovalStatus.PENDING)

    def get(self, request_id: str) -> ApprovalRequest:
        return self._get_request(request_id)

    def create_pending(
        self,
        *,
        actor: str,
        action: str,
        risk_level: RiskLevel,
        reason: str,
        command_id: str | None = None,
    ) -> ApprovalRequest:
        request = self._build_request(
            actor=actor,
            action=action,
            risk_level=risk_level,
            command_id=command_id,
            reason=reason,
            status=ApprovalStatus.PENDING,
            decided_by=None,
            decided_at=None,
        )
        self._requests[request.id] = request
        self._audit(actor, "approval_requested", risk_level, command_id, request.status.value)
        return request

    def create_denied(
        self,
        *,
        actor: str,
        action: str,
        risk_level: RiskLevel,
        reason: str,
        command_id: str | None = None,
    ) -> ApprovalRequest:
        request = self._build_request(
            actor=actor,
            action=action,
            risk_level=risk_level,
            command_id=command_id,
            reason=reason,
            status=ApprovalStatus.DENIED,
            decided_by="policy",
            decided_at=_utc_now(),
        )
        self._requests[request.id] = request
        self._audit(actor, "approval_denied", risk_level, command_id, request.status.value)
        return request

    def approve(self, request_id: str, *, decided_by: str, reason: str = "approved") -> ApprovalDecision:
        return self._decide(request_id, status=ApprovalStatus.APPROVED, decided_by=decided_by, reason=reason)

    def deny(self, request_id: str, *, decided_by: str, reason: str = "denied") -> ApprovalDecision:
        return self._decide(request_id, status=ApprovalStatus.DENIED, decided_by=decided_by, reason=reason)

    def apply_policy_decision(
        self,
        *,
        actor: str,
        action: str,
        policy_decision: PolicyDecision,
        command_id: str | None = None,
    ) -> ApprovalRequest | None:
        if policy_decision.decision is Decision.APPROVAL_REQUIRED:
            return self.create_pending(
                actor=actor,
                action=action,
                risk_level=policy_decision.risk_level,
                reason=policy_decision.reason,
                command_id=command_id,
            )
        if policy_decision.decision is Decision.DENY:
            return self.create_denied(
                actor=actor,
                action=action,
                risk_level=policy_decision.risk_level,
                reason=policy_decision.reason,
                command_id=command_id,
            )
        return None

    def _decide(
        self,
        request_id: str,
        *,
        status: ApprovalStatus,
        decided_by: str,
        reason: str,
    ) -> ApprovalDecision:
        request = self._get_request(request_id)
        if request.status is not ApprovalStatus.PENDING:
            raise ApprovalStateError("approval request is already decided")

        updated = replace(
            request,
            status=status,
            decided_by=redact_text(decided_by),
            decided_at=_utc_now(),
            reason=redact_text(reason),
        )
        self._requests[request_id] = updated
        self._audit(updated.actor, f"approval_{status.value}", updated.risk_level, None, updated.status.value)
        return ApprovalDecision(
            id=updated.id,
            timestamp=updated.timestamp,
            actor=updated.actor,
            action=updated.action,
            risk_level=updated.risk_level,
            command_id=updated.command_id,
            reason=updated.reason,
            status=updated.status,
            decided_by=updated.decided_by or "",
            decided_at=updated.decided_at or "",
        )

    def _get_request(self, request_id: str) -> ApprovalRequest:
        try:
            return self._requests[request_id]
        except KeyError as exc:
            raise ApprovalStateError("approval request does not exist") from exc

    def _build_request(
        self,
        *,
        actor: str,
        action: str,
        risk_level: RiskLevel,
        command_id: str | None,
        reason: str,
        status: ApprovalStatus,
        decided_by: str | None,
        decided_at: str | None,
    ) -> ApprovalRequest:
        return ApprovalRequest(
            id=str(uuid4()),
            timestamp=_utc_now(),
            actor=redact_text(actor),
            action=redact_text(action),
            risk_level=risk_level,
            command_id=redact_text(command_id) if command_id else None,
            reason=redact_text(reason),
            status=status,
            decided_by=redact_text(decided_by) if decided_by else None,
            decided_at=decided_at,
        )

    def _audit(
        self,
        actor: str,
        action: str,
        risk_level: RiskLevel,
        command_id: str | None,
        result: str,
    ) -> None:
        if self.audit is None:
            return
        self.audit.append(
            actor=actor,
            action=action,
            risk_level=risk_level,
            command_id=command_id,
            result=result,
            authorization_required=True,
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
