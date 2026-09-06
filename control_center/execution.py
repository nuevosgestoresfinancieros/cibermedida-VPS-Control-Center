"""Provider boundary for explicitly controlled execution.

The default service has no provider and is disabled. A provider must be
injected explicitly and return metadata-only evidence. The included
``ReadSafeExecutionProvider`` is the only current execution adapter and is
limited to the allowlisted READ_SAFE commands; this module never constructs
or invokes an operating-system command itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import re
from typing import Protocol
from uuid import uuid4

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret
from core_operator.execution_gate import ExecutionGateDecision, ExecutionGateState
from core_operator.policy import RiskLevel
from phase1_inventory.commands import CommandClass, get_command
from core_operator.safe_logging import redact_text

from .audit import MetadataAuditLog
from .auth import AuthService, Permission, User
from .state import JsonMetadataStore


class ControlledExecutionState(str, Enum):
    BLOCKED_BY_DEFAULT = "blocked_by_default"
    REJECTED = "rejected"
    PROVIDER_COMPLETED = "provider_completed"
    PROVIDER_FAILED = "provider_failed"


@dataclass(frozen=True)
class ProviderEvidence:
    provider: str
    result: str
    duration_ms: int | None = None


class ExecutionProvider(Protocol):
    name: str

    def run(self, *, actor: str, action: str, command_id: str) -> ProviderEvidence:
        """Return metadata-only evidence for an already authorized request."""


@dataclass(frozen=True)
class ControlledExecutionRecord:
    execution_id: str
    actor: str
    action: str
    command_id: str
    risk_level: RiskLevel
    approval_id: str | None
    state: ControlledExecutionState
    reason: str
    provider: str | None
    created_at: str


class ControlledExecutionService:
    def __init__(
        self,
        *,
        auth: AuthService,
        audit: MetadataAuditLog,
        provider: ExecutionProvider | None = None,
        enabled: bool = False,
        state_store: JsonMetadataStore | None = None,
    ) -> None:
        self.auth = auth
        self.audit = audit
        self.provider = provider
        self.enabled = enabled
        self.state_store = state_store
        self._records: list[ControlledExecutionRecord] = []
        if self.state_store is not None:
            for raw_record in self.state_store.load():
                record = _decode_record(raw_record)
                if any(existing.execution_id == record.execution_id for existing in self._records):
                    raise ValueError("execution state contains duplicate ids")
                self._records.append(record)

    @property
    def records(self) -> tuple[ControlledExecutionRecord, ...]:
        return tuple(self._records)

    def request(self, *, session_id: str, decision: ExecutionGateDecision) -> ControlledExecutionRecord:
        user = self.auth.require(session_id, required_execution_permission(decision.action, decision.command_id))
        fields = (decision.actor, decision.action, decision.command_id, decision.approval_id, decision.reason)
        if any(_unsafe_metadata(value) for value in fields):
            return self._record(
                user=user,
                decision=decision,
                state=ControlledExecutionState.REJECTED,
                reason="metadata contains secret-like content",
                provider=None,
            )
        if decision.state is not ExecutionGateState.ELIGIBLE_FOR_CONTROLLED_EXECUTION:
            return self._record(
                user=user,
                decision=decision,
                state=ControlledExecutionState.REJECTED,
                reason=f"execution gate is {decision.state.value}",
                provider=None,
            )
        if not decision.approval_id:
            return self._record(
                user=user,
                decision=decision,
                state=ControlledExecutionState.REJECTED,
                reason="approval is required before controlled execution",
                provider=None,
            )
        if decision.action != "read" or decision.risk_level is not RiskLevel.LOW:
            return self._record(
                user=user,
                decision=decision,
                state=ControlledExecutionState.REJECTED,
                reason="controlled provider is limited to LOW-risk READ_SAFE actions",
                provider=None,
            )
        try:
            command_spec = get_command(decision.command_id)
        except KeyError:
            command_spec = None
        if command_spec is None or command_spec.command_class is not CommandClass.READ_SAFE or command_spec.requires_sudo:
            return self._record(
                user=user,
                decision=decision,
                state=ControlledExecutionState.REJECTED,
                reason="command is outside the READ_SAFE controlled provider scope",
                provider=None,
            )
        if not self.enabled or self.provider is None:
            return self._record(
                user=user,
                decision=decision,
                state=ControlledExecutionState.BLOCKED_BY_DEFAULT,
                reason="controlled execution provider is disabled",
                provider=None,
            )

        try:
            evidence = self.provider.run(
                actor=decision.actor,
                action=decision.action,
                command_id=decision.command_id,
            )
        except Exception:
            return self._record(
                user=user,
                decision=decision,
                state=ControlledExecutionState.PROVIDER_FAILED,
                reason="controlled provider failed without raw output",
                provider=getattr(self.provider, "name", "injected"),
            )
        if not _valid_provider_evidence(evidence):
            return self._record(
                user=user,
                decision=decision,
                state=ControlledExecutionState.REJECTED,
                reason="provider evidence is unsafe",
                provider=None,
            )
        return self._record(
            user=user,
            decision=decision,
            state=ControlledExecutionState.PROVIDER_COMPLETED,
            reason=redact_text(evidence.result),
            provider=redact_text(evidence.provider),
        )

    def _record(
        self,
        *,
        user: User,
        decision: ExecutionGateDecision,
        state: ControlledExecutionState,
        reason: str,
        provider: str | None,
    ) -> ControlledExecutionRecord:
        record = ControlledExecutionRecord(
            execution_id=f"execution-{uuid4()}",
            actor=redact_text(decision.actor),
            action=redact_text(decision.action),
            command_id=redact_text(decision.command_id),
            risk_level=decision.risk_level,
            approval_id=redact_text(decision.approval_id) if decision.approval_id else None,
            state=state,
            reason=redact_text(reason),
            provider=redact_text(provider) if provider else None,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._records.append(record)
        if self.state_store is not None:
            self.state_store.save(_encode_record(item) for item in self._records)
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            action="controlled_execution_recorded",
            risk=decision.risk_level.value,
            command=record.command_id,
            authorization="execution_gate",
            result=state.value,
            metadata={"execution_id": record.execution_id, "provider": record.provider},
        )
        return record


_CONTROL_CHARACTER_PATTERN = re.compile(r"[\r\n\x00]")


def _unsafe_metadata(value: object) -> bool:
    if value is None:
        return False
    if not isinstance(value, str):
        return True
    return bool(
        contains_secret(value)
        or RAW_STREAM_PATTERN.search(value)
        or _CONTROL_CHARACTER_PATTERN.search(value)
        or len(value) > 256
    )


def _valid_provider_evidence(value: object) -> bool:
    if not isinstance(value, ProviderEvidence):
        return False
    if _unsafe_metadata(value.provider) or _unsafe_metadata(value.result):
        return False
    if not value.provider.strip() or not value.result.strip():
        return False
    if value.duration_ms is not None and (
        isinstance(value.duration_ms, bool)
        or not isinstance(value.duration_ms, int)
        or value.duration_ms < 0
        or value.duration_ms > 86_400_000
    ):
        return False
    return True


def required_execution_permission(action: str, command_id: str) -> Permission:
    """Return the least permission required to submit a gated execution.

    The policy and execution gate remain authoritative. This authorization
    check only prevents a broad deployment permission from being required for
    the bounded READ_SAFE path, while keeping unknown and modifying requests
    on the stronger path that can never bypass those gates.
    """

    if action == "read":
        try:
            command_class = get_command(command_id).command_class
        except KeyError:
            return Permission.DEPLOY
        return {
            CommandClass.READ_SAFE: Permission.RUN_READ_SAFE,
            CommandClass.READ_SENSITIVE: Permission.RUN_READ_SENSITIVE,
            CommandClass.READ_PRIVILEGED: Permission.RUN_PRIVILEGED,
            CommandClass.FORBIDDEN: Permission.RUN_PRIVILEGED,
        }[command_class]
    return Permission.DEPLOY


def _encode_record(record: ControlledExecutionRecord) -> dict[str, object]:
    return {
        "execution_id": record.execution_id,
        "actor": record.actor,
        "action": record.action,
        "command_id": record.command_id,
        "risk_level": record.risk_level.value,
        "approval_id": record.approval_id,
        "state": record.state.value,
        "reason": record.reason,
        "provider": record.provider,
        "created_at": record.created_at,
    }


def _decode_record(value: dict[str, object]) -> ControlledExecutionRecord:
    required = ("execution_id", "actor", "action", "command_id", "reason", "created_at")
    if any(not isinstance(value.get(key), str) or not value[key].strip() for key in required):
        raise ValueError("execution state text fields are invalid")
    optional = value.get("approval_id"), value.get("provider")
    if any(item is not None and (not isinstance(item, str) or not item.strip()) for item in optional):
        raise ValueError("execution state optional fields are invalid")
    text_values = tuple(value[key] for key in required) + tuple(item for item in optional if item is not None)
    if any(_unsafe_metadata(item) for item in text_values):
        raise ValueError("execution state contains unsafe metadata")
    try:
        return ControlledExecutionRecord(
            execution_id=value["execution_id"],
            actor=value["actor"],
            action=value["action"],
            command_id=value["command_id"],
            risk_level=RiskLevel(value["risk_level"]),
            approval_id=value.get("approval_id"),
            state=ControlledExecutionState(value["state"]),
            reason=value["reason"],
            provider=value.get("provider"),
            created_at=value["created_at"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("execution state record is invalid") from exc
