"""Non-operational controlled executor contract."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .audit import AuditStore, contains_secret
from .execution_gate import ExecutionGateDecision, ExecutionGateState
from .policy import Decision, PolicyEngine, PolicyRequest, RiskLevel
from .safe_logging import redact_text


class ControlledExecutionState(str, Enum):
    BLOCKED_BY_DEFAULT = "blocked_by_default"
    REJECTED = "rejected"
    NOT_CONFIGURED = "not_configured"


@dataclass(frozen=True)
class ControlledExecutionResult:
    state: ControlledExecutionState
    actor: str
    action: str
    command_id: str
    risk_level: RiskLevel
    approval_id: str | None
    reason: str


class ControlledExecutor:
    def __init__(self, *, policy: PolicyEngine, audit: AuditStore, max_risk_level: RiskLevel = RiskLevel.LOW) -> None:
        self.policy = policy
        self.audit = audit
        self.max_risk_level = max_risk_level

    def execute(self, decision: ExecutionGateDecision) -> ControlledExecutionResult:
        safe_actor = redact_text(decision.actor)
        safe_action = redact_text(decision.action)
        safe_command_id = redact_text(decision.command_id)
        safe_approval_id = redact_text(decision.approval_id) if decision.approval_id else None
        self._audit(
            actor=safe_actor,
            action="controlled_execution_requested",
            risk_level=decision.risk_level,
            command_id=safe_command_id,
            result="requested",
            authorization_required=True,
        )

        unsafe_reason = self._unsafe_metadata_reason(decision)
        if unsafe_reason:
            return self._rejected(safe_actor, safe_action, safe_command_id, decision.risk_level, safe_approval_id, unsafe_reason)

        if decision.state is not ExecutionGateState.ELIGIBLE_FOR_CONTROLLED_EXECUTION:
            return self._rejected(
                safe_actor,
                safe_action,
                safe_command_id,
                decision.risk_level,
                safe_approval_id,
                f"execution gate decision is {decision.state.value}",
            )

        policy_decision = self._policy_decision(safe_actor, safe_action, safe_command_id)
        if policy_decision.decision is not Decision.ALLOW:
            return self._rejected(
                safe_actor,
                safe_action,
                safe_command_id,
                policy_decision.risk_level,
                safe_approval_id,
                policy_decision.reason,
            )
        if decision.risk_level is not policy_decision.risk_level:
            return self._rejected(
                safe_actor,
                safe_action,
                safe_command_id,
                policy_decision.risk_level,
                safe_approval_id,
                "risk metadata mismatch",
            )
        if not _risk_allowed(decision.risk_level, self.max_risk_level):
            return self._blocked(
                safe_actor,
                safe_action,
                safe_command_id,
                decision.risk_level,
                safe_approval_id,
                "risk exceeds controlled executor limit",
            )
        if not safe_approval_id:
            return self._blocked(safe_actor, safe_action, safe_command_id, decision.risk_level, safe_approval_id, "approval is required")

        return self._blocked(
            safe_actor,
            safe_action,
            safe_command_id,
            decision.risk_level,
            safe_approval_id,
            "controlled executor is blocked by default",
        )

    def _policy_decision(self, actor: str, action: str, command_id: str):
        try:
            return self.policy.evaluate(PolicyRequest(actor=actor, action=action, command_id=command_id))
        except KeyError:
            return self.policy.evaluate(PolicyRequest(actor=actor, action=action, command_id=None))

    @staticmethod
    def _unsafe_metadata_reason(decision: ExecutionGateDecision) -> str | None:
        values = (
            decision.actor,
            decision.action,
            decision.command_id,
            decision.approval_id,
            decision.reason,
        )
        if any(value is not None and contains_secret(value) for value in values):
            return "metadata contains secret-like content"
        return None

    def _blocked(
        self,
        actor: str,
        action: str,
        command_id: str,
        risk_level: RiskLevel,
        approval_id: str | None,
        reason: str,
    ) -> ControlledExecutionResult:
        self._audit(
            actor=actor,
            action="controlled_execution_blocked",
            risk_level=risk_level,
            command_id=command_id,
            result=reason,
            authorization_required=True,
        )
        return ControlledExecutionResult(
            state=ControlledExecutionState.BLOCKED_BY_DEFAULT,
            actor=actor,
            action=action,
            command_id=command_id,
            risk_level=risk_level,
            approval_id=approval_id,
            reason=reason,
        )

    def _rejected(
        self,
        actor: str,
        action: str,
        command_id: str,
        risk_level: RiskLevel,
        approval_id: str | None,
        reason: str,
    ) -> ControlledExecutionResult:
        self._audit(
            actor=actor,
            action="controlled_execution_rejected",
            risk_level=risk_level,
            command_id=command_id,
            result=reason,
            authorization_required=True,
        )
        return ControlledExecutionResult(
            state=ControlledExecutionState.REJECTED,
            actor=actor,
            action=action,
            command_id=command_id,
            risk_level=risk_level,
            approval_id=approval_id,
            reason=reason,
        )

    def _audit(
        self,
        *,
        actor: str,
        action: str,
        risk_level: RiskLevel,
        command_id: str,
        result: str,
        authorization_required: bool,
    ) -> None:
        self.audit.append(
            actor=actor,
            action=action,
            risk_level=risk_level,
            command_id=command_id,
            result=result,
            authorization_required=authorization_required,
        )


def _risk_allowed(actual: RiskLevel, maximum: RiskLevel) -> bool:
    order = {
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }
    return order[actual] <= order[maximum]
