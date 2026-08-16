"""Dry-run consumption for approved execution plans."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .approved_execution import ApprovedExecutionPlan, ExecutionPlanState
from .audit import AuditStore, contains_secret
from .policy import Decision, PolicyEngine, PolicyRequest, RiskLevel
from .safe_logging import redact_text


class DryRunExecutionState(str, Enum):
    BLOCKED = "blocked"
    COMPLETED = "completed"


@dataclass(frozen=True)
class DryRunExecutionResult:
    state: DryRunExecutionState
    actor: str
    action: str
    command_id: str
    risk_level: RiskLevel
    approval_id: str | None
    reason: str


class ApprovedPlanDryRunner:
    def __init__(self, *, policy: PolicyEngine, audit: AuditStore, max_risk_level: RiskLevel = RiskLevel.LOW) -> None:
        self.policy = policy
        self.audit = audit
        self.max_risk_level = max_risk_level

    def dry_run(self, plan: ApprovedExecutionPlan) -> DryRunExecutionResult:
        safe_actor = redact_text(plan.actor)
        safe_action = redact_text(plan.action)
        safe_command_id = redact_text(plan.command_id)
        safe_approval_id = redact_text(plan.approval_id) if plan.approval_id else None

        unsafe_reason = self._unsafe_metadata_reason(plan)
        if unsafe_reason:
            return self._blocked(
                actor=safe_actor,
                action=safe_action,
                command_id=safe_command_id,
                risk_level=plan.risk_level,
                approval_id=safe_approval_id,
                reason=unsafe_reason,
            )

        if plan.state is not ExecutionPlanState.READY_TO_EXECUTE:
            return self._blocked(
                actor=safe_actor,
                action=safe_action,
                command_id=safe_command_id,
                risk_level=plan.risk_level,
                approval_id=safe_approval_id,
                reason=f"plan is {plan.state.value}",
            )

        policy_decision = self._policy_decision(safe_actor, safe_action, safe_command_id)
        if policy_decision.decision is Decision.DENY:
            return self._blocked(
                actor=safe_actor,
                action=safe_action,
                command_id=safe_command_id,
                risk_level=policy_decision.risk_level,
                approval_id=safe_approval_id,
                reason=policy_decision.reason,
            )
        if policy_decision.decision is not Decision.ALLOW:
            return self._blocked(
                actor=safe_actor,
                action=safe_action,
                command_id=safe_command_id,
                risk_level=policy_decision.risk_level,
                approval_id=safe_approval_id,
                reason=policy_decision.reason,
            )
        if plan.risk_level is not policy_decision.risk_level:
            return self._blocked(
                actor=safe_actor,
                action=safe_action,
                command_id=safe_command_id,
                risk_level=policy_decision.risk_level,
                approval_id=safe_approval_id,
                reason="plan risk metadata mismatch",
            )
        if not _risk_allowed(plan.risk_level, self.max_risk_level):
            return self._blocked(
                actor=safe_actor,
                action=safe_action,
                command_id=safe_command_id,
                risk_level=plan.risk_level,
                approval_id=safe_approval_id,
                reason="risk exceeds dry-run limit",
            )

        self._audit(
            actor=safe_actor,
            action="dry_run_started",
            risk_level=plan.risk_level,
            command_id=safe_command_id,
            result="started",
            authorization_required=False,
        )
        self._audit(
            actor=safe_actor,
            action="dry_run_completed",
            risk_level=plan.risk_level,
            command_id=safe_command_id,
            result="completed",
            authorization_required=False,
        )
        return DryRunExecutionResult(
            state=DryRunExecutionState.COMPLETED,
            actor=safe_actor,
            action=safe_action,
            command_id=safe_command_id,
            risk_level=plan.risk_level,
            approval_id=safe_approval_id,
            reason="dry run completed",
        )

    def _policy_decision(self, actor: str, action: str, command_id: str):
        try:
            return self.policy.evaluate(PolicyRequest(actor=actor, action=action, command_id=command_id))
        except KeyError:
            return self.policy.evaluate(PolicyRequest(actor=actor, action=action, command_id=None))

    @staticmethod
    def _unsafe_metadata_reason(plan: ApprovedExecutionPlan) -> str | None:
        values = (
            plan.actor,
            plan.action,
            plan.command_id,
            plan.approval_id,
            plan.reason,
        )
        if any(value is not None and contains_secret(value) for value in values):
            return "plan metadata contains secret-like content"
        return None

    def _blocked(
        self,
        *,
        actor: str,
        action: str,
        command_id: str,
        risk_level: RiskLevel,
        approval_id: str | None,
        reason: str,
    ) -> DryRunExecutionResult:
        self._audit(
            actor=actor,
            action="dry_run_blocked",
            risk_level=risk_level,
            command_id=command_id,
            result=reason,
            authorization_required=True,
        )
        return DryRunExecutionResult(
            state=DryRunExecutionState.BLOCKED,
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
