"""Execution gate for dry-run approved plans."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .approved_execution import ApprovedExecutionPlan, ExecutionPlanState
from .approved_plan_dry_runner import DryRunExecutionResult, DryRunExecutionState
from .audit import AuditStore, contains_secret
from .policy import Decision, PolicyEngine, PolicyRequest, RiskLevel
from .safe_logging import redact_text


class ExecutionGateState(str, Enum):
    ELIGIBLE_FOR_CONTROLLED_EXECUTION = "eligible_for_controlled_execution"
    BLOCKED = "blocked"
    REJECTED = "rejected"


@dataclass(frozen=True)
class ExecutionGateDecision:
    state: ExecutionGateState
    actor: str
    action: str
    command_id: str
    risk_level: RiskLevel
    approval_id: str | None
    reason: str


class ExecutionGate:
    def __init__(self, *, policy: PolicyEngine, audit: AuditStore, max_risk_level: RiskLevel = RiskLevel.LOW) -> None:
        self.policy = policy
        self.audit = audit
        self.max_risk_level = max_risk_level

    def evaluate(self, *, plan: ApprovedExecutionPlan, dry_run: DryRunExecutionResult) -> ExecutionGateDecision:
        safe_actor = redact_text(plan.actor)
        safe_action = redact_text(plan.action)
        safe_command_id = redact_text(plan.command_id)
        safe_approval_id = redact_text(plan.approval_id) if plan.approval_id else None
        self._audit(
            actor=safe_actor,
            action="execution_gate_evaluated",
            risk_level=plan.risk_level,
            command_id=safe_command_id,
            result="evaluated",
            authorization_required=True,
        )

        unsafe_reason = self._unsafe_metadata_reason(plan, dry_run)
        if unsafe_reason:
            return self._blocked(safe_actor, safe_action, safe_command_id, plan.risk_level, safe_approval_id, unsafe_reason)

        if dry_run.state is not DryRunExecutionState.COMPLETED:
            return self._blocked(
                safe_actor,
                safe_action,
                safe_command_id,
                plan.risk_level,
                safe_approval_id,
                f"dry run is {dry_run.state.value}",
            )
        if plan.state is not ExecutionPlanState.READY_TO_EXECUTE:
            return self._blocked(
                safe_actor,
                safe_action,
                safe_command_id,
                plan.risk_level,
                safe_approval_id,
                f"plan is {plan.state.value}",
            )
        if not plan.approval_id:
            return self._blocked(safe_actor, safe_action, safe_command_id, plan.risk_level, safe_approval_id, "approval is required")

        mismatch_reason = self._mismatch_reason(plan, dry_run)
        if mismatch_reason:
            return self._blocked(safe_actor, safe_action, safe_command_id, plan.risk_level, safe_approval_id, mismatch_reason)

        policy_decision = self._policy_decision(safe_actor, safe_action, safe_command_id)
        if policy_decision.decision is Decision.DENY:
            return self._rejected(
                safe_actor,
                safe_action,
                safe_command_id,
                policy_decision.risk_level,
                safe_approval_id,
                policy_decision.reason,
            )
        if policy_decision.decision is not Decision.ALLOW:
            return self._blocked(
                safe_actor,
                safe_action,
                safe_command_id,
                policy_decision.risk_level,
                safe_approval_id,
                policy_decision.reason,
            )
        if plan.risk_level is not policy_decision.risk_level or dry_run.risk_level is not policy_decision.risk_level:
            return self._blocked(
                safe_actor,
                safe_action,
                safe_command_id,
                policy_decision.risk_level,
                safe_approval_id,
                "risk metadata mismatch",
            )
        if not _risk_allowed(plan.risk_level, self.max_risk_level):
            return self._blocked(
                safe_actor,
                safe_action,
                safe_command_id,
                plan.risk_level,
                safe_approval_id,
                "risk exceeds execution gate limit",
            )

        return self._eligible(safe_actor, safe_action, safe_command_id, plan.risk_level, safe_approval_id)

    def _policy_decision(self, actor: str, action: str, command_id: str):
        try:
            return self.policy.evaluate(PolicyRequest(actor=actor, action=action, command_id=command_id))
        except KeyError:
            return self.policy.evaluate(PolicyRequest(actor=actor, action=action, command_id=None))

    @staticmethod
    def _unsafe_metadata_reason(plan: ApprovedExecutionPlan, dry_run: DryRunExecutionResult) -> str | None:
        values = (
            plan.actor,
            plan.action,
            plan.command_id,
            plan.approval_id,
            plan.reason,
            dry_run.actor,
            dry_run.action,
            dry_run.command_id,
            dry_run.approval_id,
            dry_run.reason,
        )
        if any(value is not None and contains_secret(value) for value in values):
            return "metadata contains secret-like content"
        return None

    @staticmethod
    def _mismatch_reason(plan: ApprovedExecutionPlan, dry_run: DryRunExecutionResult) -> str | None:
        if plan.actor != dry_run.actor:
            return "actor mismatch"
        if plan.action != dry_run.action:
            return "action mismatch"
        if plan.command_id != dry_run.command_id:
            return "command mismatch"
        if plan.approval_id != dry_run.approval_id:
            return "approval mismatch"
        if plan.risk_level is not dry_run.risk_level:
            return "risk mismatch"
        return None

    def _eligible(
        self,
        actor: str,
        action: str,
        command_id: str,
        risk_level: RiskLevel,
        approval_id: str | None,
    ) -> ExecutionGateDecision:
        self._audit(
            actor=actor,
            action="execution_gate_eligible",
            risk_level=risk_level,
            command_id=command_id,
            result=ExecutionGateState.ELIGIBLE_FOR_CONTROLLED_EXECUTION.value,
            authorization_required=True,
        )
        return ExecutionGateDecision(
            state=ExecutionGateState.ELIGIBLE_FOR_CONTROLLED_EXECUTION,
            actor=actor,
            action=action,
            command_id=command_id,
            risk_level=risk_level,
            approval_id=approval_id,
            reason="eligible for controlled execution",
        )

    def _blocked(
        self,
        actor: str,
        action: str,
        command_id: str,
        risk_level: RiskLevel,
        approval_id: str | None,
        reason: str,
    ) -> ExecutionGateDecision:
        return self._final(ExecutionGateState.BLOCKED, "execution_gate_blocked", actor, action, command_id, risk_level, approval_id, reason)

    def _rejected(
        self,
        actor: str,
        action: str,
        command_id: str,
        risk_level: RiskLevel,
        approval_id: str | None,
        reason: str,
    ) -> ExecutionGateDecision:
        return self._final(ExecutionGateState.REJECTED, "execution_gate_rejected", actor, action, command_id, risk_level, approval_id, reason)

    def _final(
        self,
        state: ExecutionGateState,
        audit_action: str,
        actor: str,
        action: str,
        command_id: str,
        risk_level: RiskLevel,
        approval_id: str | None,
        reason: str,
    ) -> ExecutionGateDecision:
        self._audit(
            actor=actor,
            action=audit_action,
            risk_level=risk_level,
            command_id=command_id,
            result=reason,
            authorization_required=True,
        )
        return ExecutionGateDecision(
            state=state,
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
