"""Approved execution planning contracts for the Core Operator."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .audit import AuditStore
from .approvals import ApprovalRequest, ApprovalStatus, ApprovalStore
from .policy import Decision, PolicyEngine, PolicyRequest, RiskLevel
from .safe_logging import redact_text


class ExecutionPlanState(str, Enum):
    BLOCKED = "blocked"
    READY_TO_EXECUTE = "ready_to_execute"
    REJECTED = "rejected"


@dataclass(frozen=True)
class ApprovedExecutionPlan:
    state: ExecutionPlanState
    actor: str
    action: str
    command_id: str
    risk_level: RiskLevel
    approval_id: str | None
    reason: str


class ApprovedExecutionPlanner:
    def __init__(self, *, policy: PolicyEngine, approvals: ApprovalStore, audit: AuditStore) -> None:
        self.policy = policy
        self.approvals = approvals
        self.audit = audit

    def build_plan(
        self,
        *,
        actor: str,
        action: str,
        command_id: str,
        approval_id: str,
        max_risk_level: RiskLevel = RiskLevel.HIGH,
    ) -> ApprovedExecutionPlan:
        safe_actor = redact_text(actor)
        safe_action = redact_text(action)
        safe_command_id = redact_text(command_id)
        policy_decision = self.policy.evaluate(
            PolicyRequest(actor=safe_actor, action=safe_action, command_id=safe_command_id)
        )
        approval = self._get_approval(approval_id)

        if policy_decision.decision is Decision.DENY:
            return self._record(
                actor=safe_actor,
                action=safe_action,
                command_id=safe_command_id,
                risk_level=policy_decision.risk_level,
                approval_id=approval_id,
                state=ExecutionPlanState.REJECTED,
                reason=policy_decision.reason,
            )

        if approval is None:
            return self._blocked(safe_actor, safe_action, safe_command_id, policy_decision.risk_level, approval_id, "approval not found")

        mismatch_reason = self._approval_mismatch_reason(approval, actor=safe_actor, action=safe_action, command_id=safe_command_id)
        if mismatch_reason:
            return self._blocked(safe_actor, safe_action, safe_command_id, policy_decision.risk_level, approval_id, mismatch_reason)

        if approval.status is not ApprovalStatus.APPROVED:
            return self._blocked(
                safe_actor,
                safe_action,
                safe_command_id,
                policy_decision.risk_level,
                approval_id,
                f"approval is {approval.status.value}",
            )

        if policy_decision.decision is not Decision.ALLOW:
            return self._blocked(safe_actor, safe_action, safe_command_id, policy_decision.risk_level, approval_id, policy_decision.reason)

        if not _risk_allowed(policy_decision.risk_level, max_risk_level):
            return self._blocked(safe_actor, safe_action, safe_command_id, policy_decision.risk_level, approval_id, "risk exceeds limit")

        return self._record(
            actor=safe_actor,
            action=safe_action,
            command_id=safe_command_id,
            risk_level=policy_decision.risk_level,
            approval_id=approval_id,
            state=ExecutionPlanState.READY_TO_EXECUTE,
            reason="approved execution plan is ready",
        )

    def _get_approval(self, approval_id: str) -> ApprovalRequest | None:
        try:
            return self.approvals.get(approval_id)
        except ValueError:
            return None

    @staticmethod
    def _approval_mismatch_reason(approval: ApprovalRequest, *, actor: str, action: str, command_id: str) -> str | None:
        if approval.actor != actor:
            return "approval actor mismatch"
        if approval.action != action:
            return "approval action mismatch"
        if approval.command_id != command_id:
            return "approval command mismatch"
        return None

    def _blocked(
        self,
        actor: str,
        action: str,
        command_id: str,
        risk_level: RiskLevel,
        approval_id: str,
        reason: str,
    ) -> ApprovedExecutionPlan:
        return self._record(
            actor=actor,
            action=action,
            command_id=command_id,
            risk_level=risk_level,
            approval_id=approval_id,
            state=ExecutionPlanState.BLOCKED,
            reason=reason,
        )

    def _record(
        self,
        *,
        actor: str,
        action: str,
        command_id: str,
        risk_level: RiskLevel,
        approval_id: str | None,
        state: ExecutionPlanState,
        reason: str,
    ) -> ApprovedExecutionPlan:
        self.audit.append(
            actor=actor,
            action="approved_execution_plan_evaluated",
            risk_level=risk_level,
            command_id=command_id,
            result=state.value,
            authorization_required=True,
        )
        return ApprovedExecutionPlan(
            state=state,
            actor=actor,
            action=action,
            command_id=command_id,
            risk_level=risk_level,
            approval_id=approval_id,
            reason=reason,
        )


def _risk_allowed(actual: RiskLevel, maximum: RiskLevel) -> bool:
    order = {
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }
    return order[actual] <= order[maximum]
