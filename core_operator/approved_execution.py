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
    actor_role: str = "UNKNOWN"
    approved_by: str | None = None
    approved_by_role: str | None = None
    policy_version: str = "legacy"
    effective_permissions: tuple[str, ...] = ()
    resource: str = "unknown"
    plan_id: str | None = None
    approval_expires_at: str | None = None
    operation_id: str | None = None
    branch: str | None = None
    commit: str | None = None
    backup_id: str | None = None
    commands: tuple[str, ...] = ()
    files: tuple[str, ...] = ()
    services_affected: tuple[str, ...] = ()
    impact: tuple[str, ...] = ()
    operation_hash: str | None = None
    plan_hash: str | None = None
    approval_hash: str | None = None
    execution_hash: str | None = None


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
        policy_version: str | None = None,
        effective_permissions: tuple[str, ...] | None = None,
        resource: str | None = None,
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
                approval=approval,
            )

        if approval is None:
            return self._blocked(safe_actor, safe_action, safe_command_id, policy_decision.risk_level, approval_id, "approval not found")

        mismatch_reason = self._approval_mismatch_reason(
            approval,
            actor=safe_actor,
            action=safe_action,
            command_id=safe_command_id,
            policy_version=policy_version,
            effective_permissions=effective_permissions,
            resource=resource,
            operation_id=approval.operation_id,
            branch=approval.branch,
            commit=approval.commit,
            backup_id=approval.backup_id,
            commands=approval.commands,
            files=approval.files,
            services_affected=approval.services_affected,
            impact=approval.impact,
            operation_hash=approval.operation_hash,
            plan_hash=approval.plan_hash,
        )
        if mismatch_reason:
            return self._blocked(
                safe_actor,
                safe_action,
                safe_command_id,
                policy_decision.risk_level,
                approval_id,
                mismatch_reason,
                approval=approval,
            )

        if approval.status is not ApprovalStatus.APPROVED:
            return self._blocked(
                safe_actor,
                safe_action,
                safe_command_id,
                policy_decision.risk_level,
                approval_id,
                f"approval is {approval.status.value}",
                approval=approval,
            )

        if policy_decision.decision is not Decision.ALLOW:
            return self._blocked(
                safe_actor,
                safe_action,
                safe_command_id,
                policy_decision.risk_level,
                approval_id,
                policy_decision.reason,
                approval=approval,
            )

        if not _risk_allowed(policy_decision.risk_level, max_risk_level):
            return self._blocked(
                safe_actor,
                safe_action,
                safe_command_id,
                policy_decision.risk_level,
                approval_id,
                "risk exceeds limit",
                approval=approval,
            )

        return self._record(
            actor=safe_actor,
            action=safe_action,
            command_id=safe_command_id,
            risk_level=policy_decision.risk_level,
            approval_id=approval_id,
            state=ExecutionPlanState.READY_TO_EXECUTE,
            reason="approved execution plan is ready",
            approval=approval,
        )

    def _get_approval(self, approval_id: str) -> ApprovalRequest | None:
        try:
            return self.approvals.get(approval_id)
        except ValueError:
            return None

    @staticmethod
    def _approval_mismatch_reason(
        approval: ApprovalRequest,
        *,
        actor: str,
        action: str,
        command_id: str,
        policy_version: str | None,
        effective_permissions: tuple[str, ...] | None,
        resource: str | None,
        operation_id: str | None,
        branch: str | None,
        commit: str | None,
        backup_id: str | None,
        commands: tuple[str, ...],
        files: tuple[str, ...],
        services_affected: tuple[str, ...],
        impact: tuple[str, ...],
        operation_hash: str | None,
        plan_hash: str | None,
    ) -> str | None:
        if approval.actor != actor:
            return "approval actor mismatch"
        if approval.action != action:
            return "approval action mismatch"
        if approval.command_id != command_id:
            return "approval command mismatch"
        if approval.policy_version != "legacy":
            if policy_version is None or approval.policy_version != policy_version:
                return "approval policy version mismatch"
            if effective_permissions is None or tuple(sorted(effective_permissions)) != approval.effective_permissions:
                return "approval effective permissions mismatch"
            if resource is None or approval.resource != resource:
                return "approval resource mismatch"
        for field, expected, recorded in (
            ("operation_id", operation_id, approval.operation_id),
            ("branch", branch, approval.branch),
            ("commit", commit, approval.commit),
            ("backup_id", backup_id, approval.backup_id),
            ("operation_hash", operation_hash, approval.operation_hash),
            ("plan_hash", plan_hash, approval.plan_hash),
        ):
            if expected is not None and recorded is not None and expected != recorded:
                return f"approval {field} mismatch"
        for field, expected, recorded in (
            ("commands", commands, approval.commands),
            ("files", files, approval.files),
            ("services_affected", services_affected, approval.services_affected),
            ("impact", impact, approval.impact),
        ):
            if expected and tuple(expected) != tuple(recorded):
                return f"approval {field} mismatch"
        return None

    def _blocked(
        self,
        actor: str,
        action: str,
        command_id: str,
        risk_level: RiskLevel,
        approval_id: str,
        reason: str,
        approval: ApprovalRequest | None = None,
    ) -> ApprovedExecutionPlan:
        return self._record(
            actor=actor,
            action=action,
            command_id=command_id,
            risk_level=risk_level,
            approval_id=approval_id,
            state=ExecutionPlanState.BLOCKED,
            reason=reason,
            approval=approval,
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
        approval: ApprovalRequest | None = None,
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
            actor_role=approval.actor_role if approval is not None else "UNKNOWN",
            approved_by=approval.decided_by if approval is not None else None,
            approved_by_role=approval.decided_by_role if approval is not None else None,
            policy_version=approval.policy_version if approval is not None else "legacy",
            effective_permissions=approval.effective_permissions if approval is not None else (),
            resource=approval.resource if approval is not None else "unknown",
            plan_id=approval.plan_id if approval is not None else None,
            approval_expires_at=approval.expires_at if approval is not None else None,
            operation_id=approval.operation_id if approval is not None else None,
            branch=approval.branch if approval is not None else None,
            commit=approval.commit if approval is not None else None,
            backup_id=approval.backup_id if approval is not None else None,
            commands=approval.commands if approval is not None else (),
            files=approval.files if approval is not None else (),
            services_affected=approval.services_affected if approval is not None else (),
            impact=approval.impact if approval is not None else (),
            operation_hash=approval.operation_hash if approval is not None else None,
            plan_hash=approval.plan_hash if approval is not None else None,
            approval_hash=approval.approval_hash if approval is not None else None,
            execution_hash=approval.execution_hash if approval is not None else None,
        )


def _risk_allowed(actual: RiskLevel, maximum: RiskLevel) -> bool:
    order = {
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }
    return order[actual] <= order[maximum]
