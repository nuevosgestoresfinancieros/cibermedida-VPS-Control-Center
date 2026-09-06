"""Application bridge for the Core Operator approved-execution chain."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from core_operator.approvals import ApprovalStore
from core_operator.approved_execution import ApprovedExecutionPlan, ApprovedExecutionPlanner
from core_operator.approved_plan_dry_runner import ApprovedPlanDryRunner, DryRunExecutionResult
from core_operator.audit import AuditEvent, AuditStore
from core_operator.execution_gate import ExecutionGate, ExecutionGateDecision
from core_operator.policy import PolicyEngine, RiskLevel

from .audit import MetadataAuditLog
from .auth import AuthService
from .execution import ControlledExecutionRecord, ControlledExecutionService, required_execution_permission


class ApplicationCoreAuditBridge(AuditStore):
    """Adapt Core Operator audit events to the application metadata log."""

    def __init__(self, audit: MetadataAuditLog) -> None:
        self.audit = audit
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
            actor=actor,
            action=action,
            risk_level=risk_level,
            command_id=command_id,
            result=result,
            authorization_required=authorization_required,
        )
        self.audit.append(
            user_id="core-operator",
            actor=actor,
            role="CORE_OPERATOR",
            action=action,
            risk=risk_level.value,
            command=command_id,
            authorization="core_operator" if authorization_required else "metadata_only",
            result=result,
        )
        self._events.append(event)
        return event


@dataclass(frozen=True)
class ExecutionPipelineResult:
    plan: ApprovedExecutionPlan
    dry_run: DryRunExecutionResult
    gate: ExecutionGateDecision
    controlled_execution: ControlledExecutionRecord | None


class ExecutionPipelineService:
    """Run every pre-execution gate without bypassing the controlled executor."""

    def __init__(
        self,
        *,
        auth: AuthService,
        policy: PolicyEngine,
        approvals: ApprovalStore,
        audit: MetadataAuditLog,
        controlled_execution: ControlledExecutionService,
        max_risk_level: RiskLevel = RiskLevel.LOW,
        policy_version: str = "legacy",
    ) -> None:
        self.auth = auth
        self.approvals = approvals
        bridge = ApplicationCoreAuditBridge(audit)
        self.planner = ApprovedExecutionPlanner(policy=policy, approvals=approvals, audit=bridge)
        self.dry_runner = ApprovedPlanDryRunner(policy=policy, audit=bridge, max_risk_level=max_risk_level)
        self.gate = ExecutionGate(policy=policy, audit=bridge, max_risk_level=max_risk_level)
        self.controlled_execution = controlled_execution
        self.policy_version = policy_version

    def run(
        self,
        *,
        session_id: str,
        action: str,
        command_id: str,
        approval_id: str,
    ) -> ExecutionPipelineResult:
        user = self.auth.require(session_id, required_execution_permission(action, command_id))
        try:
            approval = self.approvals.get(approval_id)
            approval_actor = approval.actor
            resource = approval.resource
        except ValueError:
            approval = None
            approval_actor = user.username
            resource = f"command:{command_id}"
        snapshot_user = self.auth.user_for_username(approval_actor)
        snapshot_permissions = (
            tuple(sorted(permission.value for permission in snapshot_user.permissions))
            if snapshot_user is not None
            else tuple(sorted(permission.value for permission in user.permissions))
        )
        plan = self.planner.build_plan(
            actor=approval_actor,
            action=action,
            command_id=command_id,
            approval_id=approval_id,
            policy_version=self.policy_version,
            effective_permissions=snapshot_permissions,
            resource=resource,
        )
        dry_run = self.dry_runner.dry_run(plan)
        gate = self.gate.evaluate(plan=plan, dry_run=dry_run)
        controlled = None
        if gate.state.value == "eligible_for_controlled_execution":
            controlled = self.controlled_execution.request(session_id=session_id, decision=gate)
        return ExecutionPipelineResult(
            plan=plan,
            dry_run=dry_run,
            gate=gate,
            controlled_execution=controlled,
        )
