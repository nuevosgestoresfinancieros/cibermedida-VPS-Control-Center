"""Authorization-aware planning and execution gates for application actions."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Mapping
from uuid import uuid4

from core_operator.approvals import ApprovalStore
from core_operator.audit import RAW_STREAM_PATTERN, contains_secret
from core_operator.policy import Decision, PolicyEngine, PolicyRequest, RiskLevel

from .audit import MetadataAuditLog
from .auth import AuthService, Permission, User
from .backups import BackupManager
from .operation_manifest import OperationManifest, OperationStatus, manifest_from_dict, risk_level_for
from .state import JsonMetadataStore


class OperationState(str, Enum):
    PLANNED = "planned"
    APPROVAL_REQUIRED = "approval_required"
    APPROVED = "approved"
    BACKUP_REQUIRED = "backup_required"
    READY = "ready"
    BLOCKED_BY_DEFAULT = "blocked_by_default"
    REJECTED = "rejected"
    VERIFIED = "verified"
    FAILED = "failed"


@dataclass(frozen=True)
class OperationPlan:
    plan_id: str
    actor_id: str
    actor: str
    role: str
    project: str
    action: str
    resource: str
    risk: RiskLevel
    policy_decision: str
    state: OperationState
    approval_id: str | None
    backup_id: str | None
    policy_version: str
    effective_permissions: tuple[str, ...]
    steps: tuple[str, ...]
    created_at: str
    reason: str
    manifest: OperationManifest | None = None


class OperationService:
    def __init__(
        self,
        *,
        auth: AuthService,
        policy: PolicyEngine,
        approvals: ApprovalStore,
        audit: MetadataAuditLog,
        backups: BackupManager | None = None,
        policy_version: str = "phase-3.6",
        state_store: JsonMetadataStore | None = None,
    ) -> None:
        self.auth = auth
        self.policy = policy
        self.approvals = approvals
        self.audit = audit
        self.backups = backups
        self.policy_version = policy_version
        self.state_store = state_store
        self._plans: dict[str, OperationPlan] = {}
        if self.state_store is not None:
            for raw_plan in self.state_store.load():
                plan = _decode_plan(raw_plan)
                if plan.plan_id in self._plans:
                    raise ValueError("operation state contains duplicate ids")
                self._plans[plan.plan_id] = plan

    @property
    def plans(self) -> tuple[OperationPlan, ...]:
        return tuple(self._plans.values())

    def plan(
        self,
        *,
        session_id: str,
        project: str,
        action: str,
        resource: str = "project",
        command_id: str | None = None,
        server: str = "local-lab",
        environment: str = "laboratory",
        branch: str | None = None,
        commit: str | None = None,
        files: tuple[str, ...] = (),
        services_affected: tuple[str, ...] = (),
        dependencies: tuple[str, ...] = (),
        tests_required: tuple[str, ...] = (),
        downtime_possible: bool = False,
        data_risk: str = "none",
    ) -> OperationPlan:
        user = self.auth.require(session_id, Permission.REQUEST_APPROVAL)
        _assert_safe_texts(
            (project, action, resource, command_id, self.policy_version, server, environment, branch, commit, data_risk)
        )
        for values in (files, services_affected, dependencies, tests_required):
            _assert_safe_texts(tuple(values))
        risk, decision, reason, requires_approval = self._evaluate(
            actor=user.username,
            action=action,
            command_id=command_id,
        )
        plan_id = f"plan-{uuid4()}"
        effective_permissions = tuple(sorted(permission.value for permission in user.permissions))
        if decision == Decision.DENY.value:
            state = OperationState.REJECTED
        elif requires_approval:
            state = OperationState.APPROVAL_REQUIRED
        else:
            state = OperationState.PLANNED
        backup_required = action in {"deploy", "rollback", "create_backup", "restart_service"}
        manifest = OperationManifest.create(
            operation_id=plan_id,
            project=project,
            server=server,
            environment=environment,
            resource=resource,
            requested_by=user.username,
            requested_action=action,
            agent="control_center",
            risk_level=risk_level_for(risk.value),
            status=_manifest_status(state),
            commands=(command_id,) if command_id else (),
            files=files,
            services_affected=services_affected,
            dependencies=dependencies,
            tests_required=tests_required,
            backup_required=backup_required,
            approval_required=requires_approval,
            branch=branch,
            commit=commit,
            rollback_plan=(
                "Restaurar el backup verificado y validar el estado; ejecución bloqueada por defecto."
                if backup_required
                else "No aplica para una operación de lectura."
            ),
            expected_result="La operación debe quedar registrada y validada sin salida cruda.",
            validation_steps=("policy", "approval" if requires_approval else "policy", "audit"),
            downtime_possible=downtime_possible,
            data_risk=data_risk,
            created_at=_now(),
        )
        approval_id: str | None = None
        if decision == Decision.APPROVAL_REQUIRED.value:
            request = self.approvals.create_pending(
                actor=user.username,
                action=action,
                risk_level=risk,
                reason=reason,
                command_id=command_id,
                actor_role=user.role.value,
                policy_version=self.policy_version,
                effective_permissions=effective_permissions,
                resource=resource,
                plan_id=plan_id,
                operation_id=manifest.operation_id,
                branch=manifest.branch,
                commit=manifest.commit,
                backup_id=manifest.backup_id,
                commands=manifest.commands,
                files=manifest.files,
                services_affected=manifest.services_affected,
                impact=manifest.services_affected,
                operation_hash=manifest.operation_hash,
                plan_hash=manifest.plan_hash,
            )
            approval_id = request.id
        plan = OperationPlan(
            plan_id=plan_id,
            actor_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=project,
            action=action,
            resource=resource,
            risk=risk,
            policy_decision=decision,
            state=state,
            approval_id=approval_id,
            backup_id=None,
            policy_version=self.policy_version,
            effective_permissions=effective_permissions,
            steps=self._steps_for(action),
            created_at=manifest.created_at,
            reason=reason,
            manifest=manifest,
        )
        updated_plans = dict(self._plans)
        updated_plans[plan.plan_id] = plan
        self._persist(updated_plans)
        self._plans = updated_plans
        self._audit(user, plan, "operation_planned", state.value)
        return plan

    def approve(self, *, session_id: str, plan_id: str, reason: str = "approved") -> OperationPlan:
        approver = self.auth.require(session_id, Permission.APPROVE_OPERATION)
        plan = self._get(plan_id)
        if plan.actor_id == approver.user_id:
            raise PermissionError("requester and approver must be different users")
        if plan.state is not OperationState.APPROVAL_REQUIRED or plan.approval_id is None:
            raise ValueError("plan is not awaiting approval")
        _assert_safe_texts((reason,))
        self.approvals.approve(
            plan.approval_id,
            decided_by=approver.username,
            decided_by_role=approver.role.value,
            reason=reason,
        )
        updated = replace(
            plan,
            state=OperationState.APPROVED,
            manifest=_manifest_transition(plan, OperationState.APPROVED, approved_at=_now()),
        )
        updated_plans = dict(self._plans)
        updated_plans[plan_id] = updated
        self._persist(updated_plans)
        self._plans = updated_plans
        self._audit(approver, updated, "operation_approved", updated.state.value)
        return updated

    def attach_verified_backup(self, *, session_id: str, plan_id: str, backup_id: str) -> OperationPlan:
        user = self.auth.require(session_id, Permission.APPROVE_OPERATION)
        plan = self._get(plan_id)
        if plan.state is not OperationState.APPROVED:
            raise ValueError("operation must be approved before backup attachment")
        if self.backups is not None and not self.backups.is_verified(backup_id):
            raise ValueError("backup must be verified before attachment")
        _assert_safe_texts((backup_id,))
        updated = replace(
            plan,
            state=OperationState.READY,
            backup_id=backup_id,
            manifest=_manifest_transition(plan, OperationState.READY, backup_id=backup_id),
        )
        updated_plans = dict(self._plans)
        updated_plans[plan_id] = updated
        self._persist(updated_plans)
        self._plans = updated_plans
        self._audit(user, updated, "operation_backup_attached", updated.state.value)
        return updated

    def execute(self, *, session_id: str, plan_id: str) -> OperationPlan:
        user = self.auth.require(session_id, Permission.DEPLOY)
        plan = self._get(plan_id)
        updated = replace(
            plan,
            state=OperationState.BLOCKED_BY_DEFAULT,
            reason="real execution is disabled",
            manifest=_manifest_transition(plan, OperationState.BLOCKED_BY_DEFAULT),
        )
        updated_plans = dict(self._plans)
        updated_plans[plan_id] = updated
        self._persist(updated_plans)
        self._plans = updated_plans
        self._audit(user, updated, "operation_execution_requested", updated.state.value)
        return updated

    def _evaluate(self, *, actor: str, action: str, command_id: str | None) -> tuple[RiskLevel, str, str, bool]:
        planned_actions = {"deploy", "rollback", "create_backup", "modify_code", "restart_service"}
        if action in planned_actions:
            return RiskLevel.HIGH, Decision.APPROVAL_REQUIRED.value, "sensitive action requires approval", True
        if command_id:
            decision = self.policy.evaluate(
                PolicyRequest(actor=actor, action=action, command_id=command_id)
            )
            return decision.risk_level, decision.decision.value, decision.reason, decision.decision is not Decision.ALLOW
        return RiskLevel.MEDIUM, Decision.DENY.value, "unknown operation requires an explicit contract", True

    @staticmethod
    def _steps_for(action: str) -> tuple[str, ...]:
        if action in {"deploy", "rollback"}:
            return ("preflight", "tests", "build", "backup", "approval", "execution", "validation", "audit")
        if action == "create_backup":
            return ("prepare", "checksum", "verify", "catalog", "restore_test")
        return ("policy", "approval", "dry_run", "gate", "blocked_by_default")

    def _audit(self, user: User, plan: OperationPlan, action: str, result: str) -> None:
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=plan.project,
            action=action,
            risk=plan.risk.value,
            command=plan.action,
            authorization=plan.policy_decision,
            backup=plan.backup_id,
            operation_id=plan.manifest.operation_id if plan.manifest else plan.plan_id,
            plan=plan.plan_id,
            approval=plan.approval_id,
            commands=plan.manifest.commands if plan.manifest else (),
            files=plan.manifest.files if plan.manifest else (),
            branch=plan.manifest.branch if plan.manifest else None,
            validation=", ".join(plan.manifest.validation_steps) if plan.manifest else None,
            rollback=plan.manifest.rollback_plan if plan.manifest else None,
            result=result,
            metadata={
                "plan_id": plan.plan_id,
                "policy_version": plan.policy_version,
                "effective_permissions": plan.effective_permissions,
                "operation_id": plan.manifest.operation_id if plan.manifest else plan.plan_id,
                "operation_hash": plan.manifest.operation_hash if plan.manifest else "",
                "plan_hash": plan.manifest.plan_hash if plan.manifest else "",
                "approval_hash": plan.manifest.approval_hash if plan.manifest else "",
                "execution_hash": plan.manifest.execution_hash if plan.manifest else "",
                "scope": dict(plan.manifest.scope) if plan.manifest else {"project": plan.project, "resource": plan.resource, "action": plan.action},
            },
        )

    def _get(self, plan_id: str) -> OperationPlan:
        try:
            return self._plans[plan_id]
        except KeyError as exc:
            raise ValueError("operation plan does not exist") from exc

    def _persist(self, plans: Mapping[str, OperationPlan]) -> None:
        if self.state_store is not None:
            self.state_store.save(_encode_plan(plan) for plan in plans.values())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _assert_safe_texts(values: tuple[str | None, ...]) -> None:
    for value in values:
        if value is None:
            continue
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value) > 512
            or contains_secret(value)
            or RAW_STREAM_PATTERN.search(value)
            or any(ord(character) < 32 for character in value)
        ):
            raise ValueError("operation metadata is unsafe")


def _encode_plan(plan: OperationPlan) -> dict[str, object]:
    return {
        "plan_id": plan.plan_id,
        "actor_id": plan.actor_id,
        "actor": plan.actor,
        "role": plan.role,
        "project": plan.project,
        "action": plan.action,
        "resource": plan.resource,
        "risk": plan.risk.value,
        "policy_decision": plan.policy_decision,
        "state": plan.state.value,
        "approval_id": plan.approval_id,
        "backup_id": plan.backup_id,
        "policy_version": plan.policy_version,
        "effective_permissions": list(plan.effective_permissions),
        "steps": list(plan.steps),
        "created_at": plan.created_at,
        "reason": plan.reason,
        "manifest": plan.manifest.as_dict() if plan.manifest is not None else None,
    }


def _decode_plan(value: Mapping[str, object]) -> OperationPlan:
    effective_permissions = value.get("effective_permissions")
    steps = value.get("steps")
    if (
        not isinstance(effective_permissions, list)
        or any(not isinstance(item, str) for item in effective_permissions)
        or not isinstance(steps, list)
        or any(not isinstance(item, str) for item in steps)
    ):
        raise ValueError("operation state lists are invalid")
    text_values = (
        value.get("plan_id"),
        value.get("actor_id"),
        value.get("actor"),
        value.get("role"),
        value.get("project"),
        value.get("action"),
        value.get("resource"),
        value.get("policy_decision"),
        value.get("approval_id"),
        value.get("backup_id"),
        value.get("policy_version"),
        value.get("created_at"),
        value.get("reason"),
        *effective_permissions,
        *steps,
    )
    if any(value is not None and not isinstance(value, str) for value in text_values):
        raise ValueError("operation state text fields are invalid")
    _assert_safe_texts(tuple(value for value in text_values if value is not None))
    try:
        return OperationPlan(
            plan_id=value["plan_id"],
            actor_id=value["actor_id"],
            actor=value["actor"],
            role=value["role"],
            project=value["project"],
            action=value["action"],
            resource=value["resource"],
            risk=RiskLevel(value["risk"]),
            policy_decision=value["policy_decision"],
            state=OperationState(value["state"]),
            approval_id=value.get("approval_id"),
            backup_id=value.get("backup_id"),
            policy_version=value["policy_version"],
            effective_permissions=tuple(effective_permissions),
            steps=tuple(steps),
            created_at=value["created_at"],
            reason=value["reason"],
            manifest=_decode_manifest(value, text_values),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("operation state record is invalid") from exc


def _manifest_status(state: OperationState) -> OperationStatus:
    return {
        OperationState.PLANNED: OperationStatus.PLANNED,
        OperationState.APPROVAL_REQUIRED: OperationStatus.WAITING_APPROVAL,
        OperationState.APPROVED: OperationStatus.APPROVED,
        OperationState.BACKUP_REQUIRED: OperationStatus.READY,
        OperationState.READY: OperationStatus.READY,
        OperationState.BLOCKED_BY_DEFAULT: OperationStatus.BLOCKED,
        OperationState.REJECTED: OperationStatus.REJECTED,
        OperationState.VERIFIED: OperationStatus.COMPLETED,
        OperationState.FAILED: OperationStatus.FAILED,
    }[state]


def _manifest_transition(plan: OperationPlan, state: OperationState, **changes: object) -> OperationManifest:
    if plan.manifest is None:
        raise ValueError("operation manifest is missing")
    return plan.manifest.with_status(_manifest_status(state), **changes)


def _decode_manifest(value: Mapping[str, object], text_values: tuple[object, ...]) -> OperationManifest | None:
    raw_manifest = value.get("manifest")
    if raw_manifest is None:
        return None
    if not isinstance(raw_manifest, Mapping):
        raise ValueError("operation manifest is invalid")
    return manifest_from_dict(raw_manifest)
