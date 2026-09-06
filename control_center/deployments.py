"""Deployment planning and post-validation contracts without real deployment."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Mapping, Protocol
from uuid import uuid4

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret

from .audit import MetadataAuditLog
from .auth import AuthService, Permission
from .backups import BackupManager
from .state import JsonMetadataStore


class DeploymentState(str, Enum):
    BLOCKED = "blocked"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    VERIFIED = "verified"
    FAILED = "failed"


@dataclass(frozen=True)
class DeploymentPlan:
    deployment_id: str
    project: str
    commit: str
    requested_by: str
    state: DeploymentState
    checks: Mapping[str, bool]
    backup_id: str | None
    approved_by: str | None
    reason: str
    created_at: str
    branch: str = "main"
    tests_status: str = "pending"
    build_status: str = "pending"
    risk: str = "L3"
    approval_id: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    health_status: str = "unknown"
    rollback_available: bool = False
    server: str = "local-lab"
    environment: str = "laboratory"
    operation_id: str | None = None
    operation_hash: str | None = None


@dataclass(frozen=True)
class DeploymentProviderEvidence:
    provider: str
    result: str
    verified: bool


@dataclass(frozen=True)
class DeploymentValidationEvidence:
    validator: str
    result: str
    verified: bool


class DeploymentProvider(Protocol):
    name: str

    def deploy(self, *, plan: DeploymentPlan) -> DeploymentProviderEvidence:
        ...


class DeploymentValidator(Protocol):
    name: str

    def validate(
        self,
        *,
        plan: DeploymentPlan,
        deployment: DeploymentProviderEvidence,
    ) -> DeploymentValidationEvidence:
        ...


class DeploymentManager:
    def __init__(
        self,
        *,
        auth: AuthService,
        audit: MetadataAuditLog,
        backups: BackupManager | None = None,
        provider: DeploymentProvider | None = None,
        provider_enabled: bool = False,
        post_validator: DeploymentValidator | None = None,
        state_store: JsonMetadataStore | None = None,
    ) -> None:
        self.auth = auth
        self.audit = audit
        self.backups = backups
        self.provider = provider
        self.provider_enabled = provider_enabled
        self.post_validator = post_validator
        self.state_store = state_store
        self._plans: dict[str, DeploymentPlan] = {}
        if self.state_store is not None:
            for raw_plan in self.state_store.load():
                plan = _decode_plan(raw_plan)
                if plan.deployment_id in self._plans:
                    raise ValueError("deployment state contains duplicate ids")
                self._plans[plan.deployment_id] = plan

    @property
    def plans(self) -> tuple[DeploymentPlan, ...]:
        return tuple(self._plans.values())

    def prepare(
        self,
        *,
        session_id: str,
        project: str,
        commit: str,
        checks: Mapping[str, bool],
        backup_id: str | None,
        branch: str = "main",
        server: str = "local-lab",
        environment: str = "laboratory",
        approval_id: str | None = None,
        operation_id: str | None = None,
        operation_hash: str | None = None,
    ) -> DeploymentPlan:
        user = self.auth.require(session_id, Permission.DEPLOY)
        required = ("git", "branch", "tests", "build", "dependencies", "disk", "backup", "backup_verification")
        effective = {name: bool(checks.get(name, False)) for name in required}
        backup_verified = False
        if backup_id is not None and self.backups is not None:
            backup_verified = self.backups.is_verified(backup_id)
        if backup_id is None or (self.backups is not None and not backup_verified):
            effective["backup"] = False
            effective["backup_verification"] = False
        passed = all(effective.values())
        state = DeploymentState.AWAITING_APPROVAL if passed else DeploymentState.BLOCKED
        reason = "pre-deploy checks passed; approval required" if passed else "pre-deploy checks are incomplete"
        if not all(_safe_text(value) for value in (project, commit, branch, server, environment)):
            raise ValueError("deployment metadata is unsafe")
        for value in (approval_id, operation_id, operation_hash):
            if value is not None and not _safe_text(value):
                raise ValueError("deployment metadata is unsafe")
        plan = DeploymentPlan(
            deployment_id=f"deploy-{uuid4()}",
            project=project,
            commit=commit,
            requested_by=user.username,
            state=state,
            checks=effective,
            backup_id=backup_id,
            approved_by=None,
            reason=reason,
            created_at=_now(),
            branch=branch,
            tests_status="passed" if effective["tests"] else "pending",
            build_status="passed" if effective["build"] else "pending",
            risk="L3",
            approval_id=approval_id,
            rollback_available=bool(backup_verified),
            server=server,
            environment=environment,
            operation_id=operation_id,
            operation_hash=operation_hash,
        )
        updated_plans = dict(self._plans)
        updated_plans[plan.deployment_id] = plan
        self._persist(updated_plans)
        self._plans = updated_plans
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=project,
            action="deployment_prepared",
            risk="HIGH",
            authorization="permission:DEPLOY",
            backup=backup_id,
            commit=commit,
            result=state.value,
            metadata={"checks": effective},
        )
        return plan

    def approve(self, *, session_id: str, deployment_id: str) -> DeploymentPlan:
        approver = self.auth.require(session_id, Permission.APPROVE_OPERATION)
        plan = self._get(deployment_id)
        if plan.requested_by == approver.username:
            raise PermissionError("requester and approver must be different users")
        if plan.state is not DeploymentState.AWAITING_APPROVAL:
            raise ValueError("deployment is not awaiting approval")
        updated = replace(plan, state=DeploymentState.APPROVED, approved_by=approver.username)
        updated_plans = dict(self._plans)
        updated_plans[deployment_id] = updated
        self._persist(updated_plans)
        self._plans = updated_plans
        self.audit.append(
            user_id=approver.user_id,
            actor=approver.username,
            role=approver.role.value,
            project=plan.project,
            action="deployment_approved",
            risk="HIGH",
            authorization="permission:APPROVE_OPERATION",
            backup=plan.backup_id,
            commit=plan.commit,
            result=updated.state.value,
        )
        return updated

    def execute(self, *, session_id: str, deployment_id: str) -> DeploymentPlan:
        user = self.auth.require(session_id, Permission.DEPLOY)
        plan = self._get(deployment_id)
        if plan.state is not DeploymentState.APPROVED:
            if plan.state in {
                DeploymentState.BLOCKED,
                DeploymentState.FAILED,
                DeploymentState.VERIFIED,
            }:
                raise ValueError("deployment is not approved")
            updated = replace(plan, state=DeploymentState.BLOCKED, reason="deployment requires independent approval")
        elif not self.provider_enabled or self.provider is None:
            updated = replace(plan, state=DeploymentState.BLOCKED, reason="production deployment is disabled")
        elif (
            self.backups is None
            or not self.backups.provider_enabled
            or self.backups.provider is None
            or plan.backup_id is None
            or not self.backups.is_verified(plan.backup_id)
        ):
            updated = replace(plan, state=DeploymentState.BLOCKED, reason="verified backup provider evidence is required")
        elif self.post_validator is None:
            updated = replace(plan, state=DeploymentState.BLOCKED, reason="post-deployment validator is required")
        else:
            try:
                evidence = self.provider.deploy(plan=plan)
            except Exception:
                evidence = None
            if not _valid_evidence(evidence):
                updated = replace(plan, state=DeploymentState.FAILED, reason="deployment provider returned unsafe or failed evidence")
            else:
                try:
                    validation = self.post_validator.validate(plan=plan, deployment=evidence)
                except Exception:
                    validation = None
                if _valid_validation(validation):
                    updated = replace(
                        plan,
                        state=DeploymentState.VERIFIED,
                        reason=f"{evidence.result}; {validation.result}",
                    )
                else:
                    updated = replace(
                        plan,
                        state=DeploymentState.FAILED,
                        reason="post-deployment validation failed",
                    )
        updated = replace(
            updated,
            started_at=updated.started_at or _now(),
            finished_at=_now(),
            health_status=("healthy" if updated.state is DeploymentState.VERIFIED else "blocked" if updated.state is DeploymentState.BLOCKED else "failed"),
            rollback_available=updated.rollback_available or bool(updated.backup_id),
        )
        updated_plans = dict(self._plans)
        updated_plans[deployment_id] = updated
        self._persist(updated_plans)
        self._plans = updated_plans
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=plan.project,
            action="deployment_execution_requested",
            risk="CRITICAL",
            authorization="permission:DEPLOY",
            backup=plan.backup_id,
            commit=plan.commit,
            result=updated.state.value,
            metadata={
                "post_validation": self.post_validator is not None,
            },
        )
        return updated

    def _get(self, deployment_id: str) -> DeploymentPlan:
        try:
            return self._plans[deployment_id]
        except KeyError as exc:
            raise ValueError("deployment does not exist") from exc

    def _persist(self, plans: Mapping[str, DeploymentPlan]) -> None:
        if self.state_store is not None:
            self.state_store.save(_encode_plan(plan) for plan in plans.values())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _valid_evidence(value: object) -> bool:
    if not isinstance(value, DeploymentProviderEvidence):
        return False
    fields = (value.provider, value.result)
    return all(
        isinstance(item, str)
        and item.strip()
        and len(item) <= 512
        and not contains_secret(item)
        and RAW_STREAM_PATTERN.search(item) is None
        for item in fields
    ) and value.verified is True


def _valid_validation(value: object) -> bool:
    if not isinstance(value, DeploymentValidationEvidence):
        return False
    fields = (value.validator, value.result)
    return all(
        isinstance(item, str)
        and item.strip()
        and len(item) <= 512
        and not contains_secret(item)
        and RAW_STREAM_PATTERN.search(item) is None
        for item in fields
    ) and value.verified is True


def _encode_plan(plan: DeploymentPlan) -> dict[str, object]:
    return {
        "deployment_id": plan.deployment_id,
        "project": plan.project,
        "commit": plan.commit,
        "requested_by": plan.requested_by,
        "state": plan.state.value,
        "checks": dict(plan.checks),
        "backup_id": plan.backup_id,
        "approved_by": plan.approved_by,
        "reason": plan.reason,
        "created_at": plan.created_at,
        "branch": plan.branch,
        "tests_status": plan.tests_status,
        "build_status": plan.build_status,
        "risk": plan.risk,
        "approval_id": plan.approval_id,
        "started_at": plan.started_at,
        "finished_at": plan.finished_at,
        "health_status": plan.health_status,
        "rollback_available": plan.rollback_available,
        "server": plan.server,
        "environment": plan.environment,
        "operation_id": plan.operation_id,
        "operation_hash": plan.operation_hash,
    }


def _decode_plan(value: Mapping[str, object]) -> DeploymentPlan:
    checks = value.get("checks")
    if not isinstance(checks, dict) or any(not isinstance(key, str) or not isinstance(item, bool) for key, item in checks.items()):
        raise ValueError("deployment checks are invalid")
    try:
        return DeploymentPlan(
            deployment_id=_required_text(value, "deployment_id"),
            project=_required_text(value, "project"),
            commit=_required_text(value, "commit"),
            requested_by=_required_text(value, "requested_by"),
            state=DeploymentState(value["state"]),
            checks=checks,
            backup_id=_optional_text(value, "backup_id"),
            approved_by=_optional_text(value, "approved_by"),
            reason=_required_text(value, "reason"),
            created_at=_required_text(value, "created_at"),
            branch=_required_text(value, "branch") if value.get("branch") is not None else "main",
            tests_status=_required_text(value, "tests_status") if value.get("tests_status") is not None else "pending",
            build_status=_required_text(value, "build_status") if value.get("build_status") is not None else "pending",
            risk=_required_text(value, "risk") if value.get("risk") is not None else "L3",
            approval_id=_optional_text(value, "approval_id"),
            started_at=_optional_text(value, "started_at"),
            finished_at=_optional_text(value, "finished_at"),
            health_status=_required_text(value, "health_status") if value.get("health_status") is not None else "unknown",
            rollback_available=bool(value.get("rollback_available", False)),
            server=_required_text(value, "server") if value.get("server") is not None else "local-lab",
            environment=_required_text(value, "environment") if value.get("environment") is not None else "laboratory",
            operation_id=_optional_text(value, "operation_id"),
            operation_hash=_optional_text(value, "operation_hash"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("deployment state record is invalid") from exc


def _required_text(value: Mapping[str, object], key: str) -> str:
    item = value[key]
    if not _safe_text(item):
        raise ValueError(f"deployment field {key} is invalid")
    return item.strip()


def _optional_text(value: Mapping[str, object], key: str) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    return _required_text(value, key)


def _safe_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= 512
        and not contains_secret(value)
        and RAW_STREAM_PATTERN.search(value) is None
        and not any(ord(character) < 32 for character in value)
    )
