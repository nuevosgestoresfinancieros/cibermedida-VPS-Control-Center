"""Rollback planning with an explicit authorization and execution block."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol
from uuid import uuid4

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret

from .audit import MetadataAuditLog
from .auth import AuthService, Permission
from .state import JsonMetadataStore


class RollbackState(str, Enum):
    PLANNED = "planned"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    BLOCKED = "blocked"
    VERIFIED = "verified"


@dataclass(frozen=True)
class RollbackPlan:
    rollback_id: str
    project: str
    rollback_type: str
    target: str
    requested_by: str
    approved_by: str | None
    state: RollbackState
    reason: str
    created_at: str


@dataclass(frozen=True)
class RollbackProviderEvidence:
    provider: str
    result: str
    verified: bool


class RollbackProvider(Protocol):
    name: str

    def rollback(self, *, plan: RollbackPlan) -> RollbackProviderEvidence:
        ...


class RollbackManager:
    def __init__(
        self,
        *,
        auth: AuthService,
        audit: MetadataAuditLog,
        provider: RollbackProvider | None = None,
        provider_enabled: bool = False,
        state_store: JsonMetadataStore | None = None,
    ) -> None:
        self.auth = auth
        self.audit = audit
        self.provider = provider
        self.provider_enabled = provider_enabled
        self.state_store = state_store
        self._plans: dict[str, RollbackPlan] = {}
        if self.state_store is not None:
            for raw_plan in self.state_store.load():
                plan = _decode_plan(raw_plan)
                if plan.rollback_id in self._plans:
                    raise ValueError("rollback state contains duplicate ids")
                self._plans[plan.rollback_id] = plan

    @property
    def plans(self) -> tuple[RollbackPlan, ...]:
        return tuple(self._plans.values())

    def prepare(self, *, session_id: str, project: str, rollback_type: str, target: str) -> RollbackPlan:
        user = self.auth.require(session_id, Permission.ROLLBACK)
        if not all(_safe_text(value) for value in (project, rollback_type, target)):
            raise ValueError("rollback metadata is unsafe")
        plan = RollbackPlan(
            rollback_id=f"rollback-{uuid4()}",
            project=project,
            rollback_type=rollback_type,
            target=target,
            requested_by=user.username,
            approved_by=None,
            state=RollbackState.AWAITING_APPROVAL,
            reason="rollback requires independent approval",
            created_at=_now(),
        )
        updated_plans = dict(self._plans)
        updated_plans[plan.rollback_id] = plan
        self._persist(updated_plans)
        self._plans = updated_plans
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=project,
            action="rollback_prepared",
            risk="CRITICAL",
            authorization="permission:ROLLBACK",
            result=plan.state.value,
            metadata={"rollback_type": rollback_type},
        )
        return plan

    def approve(self, *, session_id: str, rollback_id: str) -> RollbackPlan:
        user = self.auth.require(session_id, Permission.APPROVE_OPERATION)
        plan = self._get(rollback_id)
        if plan.requested_by == user.username:
            raise PermissionError("requester and approver must be different users")
        if plan.state is not RollbackState.AWAITING_APPROVAL:
            raise ValueError("rollback is not awaiting approval")
        updated = replace(plan, state=RollbackState.APPROVED, approved_by=user.username)
        updated_plans = dict(self._plans)
        updated_plans[rollback_id] = updated
        self._persist(updated_plans)
        self._plans = updated_plans
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=plan.project,
            action="rollback_approved",
            risk="CRITICAL",
            authorization="permission:APPROVE_OPERATION",
            result=updated.state.value,
        )
        return updated

    def execute(self, *, session_id: str, rollback_id: str) -> RollbackPlan:
        user = self.auth.require(session_id, Permission.ROLLBACK)
        plan = self._get(rollback_id)
        if plan.state is not RollbackState.APPROVED:
            if plan.state in {RollbackState.BLOCKED, RollbackState.VERIFIED}:
                raise ValueError("rollback is not approved")
            updated = replace(plan, state=RollbackState.BLOCKED, reason="rollback requires independent approval")
        elif not self.provider_enabled or self.provider is None:
            updated = replace(plan, state=RollbackState.BLOCKED, reason="production rollback is disabled")
        else:
            try:
                evidence = self.provider.rollback(plan=plan)
            except Exception:
                evidence = None
            if _valid_evidence(evidence):
                updated = replace(plan, state=RollbackState.VERIFIED, reason=evidence.result)
            else:
                updated = replace(plan, state=RollbackState.BLOCKED, reason="rollback provider returned unsafe or failed evidence")
        updated_plans = dict(self._plans)
        updated_plans[rollback_id] = updated
        self._persist(updated_plans)
        self._plans = updated_plans
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=plan.project,
            action="rollback_execution_requested",
            risk="CRITICAL",
            authorization="permission:ROLLBACK",
            result=updated.state.value,
        )
        return updated

    def _get(self, rollback_id: str) -> RollbackPlan:
        try:
            return self._plans[rollback_id]
        except KeyError as exc:
            raise ValueError("rollback does not exist") from exc

    def _persist(self, plans: dict[str, RollbackPlan]) -> None:
        if self.state_store is not None:
            self.state_store.save(_encode_plan(plan) for plan in plans.values())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _valid_evidence(value: object) -> bool:
    if not isinstance(value, RollbackProviderEvidence):
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


def _encode_plan(plan: RollbackPlan) -> dict[str, object]:
    return {
        "rollback_id": plan.rollback_id,
        "project": plan.project,
        "rollback_type": plan.rollback_type,
        "target": plan.target,
        "requested_by": plan.requested_by,
        "approved_by": plan.approved_by,
        "state": plan.state.value,
        "reason": plan.reason,
        "created_at": plan.created_at,
    }


def _decode_plan(value: dict[str, object]) -> RollbackPlan:
    try:
        return RollbackPlan(
            rollback_id=_required_text(value, "rollback_id"),
            project=_required_text(value, "project"),
            rollback_type=_required_text(value, "rollback_type"),
            target=_required_text(value, "target"),
            requested_by=_required_text(value, "requested_by"),
            approved_by=_optional_text(value, "approved_by"),
            state=RollbackState(value["state"]),
            reason=_required_text(value, "reason"),
            created_at=_required_text(value, "created_at"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("rollback state record is invalid") from exc


def _required_text(value: dict[str, object], key: str) -> str:
    item = value[key]
    if not _safe_text(item):
        raise ValueError(f"rollback field {key} is invalid")
    return item.strip()


def _optional_text(value: dict[str, object], key: str) -> str | None:
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
