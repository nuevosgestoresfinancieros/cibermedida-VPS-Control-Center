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
from .service_activation import (
    DEFAULT_SERVICE_UNIT,
    ServiceActivationEvidence,
    ServiceActivationProvider,
    ServiceActivationRequest,
    ServiceActivationState,
)
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
        service_activation: ServiceActivationProvider | None = None,
    ) -> None:
        self.auth = auth
        self.audit = audit
        self.provider = provider
        self.provider_enabled = provider_enabled
        self.state_store = state_store
        self.service_activation = service_activation
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
        preflight = (
            self._preflight_service(plan)
            if plan.state is RollbackState.APPROVED and self.service_activation is not None
            else None
        )
        if plan.state is not RollbackState.APPROVED:
            if plan.state in {RollbackState.BLOCKED, RollbackState.VERIFIED}:
                raise ValueError("rollback is not approved")
            updated = replace(plan, state=RollbackState.BLOCKED, reason="rollback requires independent approval")
        elif preflight is not None and not _valid_activation_evidence(preflight, self._activation_request(plan)):
            updated = replace(plan, state=RollbackState.BLOCKED, reason="service activation preflight was unsafe")
        elif preflight is not None and preflight.state is ServiceActivationState.READY and preflight.verified is not True:
            updated = replace(plan, state=RollbackState.BLOCKED, reason="service activation preflight was not verified")
        elif preflight is not None and preflight.state is not ServiceActivationState.READY:
            updated = replace(
                plan,
                state=RollbackState.BLOCKED if preflight.state is ServiceActivationState.BLOCKED_BY_DEFAULT else RollbackState.BLOCKED,
                reason=f"service activation: {preflight.result}",
            )
        elif not self.provider_enabled or self.provider is None:
            updated = replace(plan, state=RollbackState.BLOCKED, reason="production rollback is disabled")
        else:
            try:
                evidence = self.provider.rollback(plan=plan)
            except Exception:
                evidence = None
            if _valid_evidence(evidence):
                activation = self._activate_service(plan)
                if activation is not None and not _valid_activation_evidence(activation, self._activation_request(plan)):
                    updated = replace(plan, state=RollbackState.BLOCKED, reason="service activation evidence was unsafe")
                elif activation is not None and activation.state is ServiceActivationState.ACTIVATED and activation.verified is not True:
                    updated = replace(plan, state=RollbackState.BLOCKED, reason="service activation evidence was not verified")
                elif activation is not None and activation.state is not ServiceActivationState.ACTIVATED:
                    updated = replace(
                        plan,
                        state=RollbackState.BLOCKED,
                        reason=f"service activation: {activation.result}",
                    )
                else:
                    reason = evidence.result
                    if activation is not None:
                        reason = f"{reason}; {activation.result}"
                    updated = replace(plan, state=RollbackState.VERIFIED, reason=reason)
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

    def _preflight_service(self, plan: RollbackPlan) -> ServiceActivationEvidence:
        try:
            return self.service_activation.preflight(request=self._activation_request(plan))  # type: ignore[union-attr]
        except Exception:
            return ServiceActivationEvidence(
                provider="service-activation",
                unit=DEFAULT_SERVICE_UNIT,
                operation="rollback",
                state=ServiceActivationState.FAILED,
                result="service activation preflight failed",
                verified=False,
            )

    def _activation_request(self, plan: RollbackPlan) -> ServiceActivationRequest:
        return ServiceActivationRequest(
            unit=DEFAULT_SERVICE_UNIT,
            project=plan.project,
            operation="rollback",
            release=plan.target,
            requested_by=plan.requested_by,
            approved_by=plan.approved_by or "",
            approval_reference=plan.rollback_id,
        )

    def _activate_service(self, plan: RollbackPlan) -> ServiceActivationEvidence | None:
        if self.service_activation is None:
            return None
        try:
            return self.service_activation.activate(
                request=self._activation_request(plan)
            )
        except Exception:
            return ServiceActivationEvidence(
                provider="service-activation",
                unit=DEFAULT_SERVICE_UNIT,
                operation="rollback",
                state=ServiceActivationState.FAILED,
                result="service activation provider failed",
                verified=False,
            )

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


def _valid_activation_evidence(value: object, request: ServiceActivationRequest) -> bool:
    if not isinstance(value, ServiceActivationEvidence):
        return False
    fields = (value.provider, value.unit, value.operation, value.result)
    return (
        isinstance(value.state, ServiceActivationState)
        and isinstance(value.verified, bool)
        and value.unit == request.unit
        and value.operation == request.operation
        and all(
            isinstance(item, str)
            and item.strip()
            and len(item) <= 512
            and not contains_secret(item)
            and RAW_STREAM_PATTERN.search(item) is None
            and not any(ord(character) < 32 for character in item)
            for item in fields
        )
    )
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
