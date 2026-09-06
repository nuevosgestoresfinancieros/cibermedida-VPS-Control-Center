"""Fixed-service activation boundary for approved releases.

This module defines the hand-off between release management and an external
service activator. It does not execute system commands. A production runner
must be injected explicitly after its privilege boundary and health checks
have been reviewed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret


DEFAULT_SERVICE_UNIT = "cibermedida-vps-control-center.service"
ALLOWED_OPERATIONS = frozenset({"deploy", "rollback"})


class ServiceActivationState(str, Enum):
    READY = "ready"
    BLOCKED_BY_DEFAULT = "blocked_by_default"
    REJECTED = "rejected"
    ACTIVATED = "activated"
    FAILED = "failed"


@dataclass(frozen=True)
class ServiceActivationRequest:
    unit: str
    project: str
    operation: str
    release: str
    requested_by: str
    approved_by: str
    approval_reference: str


@dataclass(frozen=True)
class ServiceActivationEvidence:
    provider: str
    unit: str
    operation: str
    state: ServiceActivationState
    result: str
    verified: bool


class ServiceActivationRunner(Protocol):
    def run(self, *, request: ServiceActivationRequest) -> ServiceActivationEvidence:
        """Perform one already-authorized fixed-service activation."""


class ServiceActivationProvider(Protocol):
    name: str

    def preflight(self, *, request: ServiceActivationRequest) -> ServiceActivationEvidence:
        ...

    def activate(self, *, request: ServiceActivationRequest) -> ServiceActivationEvidence:
        ...


class FixedServiceActivation:
    """Allow only one service and two release operations.

    The provider remains blocked unless both enabled=True and an explicit
    runner are supplied. The default application graph does neither.
    """

    name = "fixed-service-activation"

    def __init__(
        self,
        *,
        allowed_unit: str = DEFAULT_SERVICE_UNIT,
        allowed_project: str = "control-center",
        enabled: bool = False,
        runner: ServiceActivationRunner | None = None,
    ) -> None:
        if not _safe_text(allowed_unit) or not allowed_unit.endswith(".service"):
            raise ValueError("allowed service unit is invalid")
        if allowed_unit != DEFAULT_SERVICE_UNIT:
            raise ValueError("only the control center service unit is allowed")
        if not _safe_text(allowed_project):
            raise ValueError("allowed project is invalid")
        if allowed_project != "control-center":
            raise ValueError("only the control-center project is allowed")
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be boolean")
        self.allowed_unit = allowed_unit
        self.allowed_project = allowed_project
        self.enabled = enabled
        self.runner = runner

    def preflight(self, *, request: ServiceActivationRequest) -> ServiceActivationEvidence:
        validation = self._validate_request(request)
        if validation is not None:
            return validation
        if not self.enabled or self.runner is None:
            return self._result(request, ServiceActivationState.BLOCKED_BY_DEFAULT, "service activation is disabled", False)
        return self._result(request, ServiceActivationState.READY, "service activation runner is configured", True)

    def status(self) -> dict[str, object]:
        """Return bounded metadata for read-only status surfaces."""

        return {
            "provider": self.name,
            "state": (
                "runner_configured"
                if self.enabled and self.runner is not None
                else ServiceActivationState.BLOCKED_BY_DEFAULT.value
            ),
            "serviceUnit": self.allowed_unit,
            "project": self.allowed_project,
            "operations": sorted(ALLOWED_OPERATIONS),
            "enabled": self.enabled,
            "runnerConfigured": self.runner is not None,
        }

    def activate(self, *, request: ServiceActivationRequest) -> ServiceActivationEvidence:
        validation = self._validate_request(request)
        if validation is not None:
            return validation
        if not self.enabled or self.runner is None:
            return self._result(request, ServiceActivationState.BLOCKED_BY_DEFAULT, "service activation is disabled", False)

        try:
            evidence = self.runner.run(request=request)
        except Exception:
            return self._result(request, ServiceActivationState.FAILED, "service activation runner failed", False)
        if not _valid_evidence(evidence, request):
            return self._result(request, ServiceActivationState.FAILED, "service activation evidence is unsafe", False)
        return evidence

    def _validate_request(self, request: ServiceActivationRequest) -> ServiceActivationEvidence | None:
        if not _request_is_safe(request):
            return self._result(request, ServiceActivationState.REJECTED, "activation metadata is unsafe", False)
        if request.unit != self.allowed_unit:
            return self._result(request, ServiceActivationState.REJECTED, "service unit is outside the allowlist", False)
        if request.project != self.allowed_project:
            return self._result(request, ServiceActivationState.REJECTED, "project is outside the allowlist", False)
        if request.operation not in ALLOWED_OPERATIONS:
            return self._result(request, ServiceActivationState.REJECTED, "operation is outside the allowlist", False)
        if request.requested_by == request.approved_by:
            return self._result(request, ServiceActivationState.REJECTED, "requester and approver must differ", False)
        return None

    def _result(
        self,
        request: ServiceActivationRequest,
        state: ServiceActivationState,
        result: str,
        verified: bool,
    ) -> ServiceActivationEvidence:
        return ServiceActivationEvidence(
            provider=self.name,
            unit=request.unit,
            operation=request.operation,
            state=state,
            result=result,
            verified=verified,
        )


def _request_is_safe(request: ServiceActivationRequest) -> bool:
    if not isinstance(request, ServiceActivationRequest):
        return False
    return all(
        _safe_text(value)
        for value in (
            request.unit,
            request.project,
            request.operation,
            request.release,
            request.requested_by,
            request.approved_by,
            request.approval_reference,
        )
    )


def _safe_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= 256
        and not any(character in value for character in ("\r", "\n", "\x00"))
        and contains_secret(value) is False
        and RAW_STREAM_PATTERN.search(value) is None
    )


def _valid_evidence(value: object, request: ServiceActivationRequest) -> bool:
    return (
        isinstance(value, ServiceActivationEvidence)
        and value.provider == "fixed-service-runner"
        and value.unit == request.unit
        and value.operation == request.operation
        and value.state is ServiceActivationState.ACTIVATED
        and value.verified is True
        and _safe_text(value.provider)
        and _safe_text(value.result)
    )
