"""Validation and metadata-analysis contracts with no system probes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret

from .audit import MetadataAuditLog
from .auth import AuthService, Permission
from .state import JsonMetadataStore


class ValidationState(str, Enum):
    PASSED = "passed"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class ValidationReport:
    validation_id: str
    target: str
    state: ValidationState
    checks: Mapping[str, bool]
    findings: tuple[str, ...]
    executed_real_tests: bool
    created_at: str


class ValidatorService:
    """Evaluates caller-provided check results without running commands."""

    def __init__(
        self,
        *,
        auth: AuthService,
        audit: MetadataAuditLog,
        state_store: JsonMetadataStore | None = None,
    ) -> None:
        self.auth = auth
        self.audit = audit
        self.state_store = state_store
        self._reports: dict[str, ValidationReport] = {}
        if self.state_store is not None:
            for raw_report in self.state_store.load():
                report = _decode_report(raw_report)
                if report.validation_id in self._reports:
                    raise ValueError("validation state contains duplicate ids")
                self._reports[report.validation_id] = report

    @property
    def reports(self) -> tuple[ValidationReport, ...]:
        return tuple(self._reports.values())

    def evaluate(
        self,
        *,
        session_id: str,
        target: str,
        checks: Mapping[str, bool],
    ) -> ValidationReport:
        user = self.auth.require(session_id, Permission.RUN_TESTS)
        target = _safe_text(target, "target")
        if not isinstance(checks, Mapping) or len(checks) > 128:
            raise ValueError("checks are invalid")
        effective: dict[str, bool] = {}
        for name, value in checks.items():
            safe_name = _safe_text(name, "check name")
            if not isinstance(value, bool):
                raise ValueError("check values must be boolean")
            effective[safe_name] = value
        findings = tuple(name for name, passed in effective.items() if not passed)
        state = ValidationState.PASSED if effective and not findings else ValidationState.BLOCKED
        report = ValidationReport(
            validation_id=f"validation-{uuid4()}",
            target=target,
            state=state,
            checks=effective,
            findings=findings or ("all supplied checks passed",),
            executed_real_tests=False,
            created_at=_now(),
        )
        previous = self._reports.get(report.validation_id)
        self._reports[report.validation_id] = report
        try:
            self._persist()
        except Exception:
            if previous is None:
                self._reports.pop(report.validation_id, None)
            else:
                self._reports[report.validation_id] = previous
            raise
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=target,
            action="validation_evaluated",
            risk="MEDIUM",
            authorization="permission:RUN_TESTS",
            result=state.value,
            metadata={"checks": effective, "executed_real_tests": False},
        )
        return report

    def _persist(self) -> None:
        if self.state_store is not None:
            self.state_store.save(_encode_report(report) for report in self._reports.values())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _encode_report(report: ValidationReport) -> dict[str, object]:
    return {
        "validation_id": report.validation_id,
        "target": report.target,
        "state": report.state.value,
        "checks": dict(report.checks),
        "findings": list(report.findings),
        "executed_real_tests": report.executed_real_tests,
        "created_at": report.created_at,
    }


def _decode_report(value: Mapping[str, Any]) -> ValidationReport:
    fields = {
        "validation_id",
        "target",
        "state",
        "checks",
        "findings",
        "executed_real_tests",
        "created_at",
    }
    if set(value) != fields:
        raise ValueError("validation state record is invalid")
    checks = value["checks"]
    findings = value["findings"]
    if not isinstance(checks, dict) or len(checks) > 128:
        raise ValueError("validation state checks are invalid")
    effective: dict[str, bool] = {}
    for name, passed in checks.items():
        safe_name = _safe_text(name, "check name")
        if not isinstance(passed, bool):
            raise ValueError("validation state check value is invalid")
        effective[safe_name] = passed
    if not isinstance(findings, list) or len(findings) > 129:
        raise ValueError("validation state findings are invalid")
    safe_findings = tuple(_safe_text(item, "finding") for item in findings)
    if not isinstance(value["executed_real_tests"], bool) or value["executed_real_tests"]:
        raise ValueError("real test execution is not allowed in validation state")
    state = value["state"]
    expected_state = ValidationState.PASSED if effective and all(effective.values()) else ValidationState.BLOCKED
    if state != expected_state.value:
        raise ValueError("validation state value is invalid")
    expected_findings = tuple(name for name, passed in effective.items() if not passed)
    expected_findings = expected_findings or ("all supplied checks passed",)
    if safe_findings != expected_findings:
        raise ValueError("validation state findings are inconsistent")
    return ValidationReport(
        validation_id=_safe_text(value["validation_id"], "validation_id"),
        target=_safe_text(value["target"], "target"),
        state=expected_state,
        checks=effective,
        findings=safe_findings,
        executed_real_tests=False,
        created_at=_safe_text(value["created_at"], "created_at"),
    )


def _safe_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError(f"{label} is invalid")
    if contains_secret(value) or RAW_STREAM_PATTERN.search(value) or any(ord(char) < 32 for char in value):
        raise ValueError(f"{label} contains unsafe metadata")
    return value.strip()
