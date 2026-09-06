"""Bounded test execution contracts for the Control Center.

The default application only evaluates caller-supplied checks.  A repository
test provider must be injected explicitly.  The optional in-process provider
discovers only the repository test directory, accepts only the fixed
"repository" target and stores result metadata without test output.
"""

from __future__ import annotations

import io
import time
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret

from .audit import MetadataAuditLog
from .auth import AuthService, Permission
from .state import JsonMetadataStore


class TestExecutionState(str, Enum):
    COMPLETED = "completed"
    BLOCKED_BY_DEFAULT = "blocked_by_default"
    REJECTED = "rejected"


@dataclass(frozen=True)
class TestEvidence:
    provider: str
    target: str
    passed: bool
    tests_run: int
    failures: int
    duration_ms: int


@dataclass(frozen=True)
class TestRun:
    run_id: str
    target: str
    state: TestExecutionState
    provider: str
    live_data: bool
    passed: bool
    tests_run: int
    failures: int
    duration_ms: int
    reason: str
    created_at: str


class TestProvider(Protocol):
    name: str
    live_data: bool

    def run(self, *, target: str) -> TestEvidence:
        ...


class SyntheticTestProvider:
    """Deterministic test evidence for the isolated laboratory profile."""

    name = "synthetic-tests"
    live_data = False

    def run(self, *, target: str) -> TestEvidence:
        if target != "repository":
            raise ValueError("only the repository target is supported")
        return TestEvidence(
            provider=self.name,
            target=target,
            passed=True,
            tests_run=1,
            failures=0,
            duration_ms=1,
        )


class InProcessTestProvider:
    """Run only the repository unittest suite when explicitly enabled.

    This adapter never starts a shell or accepts a command from the request.
    It is intentionally live-scoped so an activation manifest is required
    outside the laboratory profile.
    """

    name = "repository-tests"
    live_data = True

    def __init__(
        self,
        *,
        project_root: str | Path,
        tests_root: str | Path,
        max_test_cases: int = 512,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.tests_root = Path(tests_root).resolve()
        if not self.tests_root.is_relative_to(self.project_root):
            raise ValueError("tests root must be inside project root")
        if not self.tests_root.is_dir():
            raise ValueError("tests root must exist")
        if not isinstance(max_test_cases, int) or not 1 <= max_test_cases <= 2048:
            raise ValueError("max_test_cases is invalid")
        self.max_test_cases = max_test_cases

    def run(self, *, target: str) -> TestEvidence:
        if target != "repository":
            raise ValueError("only the repository target is supported")
        suite = unittest.defaultTestLoader.discover(
            start_dir=str(self.tests_root),
            pattern="test_*.py",
            top_level_dir=str(self.project_root),
        )
        test_count = suite.countTestCases()
        if test_count < 1 or test_count > self.max_test_cases:
            raise ValueError("repository test count is outside the configured bound")
        started = time.monotonic()
        # The stream is deliberately discarded after the run.  Raw test
        # output never becomes API data or audit metadata.
        result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
        duration_ms = min(300_000, max(0, int((time.monotonic() - started) * 1000)))
        failures = len(result.failures) + len(result.errors)
        return TestEvidence(
            provider=self.name,
            target=target,
            passed=result.wasSuccessful(),
            tests_run=result.testsRun,
            failures=failures,
            duration_ms=duration_ms,
        )


class TestService:
    def __init__(
        self,
        *,
        auth: AuthService,
        audit: MetadataAuditLog,
        provider: TestProvider | None = None,
        provider_enabled: bool = False,
        state_store: JsonMetadataStore | None = None,
    ) -> None:
        self.auth = auth
        self.audit = audit
        self.provider = provider
        self.provider_enabled = provider_enabled and provider is not None
        self.state_store = state_store
        self._runs: dict[str, TestRun] = {}
        if self.state_store is not None:
            for raw_run in self.state_store.load():
                run = _decode_run(raw_run)
                if run.run_id in self._runs:
                    raise ValueError("test state contains duplicate ids")
                self._runs[run.run_id] = run

    @property
    def runs(self) -> tuple[TestRun, ...]:
        return tuple(self._runs.values())

    def run(self, *, session_id: str, target: str) -> TestRun:
        user = self.auth.require(session_id, Permission.RUN_TESTS)
        target = _safe_text(target, "target")
        raw_provider_name = getattr(self.provider, "name", "disabled")
        try:
            provider_name = _safe_text(raw_provider_name, "provider")
        except ValueError:
            provider_name = "invalid-provider"
        live_data = bool(getattr(self.provider, "live_data", False))
        if not self.provider_enabled or self.provider is None:
            run = self._blocked(target, provider_name, live_data, "test provider is disabled")
        else:
            try:
                evidence = self.provider.run(target=target)
                _validate_evidence(evidence, provider_name, target)
                run = TestRun(
                    run_id=f"test-run-{uuid4()}",
                    target=target,
                    state=TestExecutionState.COMPLETED,
                    provider=provider_name,
                    live_data=live_data,
                    passed=evidence.passed,
                    tests_run=evidence.tests_run,
                    failures=evidence.failures,
                    duration_ms=evidence.duration_ms,
                    reason="tests completed; output discarded",
                    created_at=_now(),
                )
            except Exception:
                blocked = self._blocked(
                    target,
                    provider_name,
                    live_data,
                    "test provider failed without raw output",
                )
                run = TestRun(
                    run_id=blocked.run_id,
                    target=blocked.target,
                    state=TestExecutionState.REJECTED,
                    provider=blocked.provider,
                    live_data=blocked.live_data,
                    passed=False,
                    tests_run=0,
                    failures=0,
                    duration_ms=0,
                    reason=blocked.reason,
                    created_at=blocked.created_at,
                )
        updated = dict(self._runs)
        updated[run.run_id] = run
        self._persist(updated)
        self._runs = updated
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=target,
            action="tests_executed" if run.state is TestExecutionState.COMPLETED else "tests_blocked",
            risk="MEDIUM",
            authorization="permission:RUN_TESTS",
            result=run.state.value,
            metadata={
                "run_id": run.run_id,
                "provider": run.provider,
                "live_data": run.live_data,
                "passed": run.passed,
                "tests_run": run.tests_run,
                "failures": run.failures,
            },
        )
        return run

    def _blocked(self, target: str, provider: str, live_data: bool, reason: str) -> TestRun:
        return TestRun(
            run_id=f"test-run-{uuid4()}",
            target=target,
            state=TestExecutionState.BLOCKED_BY_DEFAULT,
            provider=provider,
            live_data=live_data,
            passed=False,
            tests_run=0,
            failures=0,
            duration_ms=0,
            reason=reason,
            created_at=_now(),
        )

    def _persist(self, runs: dict[str, TestRun]) -> None:
        if self.state_store is not None:
            self.state_store.save(_encode_run(run) for run in runs.values())


def _validate_evidence(value: object, provider: str, target: str) -> None:
    if not isinstance(value, TestEvidence):
        raise ValueError("test evidence is invalid")
    _safe_text(value.provider, "provider")
    _safe_text(value.target, "target")
    if value.provider != provider or value.target != target:
        raise ValueError("test evidence identity mismatch")
    if not isinstance(value.passed, bool):
        raise ValueError("test evidence status is invalid")
    if (
        not isinstance(value.tests_run, int)
        or not 1 <= value.tests_run <= 2048
        or not isinstance(value.failures, int)
        or not 0 <= value.failures <= value.tests_run
        or not isinstance(value.duration_ms, int)
        or not 0 <= value.duration_ms <= 300_000
    ):
        raise ValueError("test evidence bounds are invalid")


def _encode_run(run: TestRun) -> dict[str, object]:
    return {
        "run_id": run.run_id,
        "target": run.target,
        "state": run.state.value,
        "provider": run.provider,
        "live_data": run.live_data,
        "passed": run.passed,
        "tests_run": run.tests_run,
        "failures": run.failures,
        "duration_ms": run.duration_ms,
        "reason": run.reason,
        "created_at": run.created_at,
    }


def _decode_run(value: dict[str, object]) -> TestRun:
    try:
        run = TestRun(
            run_id=_safe_text(value["run_id"], "run_id"),
            target=_safe_text(value["target"], "target"),
            state=TestExecutionState(value["state"]),
            provider=_safe_text(value["provider"], "provider"),
            live_data=value["live_data"],
            passed=value["passed"],
            tests_run=value["tests_run"],
            failures=value["failures"],
            duration_ms=value["duration_ms"],
            reason=_safe_text(value["reason"], "reason"),
            created_at=_safe_text(value["created_at"], "created_at"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("test state record is invalid") from exc
    if not isinstance(run.live_data, bool) or not isinstance(run.passed, bool):
        raise ValueError("test state flags are invalid")
    if run.state is TestExecutionState.COMPLETED:
        _validate_evidence(
            TestEvidence(run.provider, run.target, run.passed, run.tests_run, run.failures, run.duration_ms),
            run.provider,
            run.target,
        )
    elif (run.tests_run, run.failures, run.duration_ms) != (0, 0, 0) or run.passed:
        raise ValueError("blocked test state contains execution evidence")
    return run


def _safe_text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 256
        or contains_secret(value)
        or RAW_STREAM_PATTERN.search(value)
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{label} is unsafe")
    return value.strip()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
