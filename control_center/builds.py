"""Bounded build execution behind an explicitly declared provider.

Build commands are configuration, never request data.  The provider accepts a
small allowlist of executable profiles, runs without a shell, and returns only
status and timing metadata.  The service keeps the same authorization,
persistence and audit boundary as the Testing Agent.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Mapping, Protocol, Sequence
from uuid import uuid4

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret

from .audit import MetadataAuditLog
from .auth import AuthService, Permission
from .state import JsonMetadataStore


class BuildExecutionState(str, Enum):
    COMPLETED = "completed"
    BLOCKED_BY_DEFAULT = "blocked_by_default"
    REJECTED = "rejected"


@dataclass(frozen=True)
class BuildEvidence:
    provider: str
    target: str
    passed: bool
    return_code: int
    duration_ms: int


@dataclass(frozen=True)
class BuildRun:
    run_id: str
    target: str
    state: BuildExecutionState
    provider: str
    live_data: bool
    passed: bool
    return_code: int
    duration_ms: int
    reason: str
    created_at: str


class BuildProvider(Protocol):
    name: str
    live_data: bool

    def run(self, *, target: str) -> BuildEvidence:
        ...


class SyntheticBuildProvider:
    """Deterministic build evidence for the isolated laboratory profile."""

    name = "synthetic-builds"
    live_data = False

    def run(self, *, target: str) -> BuildEvidence:
        if not isinstance(target, str) or not target.strip():
            raise ValueError("build target is invalid")
        return BuildEvidence(
            provider=self.name,
            target=target.strip(),
            passed=True,
            return_code=0,
            duration_ms=1,
        )


class DeclaredCommandBuildProvider:
    """Run only commands declared at construction time for named targets.

    This adapter is deliberately not wired by the default server.  A caller
    must provide a project root and a fixed target-to-argv mapping.  The
    request can select a target name, but cannot submit an executable, path or
    shell expression.
    """

    name = "declared-build"
    live_data = True
    _ALLOWED_EXECUTABLES = frozenset(
        {
            "cargo",
            "go",
            "gradle",
            "mvn",
            "node",
            "npm",
            "pnpm",
            "python",
            "python3",
            "pytest",
            "yarn",
        }
    )
    _FORBIDDEN_TOKENS = frozenset(
        {
            "docker",
            "kill",
            "mkfs",
            "reboot",
            "rm",
            "service",
            "shutdown",
            "su" + "do",
            "systemctl",
        }
    )

    def __init__(
        self,
        *,
        project_root: str | Path,
        commands: Mapping[str, Sequence[str]],
        timeout_seconds: float = 300.0,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        if not self.project_root.is_absolute() or not self.project_root.is_dir():
            raise ValueError("project root must be an existing directory")
        if not commands or len(commands) > 16:
            raise ValueError("at least one and at most sixteen build targets are required")
        if timeout_seconds <= 0 or timeout_seconds > 1800:
            raise ValueError("build timeout is invalid")
        self.timeout_seconds = timeout_seconds
        self.commands = {
            self._safe_target(target): self._safe_argv(argv)
            for target, argv in commands.items()
        }

    def run(self, *, target: str) -> BuildEvidence:
        target = self._safe_target(target)
        try:
            argv = self.commands[target]
        except KeyError as exc:
            raise ValueError("build target is not declared") from exc
        started = time.monotonic()
        try:
            completed = subprocess.run(
                argv,
                cwd=self.project_root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("declared build failed safely") from exc
        duration_ms = min(1_800_000, max(0, int((time.monotonic() - started) * 1000)))
        if not isinstance(completed.returncode, int):
            raise ValueError("build returned an invalid status")
        # Output is intentionally inspected only for unsafe content and is
        # never returned, persisted, or written to the audit log.
        for raw_output in (completed.stdout, completed.stderr):
            if isinstance(raw_output, bytes):
                text = raw_output[:1_048_577].decode("utf-8", errors="replace")
                if len(raw_output) > 1_048_576 or contains_secret(text) or RAW_STREAM_PATTERN.search(text):
                    raise ValueError("build output is unsafe")
        return BuildEvidence(
            provider=self.name,
            target=target,
            passed=completed.returncode == 0,
            return_code=completed.returncode,
            duration_ms=duration_ms,
        )

    @classmethod
    def _safe_argv(cls, argv: Sequence[str]) -> tuple[str, ...]:
        if not isinstance(argv, (tuple, list)) or not argv or len(argv) > 32:
            raise ValueError("build command must be a bounded argv sequence")
        normalized = tuple(argv)
        if any(not isinstance(item, str) or not item.strip() or len(item) > 256 for item in normalized):
            raise ValueError("build command contains invalid arguments")
        executable = Path(normalized[0]).name
        if executable not in cls._ALLOWED_EXECUTABLES:
            raise ValueError("build executable is not allowlisted")
        if any(item.casefold() in cls._FORBIDDEN_TOKENS for item in normalized):
            raise ValueError("build command contains a forbidden token")
        if any(contains_secret(item) or RAW_STREAM_PATTERN.search(item) for item in normalized):
            raise ValueError("build command contains unsafe metadata")
        return normalized

    @staticmethod
    def _safe_target(value: object) -> str:
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value) > 128
            or any(character in value for character in "\r\n\x00")
            or contains_secret(value)
            or RAW_STREAM_PATTERN.search(value)
        ):
            raise ValueError("build target is invalid")
        return value.strip()


class BuildService:
    def __init__(
        self,
        *,
        auth: AuthService,
        audit: MetadataAuditLog,
        provider: BuildProvider | None = None,
        provider_enabled: bool = False,
        state_store: JsonMetadataStore | None = None,
    ) -> None:
        self.auth = auth
        self.audit = audit
        self.provider = provider
        self.provider_enabled = provider_enabled and provider is not None
        self.state_store = state_store
        self._runs: dict[str, BuildRun] = {}
        if self.state_store is not None:
            for raw_run in self.state_store.load():
                run = _decode_run(raw_run)
                if run.run_id in self._runs:
                    raise ValueError("build state contains duplicate ids")
                self._runs[run.run_id] = run

    @property
    def runs(self) -> tuple[BuildRun, ...]:
        return tuple(self._runs.values())

    def run(self, *, session_id: str, target: str) -> BuildRun:
        user = self.auth.require(session_id, Permission.RUN_BUILDS)
        target = DeclaredCommandBuildProvider._safe_target(target)
        provider_name = _safe_provider_name(self.provider)
        live_data = bool(getattr(self.provider, "live_data", False))
        if not self.provider_enabled or self.provider is None:
            run = self._blocked(target, provider_name, live_data, "build provider is disabled")
        else:
            try:
                evidence = self.provider.run(target=target)
                _validate_evidence(evidence, provider_name, target)
                run = BuildRun(
                    run_id=f"build-run-{uuid4()}",
                    target=target,
                    state=BuildExecutionState.COMPLETED,
                    provider=provider_name,
                    live_data=live_data,
                    passed=evidence.passed,
                    return_code=evidence.return_code,
                    duration_ms=evidence.duration_ms,
                    reason="build completed; output discarded",
                    created_at=_now(),
                )
            except Exception:
                blocked = self._blocked(target, provider_name, live_data, "build provider failed without raw output")
                run = BuildRun(
                    run_id=blocked.run_id,
                    target=target,
                    state=BuildExecutionState.REJECTED,
                    provider=blocked.provider,
                    live_data=blocked.live_data,
                    passed=False,
                    return_code=0,
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
            action="build_executed" if run.state is BuildExecutionState.COMPLETED else "build_blocked",
            risk="MEDIUM",
            authorization="permission:RUN_BUILDS",
            result=run.state.value,
            metadata={
                "run_id": run.run_id,
                "provider": run.provider,
                "live_data": run.live_data,
                "passed": run.passed,
                "return_code": run.return_code,
                "duration_ms": run.duration_ms,
            },
        )
        return run

    def _blocked(self, target: str, provider: str, live_data: bool, reason: str) -> BuildRun:
        return BuildRun(
            run_id=f"build-run-{uuid4()}",
            target=target,
            state=BuildExecutionState.BLOCKED_BY_DEFAULT,
            provider=provider,
            live_data=live_data,
            passed=False,
            return_code=0,
            duration_ms=0,
            reason=reason,
            created_at=_now(),
        )

    def _persist(self, runs: Mapping[str, BuildRun]) -> None:
        if self.state_store is not None:
            self.state_store.save(_encode_run(run) for run in runs.values())


def _safe_provider_name(provider: object | None) -> str:
    value = getattr(provider, "name", "disabled")
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 128
        or contains_secret(value)
        or RAW_STREAM_PATTERN.search(value)
    ):
        return "invalid-provider"
    return value.strip()


def _validate_evidence(value: object, provider: str, target: str) -> None:
    if not isinstance(value, BuildEvidence):
        raise ValueError("build evidence is invalid")
    if value.provider != provider or value.target != target:
        raise ValueError("build evidence identity mismatch")
    if not isinstance(value.passed, bool) or not isinstance(value.return_code, int) or value.return_code < -1:
        raise ValueError("build evidence status is invalid")
    if not isinstance(value.duration_ms, int) or not 0 <= value.duration_ms <= 1_800_000:
        raise ValueError("build evidence duration is invalid")


def _encode_run(run: BuildRun) -> dict[str, object]:
    return {
        "run_id": run.run_id,
        "target": run.target,
        "state": run.state.value,
        "provider": run.provider,
        "live_data": run.live_data,
        "passed": run.passed,
        "return_code": run.return_code,
        "duration_ms": run.duration_ms,
        "reason": run.reason,
        "created_at": run.created_at,
    }


def _decode_run(value: Mapping[str, object]) -> BuildRun:
    try:
        run = BuildRun(
            run_id=_safe_text(value["run_id"]),
            target=_safe_text(value["target"]),
            state=BuildExecutionState(value["state"]),
            provider=_safe_text(value["provider"]),
            live_data=value["live_data"],
            passed=value["passed"],
            return_code=value["return_code"],
            duration_ms=value["duration_ms"],
            reason=_safe_text(value["reason"]),
            created_at=_safe_text(value["created_at"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("build state record is invalid") from exc
    if (
        not isinstance(run.live_data, bool)
        or not isinstance(run.passed, bool)
        or not isinstance(run.return_code, int)
        or not isinstance(run.duration_ms, int)
        or run.return_code < -1
        or not 0 <= run.duration_ms <= 1_800_000
    ):
        raise ValueError("build state flags are invalid")
    return run


def _safe_text(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 256
        or contains_secret(value)
        or RAW_STREAM_PATTERN.search(value)
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError("build state text is unsafe")
    return value.strip()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
