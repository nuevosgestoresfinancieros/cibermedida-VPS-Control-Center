"""Safe Codex analysis contracts for the Control Center.

Providers are injected explicitly.  The laboratory provider returns
deterministic metadata; the optional ``CodexCliProvider`` uses a declared
read-only project boundary and never turns analysis output into authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol
from uuid import uuid4

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret

from .audit import MetadataAuditLog
from .auth import AuthService, Permission
from .state import JsonMetadataStore


class CodexAnalysisState(str, Enum):
    COMPLETED = "completed"
    BLOCKED_BY_DEFAULT = "blocked_by_default"
    REJECTED = "rejected"


@dataclass(frozen=True)
class CodexEvidence:
    provider: str
    project: str
    request_kind: str
    summary: str
    findings: tuple[str, ...]
    files_examined: int
    changed_files: int
    duration_ms: int


@dataclass(frozen=True)
class CodexRun:
    run_id: str
    project: str
    request_kind: str
    state: CodexAnalysisState
    provider: str
    live_data: bool
    summary: str
    findings: tuple[str, ...]
    files_examined: int
    changed_files: int
    duration_ms: int
    reason: str
    created_at: str


class CodexProvider(Protocol):
    name: str
    live_data: bool

    def analyze(self, *, project: str, request_kind: str) -> CodexEvidence:
        ...


class SyntheticCodexProvider:
    """Deterministic lab evidence for the Codex integration boundary."""

    name = "codex-synthetic"
    live_data = False

    def analyze(self, *, project: str, request_kind: str) -> CodexEvidence:
        if request_kind not in {"repository", "diagnosis", "impact"}:
            raise ValueError("unsupported Codex request kind")
        return CodexEvidence(
            provider=self.name,
            project=project,
            request_kind=request_kind,
            summary="Análisis sintético preparado; no se leyó ni modificó el repositorio.",
            findings=("scope_verified", "execution_blocked", "human_review_required"),
            files_examined=0,
            changed_files=0,
            duration_ms=1,
        )


class CodexService:
    def __init__(
        self,
        *,
        auth: AuthService,
        audit: MetadataAuditLog,
        provider: CodexProvider | None = None,
        provider_enabled: bool = False,
        state_store: JsonMetadataStore | None = None,
    ) -> None:
        self.auth = auth
        self.audit = audit
        self.provider = provider
        self.provider_enabled = provider_enabled and provider is not None
        self.state_store = state_store
        self._runs: dict[str, CodexRun] = {}
        if self.state_store is not None:
            for raw_run in self.state_store.load():
                run = _decode_run(raw_run)
                if run.run_id in self._runs:
                    raise ValueError("Codex state contains duplicate ids")
                self._runs[run.run_id] = run

    @property
    def runs(self) -> tuple[CodexRun, ...]:
        return tuple(self._runs.values())

    def analyze(self, *, session_id: str, project: str, request_kind: str) -> CodexRun:
        user = self.auth.require(session_id, Permission.VIEW_PROJECTS)
        project = _safe_text(project, "project")
        request_kind = _safe_text(request_kind, "request_kind")
        provider = self.provider
        try:
            provider_name = _safe_text(getattr(provider, "name", "disabled"), "provider")
        except ValueError:
            provider_name = "invalid-provider"
        live_data = bool(getattr(provider, "live_data", False))
        if not self.provider_enabled or provider is None:
            run = self._blocked(project, request_kind, provider_name, live_data, "Codex provider is disabled")
        else:
            try:
                evidence = provider.analyze(project=project, request_kind=request_kind)
                _validate_evidence(evidence, provider_name, project, request_kind)
                run = CodexRun(
                    run_id=f"codex-run-{uuid4()}",
                    project=project,
                    request_kind=request_kind,
                    state=CodexAnalysisState.COMPLETED,
                    provider=provider_name,
                    live_data=live_data,
                    summary=evidence.summary,
                    findings=evidence.findings,
                    files_examined=evidence.files_examined,
                    changed_files=evidence.changed_files,
                    duration_ms=evidence.duration_ms,
                    reason="analysis metadata-only; no repository mutation",
                    created_at=_now(),
                )
            except Exception:
                blocked = self._blocked(project, request_kind, provider_name, live_data, "Codex provider failed safely")
                run = CodexRun(
                    run_id=blocked.run_id,
                    project=blocked.project,
                    request_kind=blocked.request_kind,
                    state=CodexAnalysisState.REJECTED,
                    provider=blocked.provider,
                    live_data=blocked.live_data,
                    summary="",
                    findings=(),
                    files_examined=0,
                    changed_files=0,
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
            project=project,
            action="codex_analysis_completed" if run.state is CodexAnalysisState.COMPLETED else "codex_analysis_blocked",
            risk="LOW",
            authorization="permission:VIEW_PROJECTS",
            result=run.state.value,
            metadata={
                "run_id": run.run_id,
                "provider": run.provider,
                "request_kind": run.request_kind,
                "live_data": run.live_data,
                "files_examined": run.files_examined,
                "changed_files": run.changed_files,
            },
        )
        return run

    def _blocked(self, project: str, request_kind: str, provider: str, live_data: bool, reason: str) -> CodexRun:
        return CodexRun(
            run_id=f"codex-run-{uuid4()}",
            project=project,
            request_kind=request_kind,
            state=CodexAnalysisState.BLOCKED_BY_DEFAULT,
            provider=provider,
            live_data=live_data,
            summary="",
            findings=(),
            files_examined=0,
            changed_files=0,
            duration_ms=0,
            reason=reason,
            created_at=_now(),
        )

    def _persist(self, runs: dict[str, CodexRun]) -> None:
        if self.state_store is not None:
            self.state_store.save(_encode_run(run) for run in runs.values())


def _validate_evidence(value: object, provider: str, project: str, request_kind: str) -> None:
    if not isinstance(value, CodexEvidence):
        raise ValueError("Codex evidence is invalid")
    for item, label in (
        (value.provider, "provider"),
        (value.project, "project"),
        (value.request_kind, "request_kind"),
        (value.summary, "summary"),
    ):
        _safe_text(item, label)
    if value.provider != provider or value.project != project or value.request_kind != request_kind:
        raise ValueError("Codex evidence identity mismatch")
    if (
        not isinstance(value.findings, tuple)
        or len(value.findings) > 64
        or any(not isinstance(item, str) for item in value.findings)
        or any(_unsafe(item) for item in value.findings)
        or any(len(item) > 256 for item in value.findings)
        or any(any(ord(character) < 32 for character in item) for item in value.findings)
        or not isinstance(value.files_examined, int)
        or not 0 <= value.files_examined <= 100_000
        or not isinstance(value.changed_files, int)
        or not 0 <= value.changed_files <= 100_000
        or not isinstance(value.duration_ms, int)
        or not 0 <= value.duration_ms <= 300_000
    ):
        raise ValueError("Codex evidence bounds are invalid")


def _encode_run(run: CodexRun) -> dict[str, object]:
    return {
        "run_id": run.run_id,
        "project": run.project,
        "request_kind": run.request_kind,
        "state": run.state.value,
        "provider": run.provider,
        "live_data": run.live_data,
        "summary": run.summary,
        "findings": list(run.findings),
        "files_examined": run.files_examined,
        "changed_files": run.changed_files,
        "duration_ms": run.duration_ms,
        "reason": run.reason,
        "created_at": run.created_at,
    }


def _decode_run(value: dict[str, object]) -> CodexRun:
    try:
        findings = value["findings"]
        if not isinstance(findings, list):
            raise ValueError("Codex findings must be a list")
        run = CodexRun(
            run_id=_safe_text(value["run_id"], "run_id"),
            project=_safe_text(value["project"], "project"),
            request_kind=_safe_text(value["request_kind"], "request_kind"),
            state=CodexAnalysisState(value["state"]),
            provider=_safe_text(value["provider"], "provider"),
            live_data=value["live_data"],
            summary=_safe_text(value["summary"], "summary") if value["summary"] else "",
            findings=tuple(findings),
            files_examined=value["files_examined"],
            changed_files=value["changed_files"],
            duration_ms=value["duration_ms"],
            reason=_safe_text(value["reason"], "reason"),
            created_at=_safe_text(value["created_at"], "created_at"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Codex state record is invalid") from exc
    if not isinstance(run.live_data, bool):
        raise ValueError("Codex state flags are invalid")
    if run.state is CodexAnalysisState.COMPLETED:
        _validate_evidence(
            CodexEvidence(
                run.provider,
                run.project,
                run.request_kind,
                run.summary,
                run.findings,
                run.files_examined,
                run.changed_files,
                run.duration_ms,
            ),
            run.provider,
            run.project,
            run.request_kind,
        )
    elif run.summary or run.findings or run.files_examined or run.changed_files or run.duration_ms:
        raise ValueError("blocked Codex state contains analysis evidence")
    return run


def _safe_text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 256
        or _unsafe(value)
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{label} is unsafe")
    return value.strip()


def _unsafe(value: str) -> bool:
    return contains_secret(value) or RAW_STREAM_PATTERN.search(value) is not None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
