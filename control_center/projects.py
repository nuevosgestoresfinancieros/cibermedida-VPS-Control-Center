"""Bounded project and Git metadata integration.

The service accepts only declared project metadata.  The optional live
provider consumes the two Phase 1 READ_SAFE Git commands and stores only a
branch label, dirty flag and validated short commit hash; it never returns
Git output or changes a repository.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret
from phase1_inventory.executor import CommandResult

from .audit import MetadataAuditLog
from .auth import AuthService, Permission
from .state import JsonMetadataStore


class ProjectProvider(Protocol):
    name: str
    live_data: bool

    def collect(self) -> "ProjectEvidence":
        ...


class ProjectCollectionState(str, Enum):
    COLLECTED = "collected"
    BLOCKED_BY_DEFAULT = "blocked_by_default"
    REJECTED = "rejected"


@dataclass(frozen=True)
class ProjectEvidence:
    project_id: str
    name: str
    repository: str
    branch: str
    commit: str
    dirty: bool


@dataclass(frozen=True)
class ProjectRecord:
    project_id: str
    name: str
    repository: str
    branch: str
    commit: str
    dirty: bool
    provider: str
    live_data: bool
    state: ProjectCollectionState
    reason: str
    collected_at: str


class ReadSafeProjectProvider:
    """Read only the allowlisted Git branch/status and HEAD metadata."""

    name = "phase1-read-safe-projects"
    live_data = True

    def __init__(
        self,
        *,
        executor: object,
        project_id: str = "control-center",
        name: str = "Cibermedida VPS Control Center",
        repository: str = "declared-project",
    ) -> None:
        _assert_safe_text(project_id, "project_id", limit=64)
        _assert_safe_text(name, "name", limit=128)
        _assert_safe_text(repository, "repository", limit=128)
        self.executor = executor
        self.project_id = project_id
        self.project_name = name
        self.repository = repository

    def collect(self) -> ProjectEvidence:
        status = _run_read_safe(self.executor, "git.status")
        head = _run_read_safe(self.executor, "git.head_commit").strip()
        if not re.fullmatch(r"[0-9a-fA-F]{7,40}", head):
            raise ValueError("Git HEAD is not a validated short hash")
        lines = status.splitlines()
        if not lines or not lines[0].startswith("## "):
            raise ValueError("Git status has no branch metadata")
        branch = lines[0][3:].split("...", 1)[0].strip()
        _assert_safe_text(branch, "branch", limit=128)
        return ProjectEvidence(
            project_id=self.project_id,
            name=self.project_name,
            repository=self.repository,
            branch=branch,
            commit=head.lower(),
            dirty=any(line.strip() for line in lines[1:]),
        )


class SyntheticProjectProvider:
    """Deterministic project/Git evidence for the isolated lab profile."""

    name = "synthetic-read-safe-projects"
    live_data = False

    def collect(self) -> ProjectEvidence:
        return ProjectEvidence(
            project_id="control-center",
            name="Cibermedida VPS Control Center",
            repository="laboratory-fixture",
            branch="main",
            commit="abcdef123456",
            dirty=False,
        )


class ProjectService:
    def __init__(
        self,
        *,
        auth: AuthService,
        audit: MetadataAuditLog,
        provider: ProjectProvider | None = None,
        provider_enabled: bool = False,
        state_store: JsonMetadataStore | None = None,
    ) -> None:
        self.auth = auth
        self.audit = audit
        self.provider = provider
        self.provider_enabled = provider_enabled and provider is not None
        self.state_store = state_store
        self._records: dict[str, ProjectRecord] = {}
        if self.provider_enabled and self.state_store is not None:
            for raw_record in self.state_store.load():
                record = _decode_record(raw_record)
                if record.project_id in self._records:
                    raise ValueError("project state contains duplicate ids")
                self._records[record.project_id] = record

    @property
    def records(self) -> tuple[ProjectRecord, ...]:
        return tuple(self._records.values())

    def collect(self, *, session_id: str) -> ProjectRecord:
        user = self.auth.require(session_id, Permission.RUN_READ_SAFE)
        provider_name = str(getattr(self.provider, "name", "injected"))
        live_data = bool(getattr(self.provider, "live_data", False))
        if not self.provider_enabled or self.provider is None:
            record = self._blocked_record(provider_name, live_data, "project provider is disabled")
        else:
            try:
                evidence = self.provider.collect()
                _validate_evidence(evidence)
                record = ProjectRecord(
                    project_id=evidence.project_id,
                    name=evidence.name,
                    repository=evidence.repository,
                    branch=evidence.branch,
                    commit=evidence.commit,
                    dirty=evidence.dirty,
                    provider=provider_name,
                    live_data=live_data,
                    state=ProjectCollectionState.COLLECTED,
                    reason="Git metadata validated; no repository mutation performed",
                    collected_at=_now(),
                )
            except Exception:
                record = self._blocked_record(provider_name, live_data, "project provider failed without raw output")
        updated = dict(self._records)
        updated[record.project_id] = record
        if self.state_store is not None and record.state is ProjectCollectionState.COLLECTED:
            self.state_store.save(_encode_record(item) for item in updated.values())
        self._records = updated
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            action="project_metadata_collected",
            risk="LOW",
            authorization="permission:RUN_READ_SAFE",
            result=record.state.value,
            metadata={
                "project_id": record.project_id,
                "provider": record.provider,
                "live_data": record.live_data,
                "dirty": record.dirty,
            },
        )
        return record

    def _blocked_record(self, provider: str, live_data: bool, reason: str) -> ProjectRecord:
        return ProjectRecord(
            project_id="declared-project",
            name="Proyecto no recopilado",
            repository="not-connected",
            branch="not-collected",
            commit="0000000",
            dirty=False,
            provider=provider,
            live_data=live_data,
            state=ProjectCollectionState.BLOCKED_BY_DEFAULT,
            reason=reason,
            collected_at=_now(),
        )


def _run_read_safe(executor: object, command_id: str) -> str:
    execute = getattr(executor, "execute", None)
    if not callable(execute):
        raise ValueError("project executor is invalid")
    result = execute(command_id)
    if not isinstance(result, CommandResult) or result.returncode != 0 or result.timed_out or result.error_code:
        raise ValueError("Git READ_SAFE command failed")
    for value in (result.stdout, result.stderr):
        if not isinstance(value, str) or contains_secret(value) or RAW_STREAM_PATTERN.search(value):
            raise ValueError("Git output is unsafe")
    if not result.stdout.strip():
        raise ValueError("Git output is empty")
    return result.stdout


def _validate_evidence(value: object) -> None:
    if not isinstance(value, ProjectEvidence) or not isinstance(value.dirty, bool):
        raise ValueError("project evidence is invalid")
    for field, limit in (("project_id", 64), ("name", 128), ("repository", 128), ("branch", 128)):
        _assert_safe_text(getattr(value, field), field, limit=limit)
    if not re.fullmatch(r"[0-9a-fA-F]{7,40}", value.commit):
        raise ValueError("project commit is invalid")


def _decode_record(value: dict[str, object]) -> ProjectRecord:
    try:
        record = ProjectRecord(
            project_id=_required(value, "project_id", 64),
            name=_required(value, "name", 128),
            repository=_required(value, "repository", 128),
            branch=_required(value, "branch", 128),
            commit=_required(value, "commit", 40),
            dirty=value["dirty"],
            provider=_required(value, "provider", 128),
            live_data=value["live_data"],
            state=ProjectCollectionState(value["state"]),
            reason=_required(value, "reason", 256),
            collected_at=_required(value, "collected_at", 128),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("project state record is invalid") from exc
    if not isinstance(record.dirty, bool) or not isinstance(record.live_data, bool):
        raise ValueError("project state flags are invalid")
    if not re.fullmatch(r"[0-9a-fA-F]{7,40}|0{7}", record.commit):
        raise ValueError("project state commit is invalid")
    return record


def _encode_record(record: ProjectRecord) -> dict[str, object]:
    return {
        "project_id": record.project_id,
        "name": record.name,
        "repository": record.repository,
        "branch": record.branch,
        "commit": record.commit,
        "dirty": record.dirty,
        "provider": record.provider,
        "live_data": record.live_data,
        "state": record.state.value,
        "reason": record.reason,
        "collected_at": record.collected_at,
    }


def _required(value: dict[str, object], key: str, limit: int) -> str:
    item = value[key]
    _assert_safe_text(item, key, limit=limit)
    return item.strip()


def _assert_safe_text(value: object, field: str, *, limit: int) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > limit
        or contains_secret(value)
        or RAW_STREAM_PATTERN.search(value)
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"project {field} is invalid")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
