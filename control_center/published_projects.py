"""Bounded READ_SAFE catalog of applications published below ``/var/www``.

The provider lists only direct child directories and reads directory entry
names for a small allowlist of technology markers. It never opens project
files, follows symlinks, walks recursively, executes Git, or changes files.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Protocol

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret

from .audit import MetadataAuditLog
from .auth import AuthService, Permission


AUTHORIZED_PUBLISHED_ROOT = Path("/var/www")
PROVIDER_NAME = "phase3-read-safe-published-projects"
MAX_PUBLISHED_PROJECTS = 256

_EXCLUDED_DIRECTORY_NAMES = frozenset(
    {
        "backups",
        "cache",
        "logs",
        "node_modules",
        "tmp",
        "__pycache__",
    }
)
_MARKER_NAMES = frozenset(
    {
        ".git",
        "Cargo.toml",
        "Dockerfile",
        "composer.json",
        "compose.yml",
        "docker-compose.yml",
        "go.mod",
        "index.html",
        "manage.py",
        "package.json",
        "public",
        "pyproject.toml",
        "requirements.txt",
        "src",
    }
)


class PublishedProjectProvider(Protocol):
    name: str
    live_data: bool

    def collect(self) -> "PublishedProjectEvidence":
        ...


class PublishedProjectCatalogState(str, Enum):
    COLLECTED = "collected"
    BLOCKED_BY_DEFAULT = "blocked_by_default"


@dataclass(frozen=True)
class PublishedProjectRecord:
    project_id: str
    name: str
    relative_path: str
    kind: str
    markers: tuple[str, ...]
    git_repository: bool
    state: str = "detected"


@dataclass(frozen=True)
class PublishedProjectEvidence:
    root: str
    scope: str
    projects: tuple[PublishedProjectRecord, ...]
    skipped_entries: int
    collected_at: str


@dataclass(frozen=True)
class PublishedProjectCatalogResult:
    state: PublishedProjectCatalogState
    provider: str | None
    live_data: bool
    root: str | None
    scope: str
    projects: tuple[PublishedProjectRecord, ...]
    skipped_entries: int
    reason: str
    collected_at: str


class ReadSafePublishedProjectsProvider:
    """Enumerate direct, non-symlink directories under the authorized root."""

    name = PROVIDER_NAME
    live_data = True

    def __init__(
        self,
        root: str | Path = AUTHORIZED_PUBLISHED_ROOT,
        *,
        allowed_root: str | Path = AUTHORIZED_PUBLISHED_ROOT,
        max_projects: int = MAX_PUBLISHED_PROJECTS,
    ) -> None:
        if not isinstance(max_projects, int) or isinstance(max_projects, bool):
            raise ValueError("max_projects must be an integer")
        if max_projects < 1 or max_projects > MAX_PUBLISHED_PROJECTS:
            raise ValueError("max_projects is outside the safe limit")
        self.root = _validate_root(Path(root), Path(allowed_root))
        self.max_projects = max_projects

    def collect(self) -> PublishedProjectEvidence:
        try:
            entries = sorted(self.root.iterdir(), key=lambda item: item.name.casefold())
        except OSError as exc:
            raise ValueError("published projects root cannot be read") from exc

        projects: list[PublishedProjectRecord] = []
        skipped_entries = 0
        used_ids: set[str] = set()
        for entry in entries:
            if len(projects) >= self.max_projects:
                skipped_entries += 1
                continue
            if _is_excluded(entry.name):
                skipped_entries += 1
                continue
            try:
                if entry.is_symlink() or not entry.is_dir():
                    skipped_entries += 1
                    continue
                resolved_entry = entry.resolve(strict=True)
                if resolved_entry != entry or resolved_entry.parent != self.root:
                    skipped_entries += 1
                    continue
                markers = _read_markers(entry)
            except OSError:
                # Keep the directory visible without exposing the reason or raw
                # filesystem output; marker inspection is best effort only.
                markers = ()
            name = _safe_text(entry.name, "project name", limit=128)
            project_id = _project_id(name, used_ids)
            projects.append(
                PublishedProjectRecord(
                    project_id=project_id,
                    name=name,
                    relative_path=name,
                    kind=_kind_for(markers),
                    markers=markers,
                    git_repository=".git" in markers,
                )
            )

        return PublishedProjectEvidence(
            root=_safe_text(str(self.root), "published root", limit=256),
            scope="direct_children_only",
            projects=tuple(projects),
            skipped_entries=skipped_entries,
            collected_at=_now(),
        )


class PublishedProjectCatalogService:
    """Authorize and audit a live published-project catalog read."""

    def __init__(
        self,
        *,
        auth: AuthService,
        audit: MetadataAuditLog,
        provider: PublishedProjectProvider | None = None,
        provider_enabled: bool = False,
    ) -> None:
        self.auth = auth
        self.audit = audit
        self.provider = provider
        self.provider_enabled = provider_enabled and provider is not None
        self._last: PublishedProjectCatalogResult | None = None

    @property
    def last(self) -> PublishedProjectCatalogResult | None:
        return self._last

    def status(self) -> PublishedProjectCatalogResult:
        if self._last is not None:
            return self._last
        provider_name = str(getattr(self.provider, "name", PROVIDER_NAME)) if self.provider else None
        live_data = bool(self.provider_enabled and getattr(self.provider, "live_data", False))
        return PublishedProjectCatalogResult(
            state=PublishedProjectCatalogState.BLOCKED_BY_DEFAULT,
            provider=provider_name if self.provider_enabled else None,
            live_data=live_data,
            root=str(getattr(self.provider, "root", "")) if self.provider_enabled else None,
            scope="direct_children_only",
            projects=(),
            skipped_entries=0,
            reason=(
                "published project catalog is enabled but has not been collected"
                if self.provider_enabled
                else "published project catalog is disabled"
            ),
            collected_at="",
        )

    def public_status(self) -> PublishedProjectCatalogResult:
        """Return status metadata without exposing catalog records publicly."""
        result = self.status()
        if not result.projects:
            return result
        return replace(
            result,
            projects=(),
            reason="published project catalog is available through the authenticated endpoint",
        )

    def collect(self, *, session_id: str) -> PublishedProjectCatalogResult:
        user = self.auth.require(session_id, Permission.VIEW_PROJECTS)
        provider_name = str(getattr(self.provider, "name", PROVIDER_NAME)) if self.provider else None
        live_data = bool(self.provider_enabled and getattr(self.provider, "live_data", False))
        if not self.provider_enabled or self.provider is None:
            result = PublishedProjectCatalogResult(
                state=PublishedProjectCatalogState.BLOCKED_BY_DEFAULT,
                provider=None,
                live_data=False,
                root=None,
                scope="direct_children_only",
                projects=(),
                skipped_entries=0,
                reason="published project catalog provider is disabled",
                collected_at=_now(),
            )
        else:
            try:
                evidence = self.provider.collect()
                _validate_evidence(evidence)
                result = PublishedProjectCatalogResult(
                    state=PublishedProjectCatalogState.COLLECTED,
                    provider=provider_name,
                    live_data=live_data,
                    root=evidence.root,
                    scope=evidence.scope,
                    projects=evidence.projects,
                    skipped_entries=evidence.skipped_entries,
                    reason="direct project metadata collected; no files were opened or changed",
                    collected_at=evidence.collected_at,
                )
            except Exception:
                result = PublishedProjectCatalogResult(
                    state=PublishedProjectCatalogState.BLOCKED_BY_DEFAULT,
                    provider=provider_name,
                    live_data=live_data,
                    root=str(getattr(self.provider, "root", "")) or None,
                    scope="direct_children_only",
                    projects=(),
                    skipped_entries=0,
                    reason="published project catalog failed closed without raw filesystem output",
                    collected_at=_now(),
                )
        self._last = result
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            action="published_project_catalog_read",
            risk="LOW",
            authorization="permission:VIEW_PROJECTS",
            result=result.state.value,
            metadata={
                "provider": result.provider or "disabled",
                "root": result.root or "not_configured",
                "scope": result.scope,
                "project_count": len(result.projects),
                "skipped_entries": result.skipped_entries,
                "live_data": result.live_data,
            },
        )
        return result


def _validate_root(root: Path, allowed_root: Path) -> Path:
    if not root.is_absolute() or root.is_symlink():
        raise ValueError("published projects root must be an absolute non-symlink directory")
    if not allowed_root.is_absolute() or allowed_root.is_symlink():
        raise ValueError("published projects allowed root is invalid")
    try:
        resolved = root.resolve(strict=True)
        allowed = allowed_root.resolve(strict=True)
    except OSError as exc:
        raise ValueError("published projects root cannot be resolved") from exc
    if resolved != allowed or not resolved.is_dir():
        raise ValueError("published projects root must be exactly /var/www")
    if ".git" in resolved.parts or any(part.startswith(".env") for part in resolved.parts):
        raise ValueError("published projects root is protected")
    if any(part.casefold() in {"logs", "backups"} for part in resolved.parts):
        raise ValueError("published projects root cannot be inside logs or backups")
    return resolved


def _is_excluded(name: str) -> bool:
    return name.startswith(".") or name.casefold() in _EXCLUDED_DIRECTORY_NAMES


def _read_markers(entry: Path) -> tuple[str, ...]:
    try:
        names = {child.name for child in entry.iterdir()}
    except OSError:
        return ()
    return tuple(sorted(name for name in names if name in _MARKER_NAMES))


def _kind_for(markers: tuple[str, ...]) -> str:
    if "package.json" in markers:
        return "node"
    if "pyproject.toml" in markers or "requirements.txt" in markers or "manage.py" in markers:
        return "python"
    if "composer.json" in markers:
        return "php"
    if "Cargo.toml" in markers:
        return "rust"
    if "go.mod" in markers:
        return "go"
    if "index.html" in markers or "public" in markers:
        return "web"
    if ".git" in markers:
        return "git"
    return "directory"


def _project_id(name: str, used_ids: set[str]) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip(".-").lower() or "project"
    base = f"published-{slug}"[:120]
    candidate = base
    suffix = 2
    while candidate in used_ids:
        candidate = f"{base[: max(1, 119 - len(str(suffix)))]}-{suffix}"
        suffix += 1
    used_ids.add(candidate)
    return candidate


def _validate_evidence(evidence: PublishedProjectEvidence) -> None:
    if not isinstance(evidence, PublishedProjectEvidence):
        raise ValueError("published project evidence is invalid")
    _safe_text(evidence.root, "published root", limit=256)
    if evidence.scope != "direct_children_only":
        raise ValueError("published project scope is invalid")
    if not isinstance(evidence.skipped_entries, int) or evidence.skipped_entries < 0:
        raise ValueError("published skipped entry count is invalid")
    if len(evidence.projects) > MAX_PUBLISHED_PROJECTS:
        raise ValueError("published project count exceeds the safe limit")
    seen_ids: set[str] = set()
    for project in evidence.projects:
        if not isinstance(project, PublishedProjectRecord):
            raise ValueError("published project record is invalid")
        _safe_text(project.project_id, "project id", limit=128)
        _safe_text(project.name, "project name", limit=128)
        _safe_text(project.relative_path, "relative path", limit=128)
        _safe_text(project.kind, "project kind", limit=32)
        if project.project_id in seen_ids or project.relative_path != project.name:
            raise ValueError("published project identity is invalid")
        seen_ids.add(project.project_id)
        if not isinstance(project.markers, tuple) or any(marker not in _MARKER_NAMES for marker in project.markers):
            raise ValueError("published project markers are invalid")
        if not isinstance(project.git_repository, bool) or not isinstance(project.state, str):
            raise ValueError("published project flags are invalid")


def _safe_text(value: object, field: str, *, limit: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > limit
        or contains_secret(value)
        or RAW_STREAM_PATTERN.search(value)
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{field} is unsafe")
    return value.strip()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
