"""Declared filesystem release provider for an isolated release root.

This provider manages versioned release directories and a ``CURRENT`` pointer
under explicitly declared roots. It never starts services, invokes a shell, or
changes a process manager. The caller marks an instance as live only after an
external activation review.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from .deployments import (
    DeploymentPlan,
    DeploymentProviderEvidence,
    DeploymentValidationEvidence,
)
from .filesystem_backup import (
    _assert_safe_file,
    _declared_directory,
    _is_within,
    _reject_symlink_components,
    _safe_relative,
    _unsafe_path_parts,
)
from .rollbacks import RollbackPlan, RollbackProviderEvidence


class FilesystemReleaseProvider:
    """Publish immutable file releases and switch a declared pointer."""

    name = "declared-filesystem-release"
    live_data = False
    max_files = 10_000
    max_file_bytes = 10 * 1024 * 1024
    max_total_bytes = 256 * 1024 * 1024

    def __init__(
        self,
        *,
        artifact_root: str | Path,
        release_root: str | Path,
        live_data: bool = False,
    ) -> None:
        if not isinstance(live_data, bool):
            raise ValueError("live_data must be boolean")
        self.artifact_root = _declared_directory(Path(artifact_root), "artifact root")
        self.release_root = _declared_directory(Path(release_root), "release root")
        self.live_data = live_data
        if _is_within(self.artifact_root, self.release_root) or _is_within(self.release_root, self.artifact_root):
            raise ValueError("artifact and release roots must be separate")

    def deploy(self, *, plan: DeploymentPlan) -> DeploymentProviderEvidence:
        project = _safe_relative(plan.project, "project")
        commit = _safe_relative(plan.commit, "commit")
        source = self._artifact_path(commit)
        project_directory = self._project_path(project)
        _reject_symlink_components(self.release_root, project)
        project_directory.mkdir(parents=True, exist_ok=True)
        release = project_directory / commit
        if release.exists() or release.is_symlink():
            raise FileExistsError("release already exists")

        with tempfile.TemporaryDirectory(dir=project_directory, prefix=".release-") as temporary_directory:
            stage = Path(temporary_directory) / "release"
            files, total = self._copy_tree(source, stage)
            os.rename(stage, release)
        self._write_current(project_directory, commit.as_posix())

        current = self._read_current(project_directory)
        verified = current == commit.as_posix() and release.is_dir()
        if not verified:
            raise ValueError("release pointer validation failed")
        return DeploymentProviderEvidence(
            provider=self.name,
            result=f"release_ready:{project.as_posix()}:{commit.as_posix()}:{files}:{total}",
            verified=True,
        )

    def validate(
        self,
        *,
        plan: DeploymentPlan,
        deployment: DeploymentProviderEvidence,
    ) -> DeploymentValidationEvidence:
        project = _safe_relative(plan.project, "project")
        commit = _safe_relative(plan.commit, "commit")
        project_directory = self._project_path(project)
        _reject_symlink_components(self.release_root, project)
        release = project_directory / commit
        current = self._read_current(project_directory)
        verified = (
            deployment.provider == self.name
            and deployment.verified
            and release.is_dir()
            and current == commit.as_posix()
        )
        return DeploymentValidationEvidence(
            validator=f"{self.name}-post-check",
            result="release_pointer_and_artifact_validated" if verified else "release_pointer_validation_failed",
            verified=verified,
        )

    def rollback(self, *, plan: RollbackPlan) -> RollbackProviderEvidence:
        project = _safe_relative(plan.project, "project")
        target = _safe_relative(plan.target, "rollback target")
        project_directory = self._project_path(project)
        release = (project_directory / target).resolve(strict=True)
        _reject_symlink_components(self.release_root, project)
        _reject_symlink_components(project_directory, target)
        if not _is_within(release, project_directory) or not release.is_dir():
            raise ValueError("rollback target is not a declared release")
        self._write_current(project_directory, target.as_posix())
        verified = self._read_current(project_directory) == target.as_posix()
        if not verified:
            raise ValueError("rollback pointer validation failed")
        return RollbackProviderEvidence(
            provider=self.name,
            result=f"release_rollback_ready:{project.as_posix()}:{target.as_posix()}",
            verified=True,
        )

    def _artifact_path(self, commit: Path) -> Path:
        candidate = (self.artifact_root / commit).resolve(strict=True)
        _reject_symlink_components(self.artifact_root, commit)
        if not _is_within(candidate, self.artifact_root) or not candidate.is_dir():
            raise ValueError("commit must identify an artifact directory")
        return candidate

    def _project_path(self, project: Path) -> Path:
        if _unsafe_path_parts(project.parts):
            raise ValueError("project path is protected")
        candidate = (self.release_root / project).resolve(strict=False)
        if not _is_within(candidate, self.release_root):
            raise ValueError("project path escapes release root")
        if candidate.exists() and candidate.is_symlink():
            raise ValueError("project path cannot be a symlink")
        return candidate

    def _copy_tree(self, source: Path, destination: Path) -> tuple[int, int]:
        files = 0
        total = 0
        destination.mkdir(parents=True)
        for current, directories, names in os.walk(source, topdown=True, followlinks=False):
            current_path = Path(current)
            safe_directories: list[str] = []
            for name in sorted(directories):
                path = current_path / name
                relative = path.relative_to(source)
                if path.is_symlink() or _unsafe_path_parts(relative.parts):
                    raise ValueError("artifact contains a symlink or protected directory")
                safe_directories.append(name)
            directories[:] = safe_directories
            for name in sorted(names):
                source_path = current_path / name
                relative = source_path.relative_to(source)
                if source_path.is_symlink() or not source_path.is_file() or _unsafe_path_parts(relative.parts):
                    raise ValueError("artifact contains an unsupported file")
                size = source_path.stat().st_size
                if size > self.max_file_bytes or total + size > self.max_total_bytes:
                    raise ValueError("artifact exceeds the configured size limit")
                _assert_safe_file(source_path)
                destination_path = destination / relative
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source_path, destination_path)
                os.chmod(destination_path, 0o600)
                files += 1
                total += size
                if files > self.max_files:
                    raise ValueError("artifact contains too many files")
        return files, total

    @staticmethod
    def _write_current(project_directory: Path, value: str) -> None:
        current = project_directory / "CURRENT"
        if current.is_symlink():
            raise ValueError("CURRENT pointer cannot be a symlink")
        temporary_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=project_directory,
                prefix=".CURRENT.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary_path = handle.name
                os.chmod(handle.name, 0o600)
                handle.write(value + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, current)
            temporary_path = None
        finally:
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except FileNotFoundError:
                    pass

    @staticmethod
    def _read_current(project_directory: Path) -> str:
        current = project_directory / "CURRENT"
        value = current.read_text(encoding="utf-8").strip()
        if not value or "\n" in value or "\r" in value:
            raise ValueError("CURRENT pointer is invalid")
        return value
