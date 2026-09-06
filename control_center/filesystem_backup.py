"""Fail-closed filesystem backup provider for explicitly declared roots.

This adapter is intentionally opt-in. It only archives regular UTF-8 files
under a declared source root into a separate declared destination root. It
does not discover paths, follow symlinks, include protected directories, or
overwrite an existing archive. The caller marks an instance as live only after
an external activation review.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import tarfile
import tempfile
from pathlib import Path

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret

from .backups import BackupProviderEvidence, BackupRecord, BackupType


class FilesystemBackupProvider:
    """Create and validate bounded text-file archives in declared roots."""

    name = "declared-filesystem-backup"
    live_data = False
    max_files = 10_000
    max_file_bytes = 10 * 1024 * 1024
    max_total_bytes = 256 * 1024 * 1024

    def __init__(
        self,
        *,
        source_root: str | Path,
        destination_root: str | Path,
        live_data: bool = False,
    ) -> None:
        if not isinstance(live_data, bool):
            raise ValueError("live_data must be boolean")
        self.source_root = _declared_directory(Path(source_root), "source root")
        self.destination_root = _declared_directory(Path(destination_root), "destination root")
        self.live_data = live_data
        if _is_within(self.destination_root, self.source_root) or _is_within(self.source_root, self.destination_root):
            raise ValueError("source and destination roots must be separate")

    def prepare(
        self,
        *,
        project: str,
        backup_type: BackupType,
        source_label: str,
        destination_label: str,
    ) -> BackupProviderEvidence:
        _safe_text(project, "project")
        if not isinstance(backup_type, BackupType):
            raise ValueError("backup type is invalid")
        source = self._source_path(source_label)
        destination = self._destination_path(destination_label)
        if destination.exists():
            raise FileExistsError("backup destination already exists")

        temporary_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary_path = handle.name
                os.chmod(temporary_path, 0o600)
            file_count, total_bytes = self._write_archive(source, Path(temporary_path))
            os.link(temporary_path, destination)
            os.unlink(temporary_path)
            temporary_path = None
            os.chmod(destination, 0o600)
        finally:
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except FileNotFoundError:
                    pass

        return BackupProviderEvidence(
            provider=self.name,
            checksum=_sha256(destination),
            result=f"archive_created:{file_count}:{total_bytes}",
            verified=False,
        )

    def verify(self, *, record: BackupRecord) -> BackupProviderEvidence:
        archive = self._destination_path(record.destination_label)
        verified = archive.is_file() and _sha256(archive) == record.checksum
        return BackupProviderEvidence(
            provider=self.name,
            checksum=_sha256(archive) if archive.is_file() else "missing",
            result="checksum_verified" if verified else "checksum_mismatch",
            verified=verified,
        )

    def restore_test(self, *, record: BackupRecord) -> BackupProviderEvidence:
        archive = self._destination_path(record.destination_label)
        if not archive.is_file() or _sha256(archive) != record.checksum:
            return BackupProviderEvidence(
                provider=self.name,
                checksum="missing",
                result="restore_source_invalid",
                verified=False,
            )
        with tempfile.TemporaryDirectory(prefix="cibermedida-restore-test-") as temporary_directory:
            extracted_files, extracted_bytes = self._extract_archive(archive, Path(temporary_directory))
        return BackupProviderEvidence(
            provider=self.name,
            checksum=record.checksum,
            result=f"restore_tested:{extracted_files}:{extracted_bytes}",
            verified=True,
        )

    def _source_path(self, source_label: str) -> Path:
        relative = _safe_relative(source_label, "source label")
        candidate = (self.source_root / relative).resolve(strict=True)
        if not _is_within(candidate, self.source_root) or not candidate.is_dir():
            raise ValueError("source label must resolve to a directory under source root")
        _reject_symlink_components(self.source_root, relative)
        return candidate

    def _destination_path(self, destination_label: str) -> Path:
        relative = _safe_relative(destination_label, "destination label")
        if relative.suffixes[-2:] != [".tar", ".gz"]:
            raise ValueError("destination label must end with .tar.gz")
        candidate = (self.destination_root / relative).resolve(strict=False)
        if not _is_within(candidate, self.destination_root):
            raise ValueError("destination label escapes destination root")
        _reject_symlink_components(self.destination_root, relative.parent)
        if candidate.is_symlink():
            raise ValueError("backup destination cannot be a symlink")
        if not candidate.parent.exists() or not candidate.parent.is_dir():
            raise ValueError("backup destination parent must exist")
        return candidate

    def _write_archive(self, source: Path, temporary_path: Path) -> tuple[int, int]:
        file_count = 0
        total_bytes = 0
        with tarfile.open(temporary_path, mode="w:gz", dereference=False) as archive:
            for current, directories, files in os.walk(source, topdown=True, followlinks=False):
                current_path = Path(current)
                safe_directories = []
                for name in sorted(directories):
                    path = current_path / name
                    if path.is_symlink() or _unsafe_path_parts(path.relative_to(source).parts):
                        raise ValueError("backup source contains a symlink or protected directory")
                    safe_directories.append(name)
                directories[:] = safe_directories
                for name in sorted(files):
                    path = current_path / name
                    if path.is_symlink() or not path.is_file():
                        raise ValueError("backup source contains an unsupported file")
                    relative = path.relative_to(source)
                    if _unsafe_path_parts(relative.parts):
                        raise ValueError("backup source contains a protected file")
                    size = path.stat().st_size
                    if size > self.max_file_bytes or total_bytes + size > self.max_total_bytes:
                        raise ValueError("backup source exceeds the configured size limit")
                    _assert_safe_file(path)
                    archive.add(path, arcname=relative.as_posix(), recursive=False)
                    file_count += 1
                    total_bytes += size
                    if file_count > self.max_files:
                        raise ValueError("backup source contains too many files")
        return file_count, total_bytes

    def _extract_archive(self, archive_path: Path, target: Path) -> tuple[int, int]:
        file_count = 0
        total_bytes = 0
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) > self.max_files:
                raise ValueError("backup archive contains too many entries")
            for member in members:
                relative = _safe_archive_member(member.name)
                destination = (target / relative).resolve(strict=False)
                if not _is_within(destination, target):
                    raise ValueError("backup archive contains path traversal")
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile() or member.issym() or member.islnk():
                    raise ValueError("backup archive contains an unsupported entry")
                if member.size > self.max_file_bytes or total_bytes + member.size > self.max_total_bytes:
                    raise ValueError("backup archive exceeds the configured size limit")
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError("backup archive entry cannot be read")
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("wb") as handle:
                    shutil.copyfileobj(source, handle, length=1024 * 1024)
                file_count += 1
                total_bytes += member.size
        return file_count, total_bytes


_CONTROL_PATTERN = re.compile(r"[\x00\r\n]")
_PROTECTED_PARTS = frozenset({".env", ".git", "AGENTS.md", "INVENTORY.json", "logs", "backups"})


def _declared_directory(path: Path, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.exists() or not path.is_dir():
        raise ValueError(f"{label} must be an existing non-symlink directory")
    return path.resolve()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _safe_relative(value: str, label: str) -> Path:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError(f"{label} is invalid")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or _unsafe_path_parts(path.parts):
        raise ValueError(f"{label} is outside the declared root")
    if _CONTROL_PATTERN.search(value):
        raise ValueError(f"{label} contains control characters")
    return path


def _unsafe_path_parts(parts: object) -> bool:
    return any(str(part) in _PROTECTED_PARTS or str(part).startswith(".env") for part in parts)


def _reject_symlink_components(root: Path, relative: Path) -> None:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("backup paths cannot contain symlinks")


def _safe_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError(f"{label} is invalid")
    if contains_secret(value) or RAW_STREAM_PATTERN.search(value) or _CONTROL_PATTERN.search(value):
        raise ValueError(f"{label} contains unsafe metadata")
    return value.strip()


def _assert_safe_file(path: Path) -> None:
    if path.name in _PROTECTED_PARTS or path.name.startswith(".env"):
        raise ValueError("protected files cannot be backed up")
    try:
        content = path.read_bytes()
        text = content.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("backup accepts only readable UTF-8 regular files") from exc
    if contains_secret(text) or RAW_STREAM_PATTERN.search(text):
        raise ValueError("backup source contains secret-like or raw-stream content")


def _safe_archive_member(value: str) -> Path:
    relative = _safe_relative(value, "archive member")
    if _unsafe_path_parts(relative.parts):
        raise ValueError("archive member is protected")
    return relative


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
