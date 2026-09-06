from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from control_center.audit import MetadataAuditLog
from control_center.auth import AuthService, Role
from control_center.backups import BackupManager, BackupState, BackupType
from control_center.filesystem_backup import FilesystemBackupProvider


class FilesystemBackupProviderTests(unittest.TestCase):
    def test_declared_filesystem_backup_lifecycle_uses_only_temp_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source_root = root / "source"
            destination_root = root / "destination"
            project_root = source_root / "declared-project"
            project_root.mkdir(parents=True)
            destination_root.mkdir()
            (project_root / "README.txt").write_text("safe project metadata\n", encoding="utf-8")

            auth = AuthService()
            auth.register_user(
                user_id="backup-admin-id",
                username="backup-admin",
                password="backup-admin-password-123",
                role=Role.ADMIN,
            )
            session = auth.login(username="backup-admin", password="backup-admin-password-123")
            manager = BackupManager(
                auth=auth,
                audit=MetadataAuditLog(),
                provider=FilesystemBackupProvider(
                    source_root=source_root,
                    destination_root=destination_root,
                ),
                provider_enabled=True,
            )

            prepared = manager.prepare(
                session_id=session.session_id,
                project="control-center",
                backup_type=BackupType.MANUAL,
                source_label="declared-project",
                destination_label="control-center.tar.gz",
            )
            verified = manager.verify(session_id=session.session_id, backup_id=prepared.backup_id)
            tested = manager.restore_test(session_id=session.session_id, backup_id=prepared.backup_id)

            self.assertEqual(prepared.state, BackupState.PREPARED)
            self.assertEqual(verified.state, BackupState.VERIFIED)
            self.assertEqual(tested.state, BackupState.RESTORE_TESTED)
            archive = destination_root / "control-center.tar.gz"
            self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(
                "stdout",
                json.dumps([record.__dict__ for record in manager.records], default=str).lower(),
            )

    def test_secret_like_source_content_is_rejected_before_archive_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source_root = root / "source"
            destination_root = root / "destination"
            project_root = source_root / "project"
            project_root.mkdir(parents=True)
            destination_root.mkdir()
            (project_root / "config.txt").write_text("password=do-not-store\n", encoding="utf-8")
            provider = FilesystemBackupProvider(
                source_root=source_root,
                destination_root=destination_root,
            )

            with self.assertRaises(ValueError):
                provider.prepare(
                    project="control-center",
                    backup_type=BackupType.MANUAL,
                    source_label="project",
                    destination_label="unsafe.tar.gz",
                )
            self.assertEqual(list(destination_root.iterdir()), [])

    def test_traversal_and_overwrite_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source_root = root / "source"
            destination_root = root / "destination"
            (source_root / "project").mkdir(parents=True)
            destination_root.mkdir()
            (source_root / "project" / "README.txt").write_text("safe\n", encoding="utf-8")
            provider = FilesystemBackupProvider(
                source_root=source_root,
                destination_root=destination_root,
            )

            with self.assertRaises(ValueError):
                provider.prepare(
                    project="control-center",
                    backup_type=BackupType.MANUAL,
                    source_label="../project",
                    destination_label="escape.tar.gz",
                )
            provider.prepare(
                project="control-center",
                backup_type=BackupType.MANUAL,
                source_label="project",
                destination_label="existing.tar.gz",
            )
            with self.assertRaises(FileExistsError):
                provider.prepare(
                    project="control-center",
                    backup_type=BackupType.MANUAL,
                    source_label="project",
                    destination_label="existing.tar.gz",
                )


if __name__ == "__main__":
    unittest.main()
