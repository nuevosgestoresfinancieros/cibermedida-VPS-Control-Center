from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from control_center.auth import AuthService, Role
from control_center.backups import BackupManager, BackupType
from control_center.deployments import DeploymentManager, DeploymentPlan, DeploymentState
from control_center.filesystem_backup import FilesystemBackupProvider
from control_center.filesystem_release import FilesystemReleaseProvider
from control_center.audit import MetadataAuditLog
from control_center.rollbacks import RollbackManager, RollbackPlan, RollbackState


class FilesystemReleaseProviderTests(unittest.TestCase):
    def test_approved_release_and_rollback_use_declared_temp_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact_root = root / "artifacts"
            release_root = root / "releases"
            backup_source_root = root / "backup-source"
            backup_destination_root = root / "backup-destination"
            artifact_root.mkdir()
            release_root.mkdir()
            backup_source_root.mkdir()
            backup_destination_root.mkdir()
            (artifact_root / "commit-a").mkdir()
            (artifact_root / "commit-b").mkdir()
            (artifact_root / "commit-a" / "app.txt").write_text("version a\n", encoding="utf-8")
            (artifact_root / "commit-b" / "app.txt").write_text("version b\n", encoding="utf-8")
            (backup_source_root / "demo").mkdir()
            (backup_source_root / "demo" / "app.txt").write_text("previous version\n", encoding="utf-8")
            provider = FilesystemReleaseProvider(
                artifact_root=artifact_root,
                release_root=release_root,
            )

            auth = AuthService()
            auth.register_user(
                user_id="release-operator-id",
                username="release-operator",
                password="release-operator-password-123",
                role=Role.OPERATOR,
            )
            auth.register_user(
                user_id="release-admin-id",
                username="release-admin",
                password="release-admin-password-123",
                role=Role.ADMIN,
            )
            operator = auth.login(username="release-operator", password="release-operator-password-123")
            admin = auth.login(username="release-admin", password="release-admin-password-123")
            audit = MetadataAuditLog()
            backups = BackupManager(
                auth=auth,
                audit=audit,
                provider=FilesystemBackupProvider(
                    source_root=backup_source_root,
                    destination_root=backup_destination_root,
                ),
                provider_enabled=True,
            )
            backup = backups.prepare(
                session_id=operator.session_id,
                project="demo",
                backup_type=BackupType.PRE_DEPLOY,
                source_label="demo",
                destination_label="demo-pre-deploy.tar.gz",
            )
            verified_backup = backups.verify(session_id=operator.session_id, backup_id=backup.backup_id)
            deployments = DeploymentManager(
                auth=auth,
                audit=audit,
                backups=backups,
                provider=provider,
                provider_enabled=True,
                post_validator=provider,
            )
            checks = {
                name: True
                for name in (
                    "git",
                    "branch",
                    "tests",
                    "build",
                    "dependencies",
                    "disk",
                    "backup",
                    "backup_verification",
                )
            }
            plan = deployments.prepare(
                session_id=operator.session_id,
                project="demo",
                commit="commit-a",
                checks=checks,
                backup_id=verified_backup.backup_id,
            )
            self.assertEqual(plan.state, DeploymentState.AWAITING_APPROVAL)
            deployments.approve(session_id=admin.session_id, deployment_id=plan.deployment_id)
            deployed = deployments.execute(session_id=operator.session_id, deployment_id=plan.deployment_id)
            self.assertEqual(deployed.state, DeploymentState.VERIFIED)

            rollbacks = RollbackManager(
                auth=auth,
                audit=audit,
                provider=provider,
                provider_enabled=True,
            )
            rollback = rollbacks.prepare(
                session_id=operator.session_id,
                project="demo",
                rollback_type="release",
                target="commit-a",
            )
            rollbacks.approve(session_id=admin.session_id, rollback_id=rollback.rollback_id)
            restored = rollbacks.execute(session_id=operator.session_id, rollback_id=rollback.rollback_id)

            self.assertEqual(restored.state, RollbackState.VERIFIED)
            self.assertEqual((release_root / "demo" / "CURRENT").read_text(encoding="utf-8").strip(), "commit-a")
            self.assertEqual((release_root / "demo" / "commit-a" / "app.txt").read_text(encoding="utf-8"), "version a\n")

    def test_artifact_traversal_and_secret_content_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact_root = root / "artifacts"
            release_root = root / "releases"
            artifact_root.mkdir()
            release_root.mkdir()
            (artifact_root / "unsafe").mkdir()
            (artifact_root / "unsafe" / "config.txt").write_text("token=do-not-store\n", encoding="utf-8")
            provider = FilesystemReleaseProvider(artifact_root=artifact_root, release_root=release_root)

            plan = DeploymentPlan(
                deployment_id="deploy-test",
                project="demo",
                commit="unsafe",
                requested_by="operator",
                state=DeploymentState.APPROVED,
                checks={},
                backup_id="backup",
                approved_by="admin",
                reason="approved",
                created_at="2026-01-01T00:00:00+00:00",
            )
            with self.assertRaises(ValueError):
                provider.deploy(plan=plan)
            with self.assertRaises(ValueError):
                provider.rollback(
                    plan=RollbackPlan(
                        rollback_id="rollback-test",
                        project="../outside",
                        rollback_type="release",
                        target="unsafe",
                        requested_by="operator",
                        approved_by="admin",
                        state=RollbackState.APPROVED,
                        reason="approved",
                        created_at="2026-01-01T00:00:00+00:00",
                    )
                )


if __name__ == "__main__":
    unittest.main()
