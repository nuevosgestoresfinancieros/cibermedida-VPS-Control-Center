from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core_operator.approvals import ApprovalStatus, JsonApprovalStore
from core_operator.policy import RiskLevel

from control_center.application import ControlCenterApplication
from control_center.audit import JsonlAuditSink
from control_center.auth import JsonUserStore, Role
from control_center.backups import BackupState, BackupType
from control_center.conversation import ConversationResult
from control_center.deployments import DeploymentState
from control_center.execution import ProviderEvidence, ControlledExecutionState
from control_center.filesystem_backup import FilesystemBackupProvider
from control_center.filesystem_release import FilesystemReleaseProvider
from control_center.incidents import IncidentSeverity, IncidentStatus
from control_center.monitoring import MetricSnapshot, MonitoringCollectionState
from control_center.rollbacks import RollbackState
from control_center.state import JsonMetadataStore
from control_center.validation import ValidatorService
from control_center.v3 import V3InsightsService


class FakeMonitoringProvider:
    name = "fixture-read-safe-monitoring"

    def collect(self) -> MetricSnapshot:
        return MetricSnapshot(
            timestamp="2026-01-01T00:00:00+00:00",
            cpu_percent=24.0,
            memory_percent=31.0,
            disk_percent=42.0,
            load_1m=0.35,
            http_error_rate=0.01,
            service_restarts=0,
        )


class FakeExecutionProvider:
    name = "fixture-controlled-execution"

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def run(self, *, actor: str, action: str, command_id: str) -> ProviderEvidence:
        self.calls.append((actor, action, command_id))
        return ProviderEvidence(provider=self.name, result="read_safe_metadata_accepted", duration_ms=1)


class IntegratedLabWorkflowTests(unittest.TestCase):
    def test_enabled_lab_capabilities_complete_safe_workflows_without_system_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source_root = root / "backup-source"
            destination_root = root / "backup-destination"
            artifact_root = root / "artifacts"
            release_root = root / "releases"
            for directory in (source_root, destination_root, artifact_root, release_root):
                directory.mkdir()

            (source_root / "declared-project").mkdir()
            (source_root / "declared-project" / "README.txt").write_text(
                "safe laboratory metadata\n", encoding="utf-8"
            )
            (artifact_root / "commit-a").mkdir()
            (artifact_root / "commit-a" / "app.txt").write_text("release a\n", encoding="utf-8")

            execution_provider = FakeExecutionProvider()
            app = ControlCenterApplication(
                user_store=JsonUserStore(root / "users.json"),
                audit_sink=JsonlAuditSink(root / "audit.jsonl"),
                approval_store=JsonApprovalStore(root / "approvals.json"),
                backup_provider=FilesystemBackupProvider(
                    source_root=source_root,
                    destination_root=destination_root,
                ),
                backup_state_store=JsonMetadataStore(root / "backups.json"),
                deployment_provider=FilesystemReleaseProvider(
                    artifact_root=artifact_root,
                    release_root=release_root,
                ),
                deployment_validator=FilesystemReleaseProvider(
                    artifact_root=artifact_root,
                    release_root=release_root,
                ),
                deployment_state_store=JsonMetadataStore(root / "deployments.json"),
                rollback_provider=FilesystemReleaseProvider(
                    artifact_root=artifact_root,
                    release_root=release_root,
                ),
                rollback_state_store=JsonMetadataStore(root / "rollbacks.json"),
                execution_provider=execution_provider,
                monitoring_provider=FakeMonitoringProvider(),
                monitoring_state_store=JsonMetadataStore(root / "monitoring.json"),
                incident_state_store=JsonMetadataStore(root / "incidents.json"),
                validation_state_store=JsonMetadataStore(root / "validation.json"),
                v3_state_store=JsonMetadataStore(root / "v3-insights.json"),
                providers_enabled=True,
            )
            app.register_user(
                user_id="lab-operator-id",
                username="lab-operator",
                password="lab-operator-password-123",
                role=Role.OPERATOR,
            )
            app.register_user(
                user_id="lab-admin-id",
                username="lab-admin",
                password="lab-admin-password-123",
                role=Role.ADMIN,
            )
            operator = app.auth.login(username="lab-operator", password="lab-operator-password-123")
            admin = app.auth.login(username="lab-admin", password="lab-admin-password-123")

            capability_states = {status.capability_id: status.state for status in app.capabilities.statuses}
            self.assertEqual(capability_states["authentication"], "persistent")
            self.assertEqual(capability_states["audit"], "persistent")
            self.assertEqual(capability_states["approval_workflow"], "persistent")
            self.assertEqual(capability_states["backups"], "provider_enabled")
            self.assertEqual(capability_states["deployments"], "provider_enabled")
            self.assertEqual(capability_states["rollback"], "provider_enabled")
            self.assertEqual(capability_states["monitoring"], "provider_enabled")
            self.assertEqual(capability_states["controlled_execution"], "provider_enabled")
            capability_live_data = {
                status.capability_id: status.live_data for status in app.capabilities.statuses
            }
            self.assertFalse(capability_live_data["backups"])
            self.assertFalse(capability_live_data["deployments"])
            self.assertFalse(capability_live_data["rollback"])
            self.assertFalse(capability_live_data["monitoring"])
            self.assertFalse(capability_live_data["controlled_execution"])

            chat = app.conversation.handle(session_id=operator.session_id, message="¿Cuál es el estado?")
            self.assertIsInstance(chat, ConversationResult)
            self.assertEqual(chat.intent, "status_read_only")
            self.assertFalse(chat.executable)

            validation = app.validator.evaluate(
                session_id=operator.session_id,
                target="control-center",
                checks={"syntax": True, "tests": True},
            )
            self.assertEqual(validation.state.value, "passed")
            twin = app.v3.register_digital_twin(
                session_id=operator.session_id,
                project="control-center",
                nodes=({"node_id": "web", "kind": "service", "label": "Web", "metadata": {}},),
                relations=(),
            )
            self.assertEqual(twin.state.value, "recorded")
            server = app.v3.register_server(
                session_id=operator.session_id,
                server_id="lab-01",
                label="Laboratorio 01",
                environment="lab",
            )
            self.assertFalse(server.live_data)

            monitoring = app.monitoring.collect()
            self.assertEqual(monitoring.state, MonitoringCollectionState.COLLECTED)
            self.assertEqual(monitoring.anomalies, ())
            self.assertEqual(len(app.monitoring.snapshots), 1)

            backup = app.backups.prepare(
                session_id=operator.session_id,
                project="control-center",
                backup_type=BackupType.PRE_DEPLOY,
                source_label="declared-project",
                destination_label="control-center-pre-deploy.tar.gz",
            )
            verified_backup = app.backups.verify(
                session_id=operator.session_id,
                backup_id=backup.backup_id,
            )
            tested_backup = app.backups.restore_test(
                session_id=operator.session_id,
                backup_id=backup.backup_id,
            )
            self.assertEqual(backup.state, BackupState.PREPARED)
            self.assertEqual(verified_backup.state, BackupState.VERIFIED)
            self.assertEqual(tested_backup.state, BackupState.RESTORE_TESTED)

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
            deployment = app.deployments.prepare(
                session_id=operator.session_id,
                project="control-center",
                commit="commit-a",
                checks=checks,
                backup_id=tested_backup.backup_id,
            )
            self.assertEqual(deployment.state, DeploymentState.AWAITING_APPROVAL)
            app.deployments.approve(session_id=admin.session_id, deployment_id=deployment.deployment_id)
            deployed = app.deployments.execute(
                session_id=operator.session_id,
                deployment_id=deployment.deployment_id,
            )
            self.assertEqual(deployed.state, DeploymentState.VERIFIED)

            rollback = app.rollbacks.prepare(
                session_id=operator.session_id,
                project="control-center",
                rollback_type="release",
                target="commit-a",
            )
            self.assertEqual(rollback.state, RollbackState.AWAITING_APPROVAL)
            app.rollbacks.approve(session_id=admin.session_id, rollback_id=rollback.rollback_id)
            restored = app.rollbacks.execute(
                session_id=operator.session_id,
                rollback_id=rollback.rollback_id,
            )
            self.assertEqual(restored.state, RollbackState.VERIFIED)
            self.assertEqual(
                (release_root / "control-center" / "CURRENT").read_text(encoding="utf-8").strip(),
                "commit-a",
            )

            incident = app.incidents.create(
                session_id=operator.session_id,
                project="control-center",
                service="readonly-api",
                severity=IncidentSeverity.MEDIUM,
                symptom="fixture health signal requires review",
            )
            identified = app.incidents.analyze(
                session_id=operator.session_id,
                incident_id=incident.incident_id,
                hypothesis="no production action is authorized by the lab profile",
            )
            resolved = app.incidents.transition(
                session_id=operator.session_id,
                incident_id=incident.incident_id,
                status=IncidentStatus.RESOLVED,
                note="metadata-only review completed",
            )
            self.assertEqual(identified.status, IncidentStatus.IDENTIFIED)
            self.assertEqual(resolved.status, IncidentStatus.RESOLVED)

            approval = app.approvals.create_pending(
                actor="lab-operator",
                action="read",
                risk_level=RiskLevel.LOW,
                reason="laboratory READ_SAFE execution",
                command_id="system.memory",
            )
            app.approvals.approve(approval.id, decided_by="lab-admin")
            pipeline = app.execution_pipeline.run(
                session_id=operator.session_id,
                action="read",
                command_id="system.memory",
                approval_id=approval.id,
            )
            self.assertEqual(pipeline.plan.state.value, "ready_to_execute")
            self.assertEqual(pipeline.dry_run.state.value, "completed")
            self.assertEqual(pipeline.gate.state.value, "eligible_for_controlled_execution")
            self.assertIsNotNone(pipeline.controlled_execution)
            self.assertEqual(
                pipeline.controlled_execution.state,
                ControlledExecutionState.PROVIDER_COMPLETED,
            )
            self.assertEqual(execution_provider.calls, [("lab-operator", "read", "system.memory")])

            reloaded_approvals = JsonApprovalStore(root / "approvals.json")
            self.assertEqual(reloaded_approvals.get(approval.id).status, ApprovalStatus.APPROVED)
            reloaded_auth = JsonUserStore(root / "users.json")
            self.assertTrue(reloaded_auth.load())
            reloaded_validation = ValidatorService(
                auth=app.auth,
                audit=app.audit,
                state_store=JsonMetadataStore(root / "validation.json"),
            )
            self.assertEqual(len(reloaded_validation.reports), 1)
            reloaded_v3 = V3InsightsService(
                auth=app.auth,
                audit=app.audit,
                state_store=JsonMetadataStore(root / "v3-insights.json"),
            )
            self.assertEqual(len(reloaded_v3.twins), 1)
            self.assertEqual(len(reloaded_v3.servers), 1)
            audit_text = (root / "audit.jsonl").read_text(encoding="utf-8").lower()
            self.assertNotIn("stdout", audit_text)
            self.assertNotIn("stderr", audit_text)
            self.assertNotIn("password=", audit_text)


if __name__ == "__main__":
    unittest.main()
