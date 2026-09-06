from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from control_center import (
    ActivationManifest,
    ControlCenterApplication,
    FilesystemBackupProvider,
    FilesystemReleaseProvider,
    JsonMetadataStore,
    JsonUserStore,
    JsonlAuditSink,
    OpenAICompatibleChatProvider,
    ReadSafeExecutionProvider,
    ReadSafeInventoryProvider,
    ReadSafeMonitoringProvider,
    Role,
    TotpVerifier,
    evaluate_production_readiness,
)
from core_operator.approvals import JsonApprovalStore


class ReviewedProvider:
    name = "reviewed-provider"
    live_data = True


class ProductionReadinessTests(unittest.TestCase):
    @staticmethod
    def active_manifest() -> ActivationManifest:
        now = datetime.now(timezone.utc)
        return ActivationManifest(
            manifest_id="activation-test-001",
            decision="approved",
            requester="requester",
            requester_role="OPERATOR",
            approver="approver",
            approver_role="ADMIN",
            policy_version="policy-2026-09",
            effective_permissions=(
                "VIEW_CORE_OPERATOR",
                "VIEW_DASHBOARD",
                "VIEW_MONITORING",
                "VIEW_INVENTORY_METADATA",
                "VIEW_BACKUPS",
                "VIEW_PROJECTS",
                "RUN_READ_SAFE",
                "RUN_DIAGNOSTICS",
                "CREATE_BACKUP",
                "APPROVE_OPERATION",
                "DEPLOY",
                "ROLLBACK",
                "RUN_TESTS",
                "RUN_BUILDS",
            ),
            scope=("production-readiness",),
            provider_ids=("reviewed-provider",),
            approved_at=(now - timedelta(minutes=5)).isoformat(),
            expires_at=(now + timedelta(hours=1)).isoformat(),
        )

    def test_complete_declared_graph_can_reach_go_with_external_authorization(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cibermedida-readiness-") as temporary_directory:
            root = Path(temporary_directory)
            stores = {
                name: JsonMetadataStore(root / f"{name}.json")
                for name in (
                    "operations",
                    "backups",
                    "deployments",
                    "rollbacks",
                    "monitoring",
                    "execution",
                    "conversation",
                    "incidents",
                    "inventory",
                "tests",
                    "builds",
                    "codex",
                    "validation",
                    "v3-insights",
                )
            }
            provider = ReviewedProvider()
            application = ControlCenterApplication(
                user_store=JsonUserStore(root / "users.json"),
                audit_sink=JsonlAuditSink(root / "audit.jsonl"),
                approval_store=JsonApprovalStore(root / "approvals.json"),
                operation_state_store=stores["operations"],
                backup_provider=provider,
                backup_state_store=stores["backups"],
                deployment_provider=provider,
                deployment_validator=provider,
                deployment_state_store=stores["deployments"],
                rollback_provider=provider,
                rollback_state_store=stores["rollbacks"],
                monitoring_provider=provider,
                monitoring_state_store=stores["monitoring"],
                execution_provider=provider,
                execution_state_store=stores["execution"],
                inventory_provider=provider,
                inventory_enabled=True,
                inventory_schema_path=None,
                inventory_state_store=stores["inventory"],
                test_provider=provider,
                tests_enabled=True,
                tests_state_store=stores["tests"],
                build_provider=provider,
                builds_enabled=True,
                builds_state_store=stores["builds"],
                codex_provider=provider,
                codex_enabled=True,
                codex_state_store=stores["codex"],
                chat_provider=provider,
                chat_enabled=True,
                conversation_state_store=stores["conversation"],
                incident_state_store=stores["incidents"],
                validation_state_store=stores["validation"],
                v3_state_store=stores["v3-insights"],
                providers_enabled=True,
                otp_verifier=TotpVerifier({"ready-admin-id": "JBSWY3DPEHPK3PXP"}),
            )
            application.register_user(
                user_id="ready-admin-id",
                username="ready-admin",
                password="ready-admin-password-123",
                role=Role.ADMIN,
                requires_2fa=True,
            )

            report = evaluate_production_readiness(
                application,
                secure_cookies=True,
                https_terminated=True,
                activation_manifest=self.active_manifest(),
            )

            self.assertEqual(report.state.value, "GO")
            self.assertFalse(report.blocking_checks)

    def test_concrete_provider_wiring_reaches_go_without_running_operations(self) -> None:
        """Exercise the production composition with isolated fixture roots only."""

        with tempfile.TemporaryDirectory(prefix="cibermedida-concrete-readiness-") as temporary_directory:
            root = Path(temporary_directory)
            source_root = root / "backup-source"
            destination_root = root / "backup-destination"
            artifact_root = root / "artifacts"
            release_root = root / "releases"
            for directory in (source_root, destination_root, artifact_root, release_root):
                directory.mkdir()
            schema_path = Path(__file__).resolve().parents[1] / "schemas" / "inventory.schema.json"

            stores = {
                name: JsonMetadataStore(root / f"{name}.json")
                for name in (
                    "operations",
                    "backups",
                    "deployments",
                    "rollbacks",
                    "monitoring",
                    "execution",
                    "conversation",
                    "incidents",
                    "inventory",
                "tests",
                    "builds",
                    "codex",
                    "validation",
                    "v3-insights",
                )
            }
            chat_provider = OpenAICompatibleChatProvider(
                endpoint="https://chat.example.invalid/v1/chat/completions",
                api_key="fixture-key",
                model="fixture-model",
                transport=lambda _request, _timeout: b"{}",
            )
            application = ControlCenterApplication(
                user_store=JsonUserStore(root / "users.json"),
                audit_sink=JsonlAuditSink(root / "audit.jsonl"),
                approval_store=JsonApprovalStore(root / "approvals.json"),
                operation_state_store=stores["operations"],
                backup_provider=FilesystemBackupProvider(
                    source_root=source_root,
                    destination_root=destination_root,
                    live_data=True,
                ),
                backup_state_store=stores["backups"],
                deployment_provider=FilesystemReleaseProvider(
                    artifact_root=artifact_root,
                    release_root=release_root,
                    live_data=True,
                ),
                deployment_validator=FilesystemReleaseProvider(
                    artifact_root=artifact_root,
                    release_root=release_root,
                    live_data=True,
                ),
                deployment_state_store=stores["deployments"],
                rollback_provider=FilesystemReleaseProvider(
                    artifact_root=artifact_root,
                    release_root=release_root,
                    live_data=True,
                ),
                rollback_state_store=stores["rollbacks"],
                monitoring_provider=ReadSafeMonitoringProvider(executor=object()),
                monitoring_state_store=stores["monitoring"],
                execution_provider=ReadSafeExecutionProvider(executor=object()),
                execution_state_store=stores["execution"],
                inventory_provider=ReadSafeInventoryProvider(schema_path),
                inventory_enabled=True,
                inventory_schema_path=schema_path,
                inventory_state_store=stores["inventory"],
                test_provider=ReviewedProvider(),
                tests_enabled=True,
                tests_state_store=stores["tests"],
                build_provider=ReviewedProvider(),
                builds_enabled=True,
                builds_state_store=stores["builds"],
                codex_provider=ReviewedProvider(),
                codex_enabled=True,
                codex_state_store=stores["codex"],
                chat_provider=chat_provider,
                chat_enabled=True,
                conversation_state_store=stores["conversation"],
                incident_state_store=stores["incidents"],
                validation_state_store=stores["validation"],
                v3_state_store=stores["v3-insights"],
                providers_enabled=True,
                otp_verifier=TotpVerifier({"concrete-admin-id": "JBSWY3DPEHPK3PXP"}),
            )
            application.register_user(
                user_id="concrete-admin-id",
                username="concrete-admin",
                password="concrete-admin-password-123",
                role=Role.ADMIN,
                requires_2fa=True,
            )
            manifest = ActivationManifest(
                **{
                    **self.active_manifest().__dict__,
                    "provider_ids": (
                        "openai-compatible-chat",
                        "declared-filesystem-backup",
                        "declared-filesystem-release",
                        "phase1-read-safe-monitoring",
                        "phase1-read-safe-execution",
                        "phase1-read-safe-inventory",
                        "reviewed-provider",
                    ),
                }
            )

            report = evaluate_production_readiness(
                application,
                secure_cookies=True,
                https_terminated=True,
                activation_manifest=manifest,
            )

            self.assertEqual(report.state.value, "GO")
            self.assertFalse(report.blocking_checks)

    def test_default_graph_is_no_go_without_external_activation(self) -> None:
        application = ControlCenterApplication()

        report = evaluate_production_readiness(
            application,
            secure_cookies=False,
            https_terminated=False,
        )

        self.assertEqual(report.state.value, "NO_GO")
        self.assertIn("human_authorization", {check.check_id for check in report.blocking_checks})
        self.assertIn("chat_provider", {check.check_id for check in report.blocking_checks})

    def test_validation_requires_persistent_report_state(self) -> None:
        report = evaluate_production_readiness(
            ControlCenterApplication(),
            secure_cookies=True,
            https_terminated=True,
        )

        validation_check = next(check for check in report.checks if check.check_id == "validation")
        self.assertFalse(validation_check.passed)
        self.assertIn("persistencia", validation_check.evidence)

    def test_expired_activation_manifest_does_not_authorize_readiness(self) -> None:
        manifest = self.active_manifest()
        expired = ActivationManifest(
            **{
                **manifest.__dict__,
                "expires_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
            }
        )
        report = evaluate_production_readiness(
            ControlCenterApplication(),
            secure_cookies=False,
            activation_manifest=expired,
        )
        self.assertIn("human_authorization", {check.check_id for check in report.blocking_checks})
        human_check = next(check for check in report.checks if check.check_id == "human_authorization")
        self.assertIn("caducado", human_check.evidence)


if __name__ == "__main__":
    unittest.main()
