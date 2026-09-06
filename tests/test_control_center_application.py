from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from core_operator.policy import PolicyEngine

from control_center.audit import JsonlAuditSink, MetadataAuditLog
from control_center.application import ControlCenterApplication
from control_center.analysis import (
    ChangeManager,
    ConfigurationDriftService,
    ContractState,
    ImpactAnalysisService,
    KnowledgeService,
)
from control_center.agents import AgentManager
from control_center.auth import AuthService, CSRFError, JsonUserStore, Permission, Role, TotpVerifier
from control_center.backups import BackupManager, BackupProviderEvidence, BackupState, BackupType
from control_center.conversation import ConversationService, ProviderChatResult
from control_center.deployments import (
    DeploymentManager,
    DeploymentProviderEvidence,
    DeploymentState,
    DeploymentValidationEvidence,
)
from control_center.execution import (
    ControlledExecutionService,
    ControlledExecutionState,
    ProviderEvidence,
)
from control_center.incidents import IncidentManager, IncidentSeverity, IncidentStatus
from control_center.monitoring import (
    MetricSnapshot,
    MonitoringCollectionState,
    MonitoringService,
)
from control_center.operations import OperationService, OperationState
from control_center.pipeline import ExecutionPipelineService
from control_center.rollbacks import RollbackManager, RollbackProviderEvidence, RollbackState
from control_center.state import JsonMetadataStore
from control_center.validation import ValidationState
from control_center.validation import ValidatorService
from core_operator.approvals import ApprovalStatus, InMemoryApprovalStore, JsonApprovalStore
from core_operator.execution_gate import ExecutionGateDecision, ExecutionGateState
from core_operator.policy import RiskLevel


class ControlCenterFixture:
    def __init__(self) -> None:
        self.auth = AuthService(otp_verifier=lambda _user, otp: otp == "123456")
        self.auth.register_user(
            user_id="operator-id",
            username="operator",
            password="operator-password-123",
            role=Role.OPERATOR,
        )
        self.auth.register_user(
            user_id="admin-id",
            username="admin",
            password="admin-password-123",
            role=Role.ADMIN,
        )
        self.auth.register_user(
            user_id="viewer-id",
            username="viewer",
            password="viewer-password-123",
            role=Role.VIEWER,
        )
        self.auth.register_user(
            user_id="developer-id",
            username="developer",
            password="developer-password-123",
            role=Role.DEVELOPER,
        )
        self.operator = self.auth.login(username="operator", password="operator-password-123")
        self.admin = self.auth.login(username="admin", password="admin-password-123")
        self.viewer = self.auth.login(username="viewer", password="viewer-password-123")
        self.developer = self.auth.login(username="developer", password="developer-password-123")
        self.audit = MetadataAuditLog()
        self.approvals = InMemoryApprovalStore()
        self.backups = BackupManager(auth=self.auth, audit=self.audit)
        self.operations = OperationService(
            auth=self.auth,
            policy=PolicyEngine(),
            approvals=self.approvals,
            audit=self.audit,
            backups=self.backups,
        )
        self.deployments = DeploymentManager(auth=self.auth, audit=self.audit, backups=self.backups)
        self.rollbacks = RollbackManager(auth=self.auth, audit=self.audit)
        self.conversation = ConversationService(auth=self.auth, audit=self.audit)
        self.incidents = IncidentManager(auth=self.auth, audit=self.audit)
        self.validator = ValidatorService(auth=self.auth, audit=self.audit)
        self.knowledge = KnowledgeService(auth=self.auth, audit=self.audit)
        self.impact = ImpactAnalysisService(auth=self.auth, audit=self.audit)
        self.drift = ConfigurationDriftService(auth=self.auth, audit=self.audit)
        self.agents = AgentManager(auth=self.auth, audit=self.audit)
        self.changes = ChangeManager(auth=self.auth, audit=self.audit)


class AuthAndAuditTests(unittest.TestCase):
    def test_explicit_identity_and_audit_persistence_survive_reload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            user_path = root / "users.json"
            audit_path = root / "audit.jsonl"
            auth = AuthService(user_store=JsonUserStore(user_path))
            auth.register_user(
                user_id="persistent-viewer-id",
                username="persistent-viewer",
                password="persistent-password-123",
                role=Role.VIEWER,
            )
            serialized_users = user_path.read_text(encoding="utf-8")
            self.assertNotIn("persistent-password-123", serialized_users)

            reloaded = AuthService(user_store=JsonUserStore(user_path))
            session = reloaded.login(username="persistent-viewer", password="persistent-password-123")
            self.assertEqual(reloaded.user_for_session(session.session_id).role, Role.VIEWER)

            audit = MetadataAuditLog(sink=JsonlAuditSink(audit_path))
            audit.append(
                user_id="persistent-viewer-id",
                actor="persistent-viewer",
                role="VIEWER",
                action="viewed_status",
                result="ok",
            )
            records = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(records[0]["action"], "viewed_status")
            self.assertNotIn("stdout", audit_path.read_text(encoding="utf-8").lower())
            reloaded_audit = MetadataAuditLog(sink=JsonlAuditSink(audit_path))
            self.assertEqual(len(reloaded_audit.records), 1)
            self.assertEqual(reloaded_audit.records[0].action, "viewed_status")

    def test_conversation_history_survives_reload_with_redacted_content(self) -> None:
        fixture = ControlCenterFixture()
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_store = JsonMetadataStore(Path(temporary_directory) / "conversation.json")
            service = ConversationService(
                auth=fixture.auth,
                audit=fixture.audit,
                state_store=state_store,
            )
            result = service.handle(
                session_id=fixture.operator.session_id,
                message="Como esta el sistema?",
            )
            reloaded = ConversationService(
                auth=fixture.auth,
                audit=fixture.audit,
                state_store=JsonMetadataStore(state_store.path),
            )
            self.assertEqual(len(reloaded.messages), 2)
            self.assertEqual(reloaded.messages[0].role, "user")
            self.assertEqual(reloaded.messages[1].message_id, result.message_id)
            serialized = state_store.path.read_text(encoding="utf-8").lower()
            self.assertNotIn("stdout", serialized)
            self.assertNotIn("stderr", serialized)

    def test_provider_enablement_is_scoped_to_each_capability(self) -> None:
        class BackupOnlyProvider:
            name = "backup-only"

        application = ControlCenterApplication(
            backup_provider=BackupOnlyProvider(),
            providers_enabled=True,
        )

        self.assertTrue(application.backups.provider_enabled)
        self.assertFalse(application.monitoring.provider_enabled)
        self.assertFalse(application.execution.enabled)
        self.assertFalse(application.deployments.provider_enabled)
        self.assertFalse(application.rollbacks.provider_enabled)
        states = {status.capability_id: status.state for status in application.capabilities.statuses}
        self.assertEqual(states["backups"], "provider_enabled")
        self.assertEqual(states["monitoring"], "snapshot_only")
        self.assertEqual(states["controlled_execution"], "blocked_by_default")

    def test_approval_persistence_survives_reload_without_storing_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "approvals.json"
            store = JsonApprovalStore(path)
            pending = store.create_pending(
                actor="operator",
                actor_role="OPERATOR",
                action="read",
                risk_level=RiskLevel.MEDIUM,
                reason="independent review required",
                command_id="system.ports",
                policy_version="phase-3.6",
                effective_permissions=("RUN_READ_SENSITIVE", "VIEW_AUDIT_METADATA"),
                resource="command:system.ports",
                plan_id="plan-persisted-001",
            )
            store.approve(pending.id, decided_by="admin", decided_by_role="ADMIN", reason="reviewed")

            serialized = path.read_text(encoding="utf-8")
            self.assertNotIn("password", serialized.lower())
            self.assertNotIn("stdout", serialized.lower())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

            reloaded = JsonApprovalStore(path)
            request = reloaded.get(pending.id)
            self.assertEqual(request.status, ApprovalStatus.APPROVED)
            self.assertEqual(request.decided_by, "admin")
            self.assertEqual(request.decided_by_role, "ADMIN")
            self.assertEqual(request.policy_version, "phase-3.6")
            self.assertEqual(request.plan_id, "plan-persisted-001")

    def test_approval_persistence_rejects_unsafe_serialized_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "approvals.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "requests": [
                            {
                                "id": "approval-unsafe",
                                "timestamp": "2026-01-01T00:00:00+00:00",
                                "actor": "operator",
                                "action": "read",
                                "risk_level": "MEDIUM",
                                "command_id": "system.ports",
                                "reason": "password=must-not-load",
                                "status": "pending",
                                "decided_by": None,
                                "decided_at": None,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                JsonApprovalStore(path)

    def test_operator_has_the_documented_privileged_permission_name(self) -> None:
        fixture = ControlCenterFixture()
        user = fixture.auth.user_for_session(fixture.operator.session_id)
        self.assertIn(Permission.RUN_PRIVILEGED, user.permissions)
        self.assertNotIn("RUN_READ_PRIVILEGED", {permission.value for permission in user.permissions})

    def test_csrf_is_required_for_state_changing_workflows(self) -> None:
        fixture = ControlCenterFixture()
        with self.assertRaises(CSRFError):
            fixture.auth.require_csrf(fixture.operator.session_id, "wrong-token")
        self.assertEqual(
            fixture.auth.require_csrf(fixture.operator.session_id, fixture.operator.csrf_token).username,
            "operator",
        )

    def test_two_factor_is_checked_when_enabled(self) -> None:
        auth = AuthService(otp_verifier=lambda _user, otp: otp == "123456")
        auth.register_user(
            user_id="two-factor-id",
            username="secure-user",
            password="secure-password-123",
            role=Role.VIEWER,
            requires_2fa=True,
        )
        with self.assertRaises(ValueError):
            auth.login(username="secure-user", password="secure-password-123")
        session = auth.login(username="secure-user", password="secure-password-123", otp="123456")
        self.assertEqual(auth.user_for_session(session.session_id).username, "secure-user")

    def test_totp_secret_can_be_injected_after_identity_creation_without_persistence(self) -> None:
        verifier = TotpVerifier({}, clock=lambda: 59, allowed_steps=0)
        auth = AuthService(otp_verifier=verifier)
        user = auth.register_user(
            user_id="bootstrap-totp-id",
            username="bootstrap-totp",
            password="bootstrap-totp-password-123",
            role=Role.VIEWER,
            requires_2fa=True,
        )
        self.assertEqual(auth.user_for_username("bootstrap-totp"), user)
        verifier.register_secret(user.user_id, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        session = auth.login(username="bootstrap-totp", password="bootstrap-totp-password-123", otp="287082")
        self.assertEqual(auth.user_for_session(session.session_id).username, "bootstrap-totp")

    def test_totp_verifier_accepts_rfc6238_vector_without_persisting_seed(self) -> None:
        verifier = TotpVerifier(
            {"totp-user-id": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"},
            clock=lambda: 59,
            allowed_steps=0,
        )
        auth = AuthService(otp_verifier=verifier)
        auth.register_user(
            user_id="totp-user-id",
            username="totp-user",
            password="totp-password-123",
            role=Role.VIEWER,
            requires_2fa=True,
        )
        with self.assertRaises(ValueError):
            auth.login(username="totp-user", password="totp-password-123", otp="000000")
        session = auth.login(username="totp-user", password="totp-password-123", otp="287082")
        self.assertEqual(auth.user_for_session(session.session_id).username, "totp-user")

    def test_audit_rejects_raw_streams_and_secret_like_values(self) -> None:
        audit = MetadataAuditLog()
        with self.assertRaises(ValueError):
            audit.append(
                user_id="user",
                actor="operator",
                role="OPERATOR",
                action="unsafe",
                result="blocked",
                metadata={"value": "password=do-not-store"},
            )
        with self.assertRaises(ValueError):
            audit.append(
                user_id="user",
                actor="operator",
                role="OPERATOR",
                action="unsafe",
                result="blocked",
                metadata={"value": "stdout=raw output"},
            )


class ControlledExecutionBoundaryTests(unittest.TestCase):
    def test_execution_pipeline_rechecks_every_gate_and_stops_at_disabled_executor(self) -> None:
        fixture = ControlCenterFixture()
        approval = fixture.approvals.create_pending(
            actor="operator",
            action="read",
            risk_level=RiskLevel.LOW,
            reason="approved read-safe pipeline test",
            command_id="system.memory",
        )
        fixture.approvals.approve(approval.id, decided_by="admin")
        service = ExecutionPipelineService(
            auth=fixture.auth,
            policy=PolicyEngine(),
            approvals=fixture.approvals,
            audit=fixture.audit,
            controlled_execution=ControlledExecutionService(auth=fixture.auth, audit=fixture.audit),
        )
        result = service.run(
            session_id=fixture.operator.session_id,
            action="read",
            command_id="system.memory",
            approval_id=approval.id,
        )
        self.assertEqual(result.plan.state.value, "ready_to_execute")
        self.assertEqual(result.dry_run.state.value, "completed")
        self.assertEqual(result.gate.state.value, "eligible_for_controlled_execution")
        self.assertIsNotNone(result.controlled_execution)
        self.assertEqual(result.controlled_execution.state, ControlledExecutionState.BLOCKED_BY_DEFAULT)

    def test_read_safe_pipeline_uses_read_safe_permission_not_deploy(self) -> None:
        fixture = ControlCenterFixture()
        approval = fixture.approvals.create_pending(
            actor="developer",
            action="read",
            risk_level=RiskLevel.LOW,
            reason="approved read-safe developer pipeline test",
            command_id="system.memory",
        )
        fixture.approvals.approve(approval.id, decided_by="admin")
        service = ExecutionPipelineService(
            auth=fixture.auth,
            policy=PolicyEngine(),
            approvals=fixture.approvals,
            audit=fixture.audit,
            controlled_execution=ControlledExecutionService(auth=fixture.auth, audit=fixture.audit),
        )

        result = service.run(
            session_id=fixture.developer.session_id,
            action="read",
            command_id="system.memory",
            approval_id=approval.id,
        )

        self.assertEqual(result.gate.state.value, "eligible_for_controlled_execution")
        self.assertEqual(result.controlled_execution.state, ControlledExecutionState.BLOCKED_BY_DEFAULT)

    def test_read_sensitive_pipeline_does_not_fall_back_to_read_safe_permission(self) -> None:
        fixture = ControlCenterFixture()
        approval = fixture.approvals.create_pending(
            actor="developer",
            action="read",
            risk_level=RiskLevel.MEDIUM,
            reason="sensitive read remains gated",
            command_id="system.ports",
        )
        fixture.approvals.approve(approval.id, decided_by="admin")
        service = ExecutionPipelineService(
            auth=fixture.auth,
            policy=PolicyEngine(),
            approvals=fixture.approvals,
            audit=fixture.audit,
            controlled_execution=ControlledExecutionService(auth=fixture.auth, audit=fixture.audit),
        )

        with self.assertRaises(PermissionError):
            service.run(
                session_id=fixture.developer.session_id,
                action="read",
                command_id="system.ports",
                approval_id=approval.id,
            )

    @staticmethod
    def eligible_decision(**overrides) -> ExecutionGateDecision:
        values = {
            "state": ExecutionGateState.ELIGIBLE_FOR_CONTROLLED_EXECUTION,
            "actor": "operator",
            "action": "read",
            "command_id": "system.memory",
            "risk_level": RiskLevel.LOW,
            "approval_id": "approval-1",
            "reason": "eligible for controlled execution",
        }
        values.update(overrides)
        return ExecutionGateDecision(**values)

    def test_eligible_decision_is_blocked_without_a_provider(self) -> None:
        fixture = ControlCenterFixture()
        service = ControlledExecutionService(auth=fixture.auth, audit=fixture.audit)
        record = service.request(session_id=fixture.admin.session_id, decision=self.eligible_decision())
        self.assertEqual(record.state, ControlledExecutionState.BLOCKED_BY_DEFAULT)
        self.assertEqual(service.records, (record,))
        self.assertIn("blocked_by_default", str(fixture.audit.records[-1]))

    def test_noneligible_decision_is_rejected(self) -> None:
        fixture = ControlCenterFixture()
        service = ControlledExecutionService(auth=fixture.auth, audit=fixture.audit)
        decision = self.eligible_decision(state=ExecutionGateState.BLOCKED)
        record = service.request(session_id=fixture.admin.session_id, decision=decision)
        self.assertEqual(record.state, ControlledExecutionState.REJECTED)
        self.assertNotIn("stdout", str(fixture.audit.records).lower())
        self.assertNotIn("stderr", str(fixture.audit.records).lower())

    def test_controlled_provider_rejects_non_read_safe_eligible_decisions(self) -> None:
        fixture = ControlCenterFixture()

        class FakeProvider:
            name = "must-not-run"

            def __init__(self) -> None:
                self.calls = 0

            def run(self, **_kwargs) -> ProviderEvidence:
                self.calls += 1
                return ProviderEvidence(provider=self.name, result="completed")

        provider = FakeProvider()
        service = ControlledExecutionService(
            auth=fixture.auth,
            audit=fixture.audit,
            provider=provider,
            enabled=True,
        )
        decision = self.eligible_decision(action="read", command_id="system.ports", risk_level=RiskLevel.MEDIUM)
        record = service.request(session_id=fixture.admin.session_id, decision=decision)
        self.assertEqual(record.state, ControlledExecutionState.REJECTED)
        self.assertEqual(provider.calls, 0)

    def test_secret_metadata_is_redacted_before_recording(self) -> None:
        fixture = ControlCenterFixture()
        service = ControlledExecutionService(auth=fixture.auth, audit=fixture.audit)
        decision = self.eligible_decision(approval_id="token=password=do-not-store")
        record = service.request(session_id=fixture.admin.session_id, decision=decision)
        serialized = f"{record}{fixture.audit.records}".lower()
        self.assertEqual(record.state, ControlledExecutionState.REJECTED)
        self.assertNotIn("do-not-store", serialized)
        self.assertNotIn("password=", serialized)

    def test_explicit_metadata_provider_is_validated_and_is_not_default(self) -> None:
        fixture = ControlCenterFixture()

        class FakeProvider:
            name = "test-metadata-provider"

            def __init__(self) -> None:
                self.calls = 0

            def run(self, *, actor: str, action: str, command_id: str) -> ProviderEvidence:
                self.calls += 1
                return ProviderEvidence(provider=self.name, result="completed", duration_ms=4)

        provider = FakeProvider()
        service = ControlledExecutionService(
            auth=fixture.auth,
            audit=fixture.audit,
            provider=provider,
            enabled=True,
        )
        record = service.request(session_id=fixture.admin.session_id, decision=self.eligible_decision())
        self.assertEqual(record.state, ControlledExecutionState.PROVIDER_COMPLETED)
        self.assertEqual(provider.calls, 1)

        invalid = ControlledExecutionService(
            auth=fixture.auth,
            audit=fixture.audit,
            provider=type(
                "UnsafeProvider",
                (),
                {
                    "name": "unsafe-provider",
                    "run": lambda self, **_kwargs: ProviderEvidence(
                        provider="unsafe-provider", result="stdout=raw output"
                    ),
                },
            )(),
            enabled=True,
        )
        rejected = invalid.request(session_id=fixture.admin.session_id, decision=self.eligible_decision())
        self.assertEqual(rejected.state, ControlledExecutionState.REJECTED)

    def test_execution_metadata_survives_reload_without_raw_output(self) -> None:
        fixture = ControlCenterFixture()
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_store = JsonMetadataStore(Path(temporary_directory) / "execution.json")
            service = ControlledExecutionService(
                auth=fixture.auth,
                audit=fixture.audit,
                state_store=state_store,
            )
            record = service.request(
                session_id=fixture.admin.session_id,
                decision=self.eligible_decision(),
            )
            reloaded = ControlledExecutionService(
                auth=fixture.auth,
                audit=fixture.audit,
                state_store=JsonMetadataStore(state_store.path),
            )
            self.assertEqual(reloaded.records, (record,))
            serialized = state_store.path.read_text(encoding="utf-8").lower()
            self.assertNotIn("stdout", serialized)
            self.assertNotIn("stderr", serialized)


class OperationWorkflowTests(unittest.TestCase):
    def test_operation_plans_survive_reload_and_keep_policy_snapshot(self) -> None:
        fixture = ControlCenterFixture()
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_store = JsonMetadataStore(Path(temporary_directory) / "operations.json")
            service = OperationService(
                auth=fixture.auth,
                policy=PolicyEngine(),
                approvals=fixture.approvals,
                audit=fixture.audit,
                backups=fixture.backups,
                state_store=state_store,
            )
            plan = service.plan(
                session_id=fixture.operator.session_id,
                project="control-center",
                action="deploy",
            )
            reloaded = OperationService(
                auth=fixture.auth,
                policy=PolicyEngine(),
                approvals=fixture.approvals,
                audit=fixture.audit,
                backups=fixture.backups,
                state_store=JsonMetadataStore(state_store.path),
            )
            self.assertEqual(reloaded.plans, (plan,))
            approved = reloaded.approve(
                session_id=fixture.admin.session_id,
                plan_id=plan.plan_id,
            )
            final = OperationService(
                auth=fixture.auth,
                policy=PolicyEngine(),
                approvals=fixture.approvals,
                audit=fixture.audit,
                backups=fixture.backups,
                state_store=JsonMetadataStore(state_store.path),
            )
            self.assertEqual(final.plans, (approved,))
            self.assertEqual(approved.policy_version, "phase-3.6")
            serialized = state_store.path.read_text(encoding="utf-8").lower()
            self.assertNotIn("stdout", serialized)
            self.assertNotIn("stderr", serialized)

    def test_sensitive_operation_requires_independent_approval_and_backup(self) -> None:
        fixture = ControlCenterFixture()
        plan = fixture.operations.plan(
            session_id=fixture.operator.session_id,
            project="control-center",
            action="deploy",
        )
        self.assertEqual(plan.state, OperationState.APPROVAL_REQUIRED)
        self.assertIsNotNone(plan.approval_id)
        with self.assertRaises(PermissionError):
            fixture.operations.approve(
                session_id=fixture.operator.session_id,
                plan_id=plan.plan_id,
            )
        approved = fixture.operations.approve(
            session_id=fixture.admin.session_id,
            plan_id=plan.plan_id,
        )
        self.assertEqual(approved.state, OperationState.APPROVED)
        backup = fixture.backups.prepare(
            session_id=fixture.operator.session_id,
            project="control-center",
            backup_type=BackupType.PRE_DEPLOY,
            source_label="controlled-provider",
            destination_label="approved-destination",
        )
        fixture.backups.verify(session_id=fixture.operator.session_id, backup_id=backup.backup_id)
        ready = fixture.operations.attach_verified_backup(
            session_id=fixture.admin.session_id,
            plan_id=plan.plan_id,
            backup_id=backup.backup_id,
        )
        self.assertEqual(ready.state, OperationState.READY)
        blocked = fixture.operations.execute(
            session_id=fixture.admin.session_id,
            plan_id=ready.plan_id,
        )
        self.assertEqual(blocked.state, OperationState.BLOCKED_BY_DEFAULT)

    def test_denied_or_unknown_operation_cannot_become_pending_approval(self) -> None:
        fixture = ControlCenterFixture()
        plan = fixture.operations.plan(
            session_id=fixture.operator.session_id,
            project="control-center",
            action="unknown-operation",
        )
        self.assertEqual(plan.policy_decision, "deny")
        self.assertEqual(plan.state, OperationState.REJECTED)
        self.assertIsNone(plan.approval_id)

    def test_read_safe_plan_is_non_mutating_and_read_sensitive_requires_approval(self) -> None:
        fixture = ControlCenterFixture()
        safe = fixture.operations.plan(
            session_id=fixture.operator.session_id,
            project="control-center",
            action="read",
            command_id="system.memory",
        )
        self.assertEqual(safe.state, OperationState.PLANNED)
        sensitive = fixture.operations.plan(
            session_id=fixture.operator.session_id,
            project="control-center",
            action="read",
            command_id="system.ports",
        )
        self.assertEqual(sensitive.state, OperationState.APPROVAL_REQUIRED)


class BackupDeploymentRollbackTests(unittest.TestCase):
    def test_backup_deployment_and_rollback_metadata_survive_reload(self) -> None:
        fixture = ControlCenterFixture()
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            backup_store = JsonMetadataStore(root / "backups.json")
            deployment_store = JsonMetadataStore(root / "deployments.json")
            rollback_store = JsonMetadataStore(root / "rollbacks.json")

            backup_manager = BackupManager(
                auth=fixture.auth,
                audit=fixture.audit,
                state_store=backup_store,
            )
            backup = backup_manager.prepare(
                session_id=fixture.operator.session_id,
                project="control-center",
                backup_type=BackupType.PRE_DEPLOY,
                source_label="source",
                destination_label="destination",
            )
            backup_manager.verify(session_id=fixture.operator.session_id, backup_id=backup.backup_id)

            reloaded_backups = BackupManager(
                auth=fixture.auth,
                audit=fixture.audit,
                state_store=JsonMetadataStore(root / "backups.json"),
            )
            self.assertTrue(reloaded_backups.is_verified(backup.backup_id))

            deployment_manager = DeploymentManager(
                auth=fixture.auth,
                audit=fixture.audit,
                backups=reloaded_backups,
                state_store=deployment_store,
            )
            checks = {name: True for name in ("git", "branch", "tests", "build", "dependencies", "disk", "backup", "backup_verification")}
            deployment = deployment_manager.prepare(
                session_id=fixture.operator.session_id,
                project="control-center",
                commit="abc123",
                checks=checks,
                backup_id=backup.backup_id,
            )
            reloaded_deployments = DeploymentManager(
                auth=fixture.auth,
                audit=fixture.audit,
                backups=reloaded_backups,
                state_store=JsonMetadataStore(root / "deployments.json"),
            )
            self.assertEqual(reloaded_deployments.plans[0].deployment_id, deployment.deployment_id)

            rollback_manager = RollbackManager(
                auth=fixture.auth,
                audit=fixture.audit,
                state_store=rollback_store,
            )
            rollback = rollback_manager.prepare(
                session_id=fixture.operator.session_id,
                project="control-center",
                rollback_type="previous_verified_release",
                target="release-mock",
            )
            reloaded_rollbacks = RollbackManager(
                auth=fixture.auth,
                audit=fixture.audit,
                state_store=JsonMetadataStore(root / "rollbacks.json"),
            )
            self.assertEqual(reloaded_rollbacks.plans[0].rollback_id, rollback.rollback_id)

    def test_deployment_provider_cannot_bypass_real_backup_provider(self) -> None:
        fixture = ControlCenterFixture()

        class DeploymentProvider:
            name = "test-deployment-provider"

            def deploy(self, **_kwargs) -> DeploymentProviderEvidence:
                return DeploymentProviderEvidence(self.name, "must-not-run", verified=True)

        deployment_manager = DeploymentManager(
            auth=fixture.auth,
            audit=fixture.audit,
            backups=fixture.backups,
            provider=DeploymentProvider(),
            provider_enabled=True,
        )
        simulated_backup = fixture.backups.prepare(
            session_id=fixture.operator.session_id,
            project="control-center",
            backup_type=BackupType.PRE_DEPLOY,
            source_label="simulated-source",
            destination_label="simulated-destination",
        )
        simulated_backup = fixture.backups.verify(
            session_id=fixture.operator.session_id,
            backup_id=simulated_backup.backup_id,
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
        plan = deployment_manager.prepare(
            session_id=fixture.operator.session_id,
            project="control-center",
            commit="abc123",
            checks=checks,
            backup_id=simulated_backup.backup_id,
        )
        deployment_manager.approve(session_id=fixture.admin.session_id, deployment_id=plan.deployment_id)
        blocked = deployment_manager.execute(
            session_id=fixture.operator.session_id,
            deployment_id=plan.deployment_id,
        )
        self.assertEqual(blocked.state, DeploymentState.BLOCKED)
        self.assertIn("verified backup provider", blocked.reason)

    def test_explicit_providers_run_only_after_approval_and_return_verified_metadata(self) -> None:
        fixture = ControlCenterFixture()

        class FakeBackupProvider:
            name = "test-backup-provider"

            def prepare(self, **_kwargs) -> BackupProviderEvidence:
                return BackupProviderEvidence(self.name, "checksum-mock", "prepared")

            def verify(self, **_kwargs) -> BackupProviderEvidence:
                return BackupProviderEvidence(self.name, "checksum-mock", "verified", verified=True)

            def restore_test(self, **_kwargs) -> BackupProviderEvidence:
                return BackupProviderEvidence(self.name, "checksum-mock", "restore-tested", verified=True)

        class FakeDeploymentProvider:
            name = "test-deployment-provider"

            def deploy(self, **_kwargs) -> DeploymentProviderEvidence:
                return DeploymentProviderEvidence(self.name, "deployment-validated", verified=True)

        class FakeDeploymentValidator:
            name = "test-deployment-validator"

            def validate(self, **_kwargs) -> DeploymentValidationEvidence:
                return DeploymentValidationEvidence(self.name, "post-validation-validated", verified=True)

        class FakeRollbackProvider:
            name = "test-rollback-provider"

            def rollback(self, **_kwargs) -> RollbackProviderEvidence:
                return RollbackProviderEvidence(self.name, "rollback-validated", verified=True)

        backup_manager = BackupManager(
            auth=fixture.auth,
            audit=fixture.audit,
            provider=FakeBackupProvider(),
            provider_enabled=True,
        )
        backup = backup_manager.prepare(
            session_id=fixture.operator.session_id,
            project="control-center",
            backup_type=BackupType.PRE_DEPLOY,
            source_label="controlled-provider",
            destination_label="approved-destination",
        )
        verified = backup_manager.verify(session_id=fixture.operator.session_id, backup_id=backup.backup_id)
        tested = backup_manager.restore_test(session_id=fixture.operator.session_id, backup_id=backup.backup_id)
        self.assertEqual(verified.state, BackupState.VERIFIED)
        self.assertEqual(tested.state, BackupState.RESTORE_TESTED)

        deployment_manager = DeploymentManager(
            auth=fixture.auth,
            audit=fixture.audit,
            backups=backup_manager,
            provider=FakeDeploymentProvider(),
            provider_enabled=True,
            post_validator=FakeDeploymentValidator(),
        )
        checks = {name: True for name in ("git", "branch", "tests", "build", "dependencies", "disk", "backup", "backup_verification")}
        deployment = deployment_manager.prepare(
            session_id=fixture.operator.session_id,
            project="control-center",
            commit="abc123",
            checks=checks,
            backup_id=backup.backup_id,
        )
        deployment_manager.approve(session_id=fixture.admin.session_id, deployment_id=deployment.deployment_id)
        deployed = deployment_manager.execute(session_id=fixture.admin.session_id, deployment_id=deployment.deployment_id)
        self.assertEqual(deployed.state, DeploymentState.VERIFIED)
        with self.assertRaises(ValueError):
            deployment_manager.execute(
                session_id=fixture.admin.session_id,
                deployment_id=deployment.deployment_id,
            )

        rollback_manager = RollbackManager(
            auth=fixture.auth,
            audit=fixture.audit,
            provider=FakeRollbackProvider(),
            provider_enabled=True,
        )
        rollback = rollback_manager.prepare(
            session_id=fixture.operator.session_id,
            project="control-center",
            rollback_type="previous_verified_release",
            target="release-mock",
        )
        rollback_manager.approve(session_id=fixture.admin.session_id, rollback_id=rollback.rollback_id)
        rolled_back = rollback_manager.execute(session_id=fixture.admin.session_id, rollback_id=rollback.rollback_id)
        self.assertEqual(rolled_back.state, RollbackState.VERIFIED)
        with self.assertRaises(ValueError):
            rollback_manager.execute(
                session_id=fixture.admin.session_id,
                rollback_id=rollback.rollback_id,
            )

    def test_deployment_fails_closed_when_post_validation_is_not_verified(self) -> None:
        fixture = ControlCenterFixture()

        class FakeBackupProvider:
            name = "test-backup-provider"

            def prepare(self, **_kwargs) -> BackupProviderEvidence:
                return BackupProviderEvidence(self.name, "checksum-mock", "prepared")

            def verify(self, **_kwargs) -> BackupProviderEvidence:
                return BackupProviderEvidence(self.name, "checksum-mock", "verified", verified=True)

            def restore_test(self, **_kwargs) -> BackupProviderEvidence:
                return BackupProviderEvidence(self.name, "checksum-mock", "restore-tested", verified=True)

        class FakeDeploymentProvider:
            name = "test-deployment-provider"

            def deploy(self, **_kwargs) -> DeploymentProviderEvidence:
                return DeploymentProviderEvidence(self.name, "release-created", verified=True)

        class RejectingValidator:
            name = "test-post-validator"

            def validate(self, **_kwargs) -> DeploymentValidationEvidence:
                return DeploymentValidationEvidence(self.name, "health-check-failed", verified=False)

        backup_manager = BackupManager(
            auth=fixture.auth,
            audit=fixture.audit,
            provider=FakeBackupProvider(),
            provider_enabled=True,
        )
        backup = backup_manager.prepare(
            session_id=fixture.operator.session_id,
            project="control-center",
            backup_type=BackupType.PRE_DEPLOY,
            source_label="controlled-provider",
            destination_label="post-validation-destination",
        )
        backup_manager.verify(session_id=fixture.operator.session_id, backup_id=backup.backup_id)
        manager = DeploymentManager(
            auth=fixture.auth,
            audit=fixture.audit,
            backups=backup_manager,
            provider=FakeDeploymentProvider(),
            provider_enabled=True,
            post_validator=RejectingValidator(),
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
        plan = manager.prepare(
            session_id=fixture.operator.session_id,
            project="control-center",
            commit="abc123",
            checks=checks,
            backup_id=backup.backup_id,
        )
        manager.approve(session_id=fixture.admin.session_id, deployment_id=plan.deployment_id)
        failed = manager.execute(session_id=fixture.operator.session_id, deployment_id=plan.deployment_id)
        self.assertEqual(failed.state, DeploymentState.FAILED)
        self.assertEqual(failed.reason, "post-deployment validation failed")

    def test_backup_lifecycle_is_metadata_only(self) -> None:
        fixture = ControlCenterFixture()
        prepared = fixture.backups.prepare(
            session_id=fixture.operator.session_id,
            project="control-center",
            backup_type=BackupType.PRE_DEPLOY,
            source_label="controlled-provider",
            destination_label="approved-destination",
        )
        self.assertEqual(prepared.state, BackupState.PREPARED)
        verified = fixture.backups.verify(session_id=fixture.operator.session_id, backup_id=prepared.backup_id)
        tested = fixture.backups.restore_test(session_id=fixture.operator.session_id, backup_id=prepared.backup_id)
        self.assertEqual(verified.state, BackupState.VERIFIED)
        self.assertEqual(tested.state, BackupState.RESTORE_TESTED)
        self.assertEqual(len(fixture.backups.records), 1)

    def test_deployment_requires_all_preflight_checks_and_stays_blocked(self) -> None:
        fixture = ControlCenterFixture()
        checks = {
            name: True
            for name in ("git", "branch", "tests", "build", "dependencies", "disk", "backup", "backup_verification")
        }
        plan = fixture.deployments.prepare(
            session_id=fixture.operator.session_id,
            project="control-center",
            commit="abc123",
            checks=checks,
            backup_id=self._verified_backup(fixture),
        )
        self.assertEqual(plan.state, DeploymentState.AWAITING_APPROVAL)
        approved = fixture.deployments.approve(
            session_id=fixture.admin.session_id,
            deployment_id=plan.deployment_id,
        )
        self.assertEqual(approved.state, DeploymentState.APPROVED)
        blocked = fixture.deployments.execute(
            session_id=fixture.admin.session_id,
            deployment_id=plan.deployment_id,
        )
        self.assertEqual(blocked.state, DeploymentState.BLOCKED)

    @staticmethod
    def _verified_backup(fixture: ControlCenterFixture) -> str:
        backup = fixture.backups.prepare(
            session_id=fixture.operator.session_id,
            project="control-center",
            backup_type=BackupType.PRE_DEPLOY,
            source_label="controlled-provider",
            destination_label="approved-destination",
        )
        fixture.backups.verify(session_id=fixture.operator.session_id, backup_id=backup.backup_id)
        return backup.backup_id

    def test_rollback_requires_independent_approval_and_never_executes(self) -> None:
        fixture = ControlCenterFixture()
        plan = fixture.rollbacks.prepare(
            session_id=fixture.operator.session_id,
            project="control-center",
            rollback_type="previous_verified_release",
            target="release-mock",
        )
        self.assertEqual(plan.state, RollbackState.AWAITING_APPROVAL)
        with self.assertRaises(PermissionError):
            fixture.rollbacks.approve(
                session_id=fixture.operator.session_id,
                rollback_id=plan.rollback_id,
            )
        approved = fixture.rollbacks.approve(
            session_id=fixture.admin.session_id,
            rollback_id=plan.rollback_id,
        )
        self.assertEqual(approved.state, RollbackState.APPROVED)
        with self.assertRaises(ValueError):
            fixture.rollbacks.approve(
                session_id=fixture.admin.session_id,
                rollback_id=plan.rollback_id,
            )
        blocked = fixture.rollbacks.execute(
            session_id=fixture.admin.session_id,
            rollback_id=plan.rollback_id,
        )
        self.assertEqual(blocked.state, RollbackState.BLOCKED)
        with self.assertRaises(ValueError):
            fixture.rollbacks.approve(
                session_id=fixture.admin.session_id,
                rollback_id=plan.rollback_id,
            )


class ConversationMonitoringIncidentTests(unittest.TestCase):
    def test_monitoring_and_incident_metadata_survive_reload(self) -> None:
        fixture = ControlCenterFixture()
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            monitoring = MonitoringService(
                state_store=JsonMetadataStore(root / "monitoring.json"),
            )
            snapshot = MetricSnapshot(
                timestamp="2026-09-05T10:00:00+00:00",
                cpu_percent=95.0,
                memory_percent=30.0,
                disk_percent=40.0,
                load_1m=0.5,
            )
            monitoring.record(snapshot)
            reloaded_monitoring = MonitoringService(
                state_store=JsonMetadataStore(root / "monitoring.json"),
            )
            self.assertEqual(reloaded_monitoring.latest(), snapshot)
            self.assertEqual(reloaded_monitoring.anomalies(), ("cpu_high",))

            incidents = IncidentManager(
                auth=fixture.auth,
                audit=fixture.audit,
                state_store=JsonMetadataStore(root / "incidents.json"),
            )
            incident = incidents.create(
                session_id=fixture.operator.session_id,
                project="control-center",
                service="read-safe-monitoring",
                severity=IncidentSeverity.HIGH,
                symptom="cpu_high metadata anomaly",
                detected_by="read-safe-monitoring",
            )
            reloaded_incidents = IncidentManager(
                auth=fixture.auth,
                audit=fixture.audit,
                state_store=JsonMetadataStore(root / "incidents.json"),
            )
            self.assertEqual(reloaded_incidents.incidents[0].incident_id, incident.incident_id)

    def test_monitoring_collection_is_blocked_without_an_explicit_provider(self) -> None:
        monitoring = MonitoringService()
        result = monitoring.collect()
        self.assertEqual(result.state, MonitoringCollectionState.BLOCKED_BY_DEFAULT)
        self.assertIsNone(result.snapshot)

    def test_monitoring_provider_must_return_bounded_metadata(self) -> None:
        class SafeProvider:
            name = "test-monitoring-provider"

            def collect(self) -> MetricSnapshot:
                return MetricSnapshot(
                    timestamp="2026-09-05T10:00:00+00:00",
                    cpu_percent=12.5,
                    memory_percent=30.0,
                    disk_percent=40.0,
                    load_1m=0.5,
                )

        service = MonitoringService(provider=SafeProvider(), provider_enabled=True)
        result = service.collect()
        self.assertEqual(result.state, MonitoringCollectionState.COLLECTED)
        self.assertEqual(result.provider, "test-monitoring-provider")
        self.assertIsNotNone(result.snapshot)

        class UnsafeProvider:
            name = "unsafe-monitoring-provider"

            def collect(self) -> MetricSnapshot:
                return MetricSnapshot(
                    timestamp="stdout=raw output",
                    cpu_percent=1.0,
                    memory_percent=1.0,
                    disk_percent=1.0,
                    load_1m=0.1,
                )

        rejected = MonitoringService(provider=UnsafeProvider(), provider_enabled=True).collect()
        self.assertEqual(rejected.state, MonitoringCollectionState.REJECTED)
        self.assertIsNone(rejected.snapshot)

    def test_explicit_chat_provider_is_sandboxed_to_a_non_executable_plan(self) -> None:
        fixture = ControlCenterFixture()

        class FakeProvider:
            name = "test-ai-provider"

            def generate(self, *, message: str, role: str) -> ProviderChatResult:
                return ProviderChatResult(
                    intent="provider_intent",
                    risk="HIGH",
                    requires_approval=False,
                    response="Propuesta generada para revisión humana.",
                    plan=("interpretar", "solicitar aprobación"),
                )

        service = ConversationService(
            auth=fixture.auth,
            audit=fixture.audit,
            provider=FakeProvider(),
            ai_enabled=True,
        )
        result = service.handle(session_id=fixture.operator.session_id, message="prepara un plan")
        self.assertEqual(result.intent, "provider_intent")
        self.assertEqual(result.risk, "HIGH")
        self.assertTrue(result.requires_approval)
        self.assertFalse(result.executable)

    def test_conversation_plans_high_risk_requests_without_execution(self) -> None:
        fixture = ControlCenterFixture()
        result = fixture.conversation.handle(
            session_id=fixture.operator.session_id,
            message="prepara un despliegue del proyecto",
        )
        self.assertTrue(result.requires_approval)
        self.assertFalse(result.executable)
        self.assertIn("bloquear ejecución real", " ".join(result.plan))

    def test_monitoring_detects_anomalies_in_memory(self) -> None:
        monitoring = MonitoringService()
        snapshot = monitoring.record(
            MetricSnapshot(
                timestamp="2026-01-01T00:00:00+00:00",
                cpu_percent=95.0,
                memory_percent=91.0,
                disk_percent=20.0,
                load_1m=3.0,
                http_error_rate=0.2,
                service_restarts=12,
            )
        )
        self.assertEqual(monitoring.latest(), snapshot)
        self.assertEqual(
            monitoring.anomalies(),
            ("cpu_high", "memory_high", "http_error_rate_high", "service_restarts_high"),
        )

    def test_incident_lifecycle_is_audited_without_operational_records(self) -> None:
        fixture = ControlCenterFixture()
        incident = fixture.incidents.create(
            session_id=fixture.operator.session_id,
            project="control-center",
            service="web-shell",
            severity=IncidentSeverity.MEDIUM,
            symptom="mock health degraded",
        )
        investigating = fixture.incidents.transition(
            session_id=fixture.operator.session_id,
            incident_id=incident.incident_id,
            status=IncidentStatus.INVESTIGATING,
            note="review metadata-only health result",
        )
        resolved = fixture.incidents.transition(
            session_id=fixture.operator.session_id,
            incident_id=incident.incident_id,
            status=IncidentStatus.RESOLVED,
            note="no production action taken",
            resolution="validated metadata-only recovery",
            rollback="rollback plan remains unexecuted",
        )
        self.assertEqual(investigating.status, IncidentStatus.INVESTIGATING)
        self.assertEqual(resolved.status, IncidentStatus.RESOLVED)
        self.assertIsNotNone(resolved.closed_at)
        self.assertEqual(resolved.resolution, "validated metadata-only recovery")
        self.assertEqual(resolved.rollback, "rollback plan remains unexecuted")
        self.assertGreaterEqual(len(fixture.audit.records), 3)
        serialized = str(fixture.audit.records).lower()
        self.assertNotIn("stdout=", serialized)
        self.assertNotIn("stderr=", serialized)

        identified = fixture.incidents.analyze(
            session_id=fixture.operator.session_id,
            incident_id=incident.incident_id,
            hypothesis="mock health metadata requires review",
            evidence_labels=("caller_metadata",),
        )
        self.assertEqual(identified.status, IncidentStatus.IDENTIFIED)
        self.assertEqual(identified.suspected_cause, "mock health metadata requires review")


class CrossCuttingContractTests(unittest.TestCase):
    def test_validator_only_evaluates_supplied_checks(self) -> None:
        fixture = ControlCenterFixture()
        passed = fixture.validator.evaluate(
            session_id=fixture.operator.session_id,
            target="control-center",
            checks={"policy": True, "backup": True, "tests": True},
        )
        blocked = fixture.validator.evaluate(
            session_id=fixture.operator.session_id,
            target="control-center",
            checks={"policy": True, "backup": False},
        )
        self.assertEqual(passed.state, ValidationState.PASSED)
        self.assertFalse(passed.executed_real_tests)
        self.assertEqual(blocked.state, ValidationState.BLOCKED)
        self.assertIn("backup", blocked.findings)

    def test_knowledge_impact_and_drift_use_caller_metadata_only(self) -> None:
        fixture = ControlCenterFixture()
        knowledge = fixture.knowledge.register(
            session_id=fixture.operator.session_id,
            project="control-center",
            repository_label="repository-mock",
            branch_label="main-mock",
            deployment_label="staging-mock",
            services=("web-mock",),
        )
        impact = fixture.impact.analyze(
            session_id=fixture.operator.session_id,
            project="control-center",
            action="deploy",
            risk="HIGH",
            affected_components=("web", "policy"),
        )
        drift = fixture.drift.compare(
            session_id=fixture.operator.session_id,
            project="control-center",
            desired={"mode": "safe", "version": "1"},
            observed={"mode": "safe", "version": "0"},
        )
        self.assertEqual(knowledge.state, ContractState.RECORDED)
        self.assertTrue(impact.requires_backup)
        self.assertEqual(impact.execution, ContractState.BLOCKED_BY_DEFAULT)
        self.assertEqual(drift.changed_keys, ("version",))

    def test_agents_and_change_manager_plan_without_activation(self) -> None:
        fixture = ControlCenterFixture()
        task = fixture.agents.plan(
            session_id=fixture.operator.session_id,
            agent_id="planner",
            task="preparar una evaluación segura",
        )
        change = fixture.changes.propose(
            session_id=fixture.operator.session_id,
            project="control-center",
            action="modify_code",
            risk="HIGH",
        )
        self.assertEqual(task.execution, "blocked_by_default")
        self.assertTrue(change.approval_required)
        self.assertTrue(change.backup_required)
        self.assertEqual(change.execution, ContractState.BLOCKED_BY_DEFAULT)

    def test_metadata_analysis_rejects_secret_like_values(self) -> None:
        fixture = ControlCenterFixture()
        with self.assertRaises(ValueError):
            fixture.drift.compare(
                session_id=fixture.operator.session_id,
                project="control-center",
                desired={"credential": "password=do-not-store"},
                observed={},
            )
        with self.assertRaises(ValueError):
            fixture.knowledge.register(
                session_id=fixture.operator.session_id,
                project="control-center",
                repository_label="stdout=raw-output",
                branch_label="main",
                deployment_label="staging",
                services=(),
            )


if __name__ == "__main__":
    unittest.main()
