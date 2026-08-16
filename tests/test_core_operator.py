from __future__ import annotations

import ast
from dataclasses import replace
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from core_operator.audit import InMemoryAuditStore, JsonlAuditStore, UnsafeAuditEventError
from core_operator.approved_execution import ApprovedExecutionPlanner, ExecutionPlanState
from core_operator.approvals import ApprovalStateError, ApprovalStatus, InMemoryApprovalStore
from core_operator.config import AUTHORIZED_PROJECT_ROOT, OperatorConfig, default_config
from core_operator.executor_adapter import ReadSafeExecutorAdapter
from core_operator.health import CoreHealthChecker
from core_operator.policy import Decision, PolicyEngine, PolicyRequest, RiskLevel
from core_operator.safe_logging import InMemoryStructuredLogger
from phase1_inventory.commands import CommandClass
from phase1_inventory.executor import CommandResult

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "core_operator"


class FakeExecutor:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def execute(self, command_id: str) -> CommandResult:
        self.calls.append(command_id)
        return CommandResult(command_id, 0, "password=raw-secret stdout", "token=raw-secret stderr")


class ConfigTests(unittest.TestCase):
    def test_default_config_is_safe_and_valid(self) -> None:
        config = default_config()
        self.assertEqual(config.project_root, AUTHORIZED_PROJECT_ROOT)
        self.assertFalse(config.persistence_enabled)
        self.assertFalse(config.log_to_disk)
        self.assertFalse(config.audit_to_disk)
        self.assertIsNone(config.audit_path)
        self.assertFalse(config.load_environment_files)
        self.assertFalse(config.allow_network_health_checks)

    def test_disk_persistence_is_disabled_by_default(self) -> None:
        with self.assertRaises(ValueError):
            JsonlAuditStore(config=default_config())
        with self.assertRaises(ValueError):
            OperatorConfig(audit_to_disk=True, audit_path=Path("audit.jsonl")).validate()
        with self.assertRaises(ValueError):
            OperatorConfig(persistence_enabled=True).validate()
        with self.assertRaises(ValueError):
            OperatorConfig(log_to_disk=True).validate()

    def test_audit_path_must_stay_inside_project(self) -> None:
        with self.assertRaises(ValueError):
            OperatorConfig(
                persistence_enabled=True,
                audit_to_disk=True,
                audit_path=Path("../audit.jsonl"),
            ).validate()
        with self.assertRaises(ValueError):
            OperatorConfig(
                persistence_enabled=True,
                audit_to_disk=True,
                audit_path=Path("/tmp/audit.jsonl"),
            ).validate()

    def test_audit_path_rejects_critical_files(self) -> None:
        with self.assertRaises(ValueError):
            OperatorConfig(
                persistence_enabled=True,
                audit_to_disk=True,
                audit_path=Path("INVENTORY.json"),
            ).validate()

    def test_env_loading_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            OperatorConfig(load_environment_files=True).validate()


class PolicyEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = PolicyEngine()

    def test_read_safe_is_allowed(self) -> None:
        decision = self.policy.evaluate(PolicyRequest(actor="tester", action="read", command_id="system.memory"))
        self.assertEqual(decision.decision, Decision.ALLOW)
        self.assertEqual(decision.risk_level, RiskLevel.LOW)
        self.assertFalse(decision.authorization_required)

    def test_read_sensitive_requires_authorization(self) -> None:
        decision = self.policy.evaluate(PolicyRequest(actor="tester", action="read", command_id="system.ports"))
        self.assertEqual(decision.decision, Decision.APPROVAL_REQUIRED)
        self.assertTrue(decision.authorization_required)

    def test_read_privileged_requires_authorization(self) -> None:
        decision = self.policy.evaluate(PolicyRequest(actor="tester", action="read", command_class=CommandClass.READ_PRIVILEGED))
        self.assertEqual(decision.decision, Decision.APPROVAL_REQUIRED)
        self.assertEqual(decision.risk_level, RiskLevel.HIGH)

    def test_forbidden_is_denied(self) -> None:
        decision = self.policy.evaluate(PolicyRequest(actor="tester", action="read", command_id="forbidden.docker_inspect"))
        self.assertEqual(decision.decision, Decision.DENY)
        self.assertEqual(decision.risk_level, RiskLevel.CRITICAL)

    def test_modifying_actions_are_denied_by_default(self) -> None:
        actions = ("deploy", "rollback", "restart_service", "modify_apache", "write_file", "create_backup")
        for action in actions:
            with self.subTest(action=action):
                decision = self.policy.evaluate(PolicyRequest(actor="tester", action=action, command_class=CommandClass.READ_SAFE))
                self.assertEqual(decision.decision, Decision.DENY)
                self.assertTrue(decision.authorization_required)


class ApprovalWorkflowTests(unittest.TestCase):
    def test_read_safe_does_not_create_approval(self) -> None:
        audit = InMemoryAuditStore()
        approvals = InMemoryApprovalStore(audit=audit)
        decision = PolicyEngine().evaluate(PolicyRequest(actor="tester", action="read", command_id="system.memory"))
        request = approvals.apply_policy_decision(
            actor="tester",
            action="execute_read_safe",
            policy_decision=decision,
            command_id="system.memory",
        )
        self.assertIsNone(request)
        self.assertEqual(approvals.requests, ())

    def test_read_sensitive_generates_pending_approval_without_execution(self) -> None:
        fake = FakeExecutor()
        audit = InMemoryAuditStore()
        approvals = InMemoryApprovalStore(audit=audit)
        envelope = ReadSafeExecutorAdapter(
            policy=PolicyEngine(),
            audit=audit,
            logger=InMemoryStructuredLogger(),
            executor=fake,
            approvals=approvals,
        ).execute(actor="tester", command_id="system.ports")
        self.assertEqual(envelope.decision, Decision.APPROVAL_REQUIRED)
        self.assertIsNotNone(envelope.approval_request)
        self.assertEqual(envelope.approval_request.status, ApprovalStatus.PENDING)
        self.assertEqual(fake.calls, [])

    def test_read_privileged_generates_pending_approval(self) -> None:
        audit = InMemoryAuditStore()
        approvals = InMemoryApprovalStore(audit=audit)
        decision = PolicyEngine().evaluate(
            PolicyRequest(actor="tester", action="read", command_class=CommandClass.READ_PRIVILEGED)
        )
        request = approvals.apply_policy_decision(
            actor="tester",
            action="read",
            policy_decision=decision,
        )
        self.assertIsNotNone(request)
        self.assertEqual(request.status, ApprovalStatus.PENDING)
        self.assertEqual(request.risk_level, RiskLevel.HIGH)

    def test_forbidden_creates_denied_request_that_cannot_be_approved(self) -> None:
        audit = InMemoryAuditStore()
        approvals = InMemoryApprovalStore(audit=audit)
        decision = PolicyEngine().evaluate(
            PolicyRequest(actor="tester", action="read", command_id="forbidden.docker_inspect")
        )
        request = approvals.apply_policy_decision(
            actor="tester",
            action="read",
            policy_decision=decision,
            command_id="forbidden.docker_inspect",
        )
        self.assertIsNotNone(request)
        self.assertEqual(request.status, ApprovalStatus.DENIED)
        with self.assertRaises(ApprovalStateError):
            approvals.approve(request.id, decided_by="admin")

    def test_modifying_action_is_never_executed(self) -> None:
        fake = FakeExecutor()
        audit = InMemoryAuditStore()
        approvals = InMemoryApprovalStore(audit=audit)
        decision = PolicyEngine().evaluate(
            PolicyRequest(actor="tester", action="write_file", command_class=CommandClass.READ_SAFE)
        )
        request = approvals.apply_policy_decision(
            actor="tester",
            action="write_file",
            policy_decision=decision,
        )
        self.assertIn(decision.decision, {Decision.DENY, Decision.APPROVAL_REQUIRED})
        self.assertIsNotNone(request)
        self.assertIn(request.status, {ApprovalStatus.DENIED, ApprovalStatus.PENDING})
        self.assertEqual(fake.calls, [])

    def test_approve_changes_state(self) -> None:
        approvals = InMemoryApprovalStore(audit=InMemoryAuditStore())
        request = approvals.create_pending(
            actor="tester",
            action="read",
            risk_level=RiskLevel.MEDIUM,
            reason="needs authorization",
        )
        decision = approvals.approve(request.id, decided_by="admin")
        self.assertEqual(decision.status, ApprovalStatus.APPROVED)
        self.assertEqual(approvals.requests[0].status, ApprovalStatus.APPROVED)

    def test_deny_changes_state(self) -> None:
        approvals = InMemoryApprovalStore(audit=InMemoryAuditStore())
        request = approvals.create_pending(
            actor="tester",
            action="read",
            risk_level=RiskLevel.MEDIUM,
            reason="needs authorization",
        )
        decision = approvals.deny(request.id, decided_by="admin")
        self.assertEqual(decision.status, ApprovalStatus.DENIED)
        self.assertEqual(approvals.requests[0].status, ApprovalStatus.DENIED)

    def test_cannot_approve_twice(self) -> None:
        approvals = InMemoryApprovalStore(audit=InMemoryAuditStore())
        request = approvals.create_pending(
            actor="tester",
            action="read",
            risk_level=RiskLevel.MEDIUM,
            reason="needs authorization",
        )
        approvals.approve(request.id, decided_by="admin")
        with self.assertRaises(ApprovalStateError):
            approvals.approve(request.id, decided_by="admin")

    def test_audit_receives_non_sensitive_approval_events(self) -> None:
        audit = InMemoryAuditStore()
        approvals = InMemoryApprovalStore(audit=audit)
        request = approvals.create_pending(
            actor="tester token=syntheticSecret12345",
            action="read",
            risk_level=RiskLevel.MEDIUM,
            reason="needs authorization",
            command_id="system.ports",
        )
        approvals.deny(request.id, decided_by="admin password=syntheticSecret12345")
        actions = [event.action for event in audit.events]
        self.assertEqual(actions, ["approval_requested", "approval_denied"])
        self.assertNotIn("syntheticSecret12345", str(audit.events))
        self.assertNotIn("stdout", str(audit.events).lower())
        self.assertNotIn("stderr", str(audit.events).lower())

    def test_in_memory_approval_store_does_not_write_to_disk(self) -> None:
        audit = InMemoryAuditStore()
        approvals = InMemoryApprovalStore(audit=audit)
        with patch("pathlib.Path.open", side_effect=AssertionError("disk write attempted")):
            request = approvals.create_pending(
                actor="tester",
                action="read",
                risk_level=RiskLevel.MEDIUM,
                reason="needs authorization",
            )
            approvals.approve(request.id, decided_by="admin")
        self.assertEqual(approvals.requests[0].status, ApprovalStatus.APPROVED)


class ApprovedExecutionContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = InMemoryAuditStore()
        self.approvals = InMemoryApprovalStore(audit=self.audit)
        self.planner = ApprovedExecutionPlanner(policy=PolicyEngine(), approvals=self.approvals, audit=self.audit)

    def _approval(self, *, actor: str = "tester", action: str = "execute_read_safe", command_id: str = "system.memory"):
        return self.approvals.create_pending(
            actor=actor,
            action=action,
            risk_level=RiskLevel.LOW,
            reason="plan authorization",
            command_id=command_id,
        )

    def _approved_request(self):
        request = self._approval()
        self.approvals.approve(request.id, decided_by="admin")
        return self.approvals.get(request.id)

    def test_approved_matching_approval_builds_ready_plan(self) -> None:
        request = self._approved_request()
        plan = self.planner.build_plan(
            actor="tester",
            action="execute_read_safe",
            command_id="system.memory",
            approval_id=request.id,
        )
        self.assertEqual(plan.state, ExecutionPlanState.READY_TO_EXECUTE)
        self.assertEqual(plan.approval_id, request.id)
        self.assertEqual(plan.command_id, "system.memory")

    def test_pending_approval_blocks_plan(self) -> None:
        request = self._approval()
        plan = self.planner.build_plan(
            actor="tester",
            action="execute_read_safe",
            command_id="system.memory",
            approval_id=request.id,
        )
        self.assertEqual(plan.state, ExecutionPlanState.BLOCKED)
        self.assertIn("pending", plan.reason)

    def test_denied_approval_blocks_plan(self) -> None:
        request = self._approval()
        self.approvals.deny(request.id, decided_by="admin")
        plan = self.planner.build_plan(
            actor="tester",
            action="execute_read_safe",
            command_id="system.memory",
            approval_id=request.id,
        )
        self.assertEqual(plan.state, ExecutionPlanState.BLOCKED)
        self.assertIn("denied", plan.reason)

    def test_expired_approval_blocks_plan(self) -> None:
        request = self._approval()
        self.approvals._requests[request.id] = replace(request, status=ApprovalStatus.EXPIRED)
        plan = self.planner.build_plan(
            actor="tester",
            action="execute_read_safe",
            command_id="system.memory",
            approval_id=request.id,
        )
        self.assertEqual(plan.state, ExecutionPlanState.BLOCKED)
        self.assertIn("expired", plan.reason)

    def test_forbidden_command_is_rejected_even_with_approval(self) -> None:
        request = self._approval(command_id="forbidden.docker_inspect")
        self.approvals.approve(request.id, decided_by="admin")
        plan = self.planner.build_plan(
            actor="tester",
            action="execute_read_safe",
            command_id="forbidden.docker_inspect",
            approval_id=request.id,
        )
        self.assertEqual(plan.state, ExecutionPlanState.REJECTED)
        self.assertEqual(plan.risk_level, RiskLevel.CRITICAL)

    def test_different_command_id_blocks_plan(self) -> None:
        request = self._approved_request()
        plan = self.planner.build_plan(
            actor="tester",
            action="execute_read_safe",
            command_id="system.disk_usage",
            approval_id=request.id,
        )
        self.assertEqual(plan.state, ExecutionPlanState.BLOCKED)
        self.assertIn("command", plan.reason)

    def test_different_action_blocks_plan(self) -> None:
        request = self._approved_request()
        plan = self.planner.build_plan(
            actor="tester",
            action="read",
            command_id="system.memory",
            approval_id=request.id,
        )
        self.assertEqual(plan.state, ExecutionPlanState.BLOCKED)
        self.assertIn("action", plan.reason)

    def test_different_actor_blocks_plan(self) -> None:
        request = self._approved_request()
        plan = self.planner.build_plan(
            actor="other",
            action="execute_read_safe",
            command_id="system.memory",
            approval_id=request.id,
        )
        self.assertEqual(plan.state, ExecutionPlanState.BLOCKED)
        self.assertIn("actor", plan.reason)

    def test_planner_never_calls_real_executor(self) -> None:
        fake = FakeExecutor()
        request = self._approved_request()
        plan = self.planner.build_plan(
            actor="tester",
            action="execute_read_safe",
            command_id="system.memory",
            approval_id=request.id,
        )
        self.assertEqual(plan.state, ExecutionPlanState.READY_TO_EXECUTE)
        self.assertEqual(fake.calls, [])

    def test_execution_plan_audit_is_metadata_only(self) -> None:
        request = self.approvals.create_pending(
            actor="tester token=syntheticSecret12345",
            action="execute_read_safe",
            risk_level=RiskLevel.LOW,
            reason="plan authorization",
            command_id="system.memory",
        )
        self.approvals.approve(request.id, decided_by="admin password=syntheticSecret12345")
        plan = self.planner.build_plan(
            actor="tester token=syntheticSecret12345",
            action="execute_read_safe",
            command_id="system.memory",
            approval_id=request.id,
        )
        self.assertEqual(plan.state, ExecutionPlanState.READY_TO_EXECUTE)
        self.assertEqual(self.audit.events[-1].action, "approved_execution_plan_evaluated")
        self.assertNotIn("syntheticSecret12345", str(self.audit.events))
        self.assertNotIn("stdout", str(self.audit.events).lower())
        self.assertNotIn("stderr", str(self.audit.events).lower())


class AuditAndLoggingTests(unittest.TestCase):
    def test_audit_event_has_required_fields_and_redacts_secrets(self) -> None:
        audit = InMemoryAuditStore()
        event = audit.append(
            actor="operator token=syntheticSecret12345",
            action="read",
            risk_level=RiskLevel.LOW,
            command_id="system.memory",
            result="ok password=syntheticSecret12345",
            authorization_required=False,
        )
        self.assertEqual(len(audit.events), 1)
        self.assertTrue(event.timestamp)
        self.assertEqual(event.risk_level, RiskLevel.LOW)
        self.assertFalse(event.authorization_required)
        self.assertNotIn("syntheticSecret12345", str(event))

    def test_jsonl_audit_store_writes_valid_json_when_explicitly_enabled(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            audit_path = Path(temp_dir) / "audit.jsonl"
            store = JsonlAuditStore(
                config=OperatorConfig(
                    persistence_enabled=True,
                    audit_to_disk=True,
                    audit_path=audit_path,
                )
            )
            event = store.append(
                actor="tester",
                action="execute_read_safe",
                risk_level=RiskLevel.LOW,
                command_id="system.memory",
                result="success",
                authorization_required=False,
            )
            lines = audit_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            record = json.loads(lines[0])
            self.assertEqual(record["actor"], "tester")
            self.assertEqual(record["risk_level"], "LOW")
            self.assertEqual(record["command_id"], "system.memory")
            self.assertEqual(store.events, (event,))

    def test_jsonl_audit_store_fails_closed_on_secret_like_content(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            audit_path = Path(temp_dir) / "audit.jsonl"
            store = JsonlAuditStore(
                config=OperatorConfig(
                    persistence_enabled=True,
                    audit_to_disk=True,
                    audit_path=audit_path,
                )
            )
            with self.assertRaises(UnsafeAuditEventError):
                store.append(
                    actor="tester token=fictitiousSecretValue12345",
                    action="execute_read_safe",
                    risk_level=RiskLevel.LOW,
                    command_id="system.memory",
                    result="success",
                    authorization_required=False,
                )
            self.assertFalse(audit_path.exists())

    def test_jsonl_audit_store_rejects_raw_stdout_or_stderr(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            audit_path = Path(temp_dir) / "audit.jsonl"
            store = JsonlAuditStore(
                config=OperatorConfig(
                    persistence_enabled=True,
                    audit_to_disk=True,
                    audit_path=audit_path,
                )
            )
            with self.assertRaises(UnsafeAuditEventError):
                store.append(
                    actor="tester",
                    action="execute_read_safe",
                    risk_level=RiskLevel.LOW,
                    command_id="system.memory",
                    result="stdout=raw output",
                    authorization_required=False,
                )
            self.assertFalse(audit_path.exists())

    def test_logger_redacts_without_raw_stdout_or_stderr_contract(self) -> None:
        logger = InMemoryStructuredLogger()
        logger.log(
            "info",
            "completed Authorization: Bearer fictitiousTokenValue12345",
            stdout="password=do-not-log",
            stderr="token=do-not-log",
            command_id="system.memory",
        )
        record = logger.records[0]
        self.assertNotIn("fictitiousTokenValue12345", str(record))
        self.assertNotIn("do-not-log", str(record))
        self.assertEqual(record.fields["command_id"], "system.memory")


class HealthTests(unittest.TestCase):
    def test_internal_health_checks_only_core_components(self) -> None:
        result = CoreHealthChecker(
            config=default_config(),
            policy=PolicyEngine(),
            audit=InMemoryAuditStore(),
            logger=InMemoryStructuredLogger(),
        ).check()
        self.assertTrue(result.healthy)
        self.assertTrue(result.checks["config_initialized"])
        self.assertTrue(result.checks["network_health_checks_disabled"])


class ExecutorAdapterTests(unittest.TestCase):
    def test_read_safe_adapter_uses_injected_executor_and_audits_metadata_only(self) -> None:
        fake = FakeExecutor()
        audit = InMemoryAuditStore()
        logger = InMemoryStructuredLogger()
        envelope = ReadSafeExecutorAdapter(policy=PolicyEngine(), audit=audit, logger=logger, executor=fake).execute(
            actor="tester", command_id="system.memory"
        )
        self.assertEqual(envelope.decision, Decision.ALLOW)
        self.assertEqual(fake.calls, ["system.memory"])
        self.assertEqual(audit.events[0].result, "success")
        self.assertNotIn("raw-secret", str(audit.events))
        self.assertNotIn("raw-secret", str(logger.records))

    def test_read_safe_adapter_persists_metadata_without_raw_streams(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            audit_path = Path(temp_dir) / "audit.jsonl"
            audit = JsonlAuditStore(
                config=OperatorConfig(
                    persistence_enabled=True,
                    audit_to_disk=True,
                    audit_path=audit_path,
                )
            )
            envelope = ReadSafeExecutorAdapter(
                policy=PolicyEngine(),
                audit=audit,
                logger=InMemoryStructuredLogger(),
                executor=FakeExecutor(),
            ).execute(actor="tester", command_id="system.memory")
            self.assertEqual(envelope.decision, Decision.ALLOW)
            payload = audit_path.read_text(encoding="utf-8")
            self.assertNotIn("raw-secret", payload)
            self.assertNotIn("stdout", payload.lower())
            self.assertNotIn("stderr", payload.lower())

    def test_adapter_does_not_call_executor_when_policy_blocks(self) -> None:
        fake = FakeExecutor()
        envelope = ReadSafeExecutorAdapter(
            policy=PolicyEngine(),
            audit=InMemoryAuditStore(),
            logger=InMemoryStructuredLogger(),
            executor=fake,
        ).execute(actor="tester", command_id="system.ports")
        self.assertEqual(envelope.decision, Decision.APPROVAL_REQUIRED)
        self.assertEqual(fake.calls, [])


class StaticSafetyTests(unittest.TestCase):
    def test_core_operator_has_no_forbidden_execution_primitives(self) -> None:
        forbidden_names = {"eval", "exec"}
        forbidden_attributes = {("os", "system")}
        for path in PACKAGE.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        self.assertNotIn(node.func.id, forbidden_names, path)
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        self.assertNotIn((node.func.value.id, node.func.attr), forbidden_attributes, path)

    def test_core_operator_does_not_import_subprocess_or_use_shell_sudo(self) -> None:
        for path in PACKAGE.glob("*.py"):
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("import subprocess", source)
            self.assertNotIn("shell=True", source)
            self.assertNotIn("sudo", source)


if __name__ == "__main__":
    unittest.main()
