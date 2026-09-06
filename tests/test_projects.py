from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from control_center.audit import MetadataAuditLog
from control_center.auth import AuthService, Role
from control_center.projects import (
    ProjectCollectionState,
    ProjectService,
    ReadSafeProjectProvider,
    SyntheticProjectProvider,
)
from control_center.state import JsonMetadataStore
from phase1_inventory.executor import CommandResult


ROOT = Path(__file__).resolve().parents[1]


class FakeGitExecutor:
    def __init__(self, status: str, head: str = "abcdef123456") -> None:
        self.status = status
        self.head = head
        self.calls: list[str] = []

    def execute(self, command_id: str) -> CommandResult:
        self.calls.append(command_id)
        if command_id == "git.status":
            return CommandResult(command_id, 0, self.status, "")
        if command_id == "git.head_commit":
            return CommandResult(command_id, 0, f"{self.head}\n", "")
        raise AssertionError(command_id)


class ProjectIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.auth = AuthService()
        self.auth.register_user(
            user_id="project-operator-id",
            username="project-operator",
            password="project-operator-password-123",
            role=Role.OPERATOR,
        )
        self.session_id = self.auth.login(
            username="project-operator",
            password="project-operator-password-123",
        ).session_id

    def test_read_safe_provider_returns_only_validated_git_metadata(self) -> None:
        executor = FakeGitExecutor("## main...origin/main\n M private-name.txt\n")
        evidence = ReadSafeProjectProvider(executor=executor).collect()
        self.assertEqual(evidence.branch, "main")
        self.assertEqual(evidence.commit, "abcdef123456")
        self.assertTrue(evidence.dirty)
        self.assertEqual(executor.calls, ["git.status", "git.head_commit"])

    def test_service_persists_and_reloads_declared_project_metadata(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            store = JsonMetadataStore(Path(temporary_directory) / "projects.json")
            service = ProjectService(
                auth=self.auth,
                audit=MetadataAuditLog(),
                provider=SyntheticProjectProvider(),
                provider_enabled=True,
                state_store=store,
            )
            record = service.collect(session_id=self.session_id)
            self.assertEqual(record.state, ProjectCollectionState.COLLECTED)
            self.assertFalse(record.live_data)
            reloaded = ProjectService(
                auth=self.auth,
                audit=MetadataAuditLog(),
                provider=SyntheticProjectProvider(),
                provider_enabled=True,
                state_store=JsonMetadataStore(store.path),
            )
            self.assertEqual(reloaded.records, (record,))
            self.assertNotIn("private-name", store.path.read_text(encoding="utf-8"))

    def test_unsafe_git_output_is_rejected_without_raw_metadata(self) -> None:
        provider = ReadSafeProjectProvider(
            executor=FakeGitExecutor("## main\npassword=must-not-store\n")
        )
        with self.assertRaises(ValueError):
            provider.collect()

    def test_failed_git_command_is_rejected_without_persisting_output(self) -> None:
        class FailedExecutor(FakeGitExecutor):
            def execute(self, command_id: str) -> CommandResult:
                self.calls.append(command_id)
                return CommandResult(command_id, 1, "fatal: private failure", "", error_code="command_failed")

        with self.assertRaises(ValueError):
            ReadSafeProjectProvider(executor=FailedExecutor("")).collect()

    def test_disabled_provider_stays_blocked(self) -> None:
        service = ProjectService(
            auth=self.auth,
            audit=MetadataAuditLog(),
            provider=None,
            provider_enabled=False,
        )
        record = service.collect(session_id=self.session_id)
        self.assertEqual(record.state, ProjectCollectionState.BLOCKED_BY_DEFAULT)
        self.assertEqual(service.records, (record,))


if __name__ == "__main__":
    unittest.main()
