from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from control_center.audit import MetadataAuditLog
from control_center.auth import AuthService, Role
from control_center.state import JsonMetadataStore
from control_center.testing import (
    InProcessTestProvider,
    SyntheticTestProvider,
    TestEvidence,
    TestExecutionState,
    TestService,
)


ROOT = Path(__file__).resolve().parents[1]


class TestServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.auth = AuthService()
        self.auth.register_user(
            user_id="testing-operator-id",
            username="testing-operator",
            password="testing-operator-password-123",
            role=Role.OPERATOR,
        )
        self.session_id = self.auth.login(
            username="testing-operator",
            password="testing-operator-password-123",
        ).session_id

    def test_disabled_provider_is_blocked(self) -> None:
        service = TestService(auth=self.auth, audit=MetadataAuditLog())
        run = service.run(session_id=self.session_id, target="repository")
        self.assertEqual(run.state, TestExecutionState.BLOCKED_BY_DEFAULT)
        self.assertEqual(run.tests_run, 0)

    def test_synthetic_provider_returns_metadata_only_and_persists(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            store = JsonMetadataStore(Path(temporary_directory) / "tests.json")
            service = TestService(
                auth=self.auth,
                audit=MetadataAuditLog(),
                provider=SyntheticTestProvider(),
                provider_enabled=True,
                state_store=store,
            )
            run = service.run(session_id=self.session_id, target="repository")
            self.assertEqual(run.state, TestExecutionState.COMPLETED)
            self.assertTrue(run.passed)
            self.assertEqual(run.tests_run, 1)
            self.assertNotIn("stdout", store.path.read_text(encoding="utf-8").lower())
            self.assertNotIn("stderr", store.path.read_text(encoding="utf-8").lower())

    def test_provider_cannot_return_unsafe_identity(self) -> None:
        class UnsafeProvider:
            name = "password=must-not-store"
            live_data = False

            def run(self, *, target: str) -> TestEvidence:
                return TestEvidence(self.name, target, True, 1, 0, 1)

        service = TestService(
            auth=self.auth,
            audit=MetadataAuditLog(),
            provider=UnsafeProvider(),
            provider_enabled=True,
        )
        run = service.run(session_id=self.session_id, target="repository")
        self.assertEqual(run.state, TestExecutionState.REJECTED)

    def test_in_process_provider_accepts_only_fixed_target(self) -> None:
        provider = InProcessTestProvider(project_root=ROOT, tests_root=ROOT / "tests")
        with self.assertRaises(ValueError):
            provider.run(target="arbitrary-command")


if __name__ == "__main__":
    unittest.main()
