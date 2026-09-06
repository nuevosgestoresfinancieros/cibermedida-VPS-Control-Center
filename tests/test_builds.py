from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from control_center.auth import AuthService, Role
from control_center.audit import MetadataAuditLog
from control_center.builds import (
    BuildEvidence,
    BuildExecutionState,
    BuildService,
    DeclaredCommandBuildProvider,
)
from control_center.state import JsonMetadataStore


class BuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.auth = AuthService()
        self.auth.register_user(
            user_id="build-operator-id",
            username="build-operator",
            password="build-operator-password-123",
            role=Role.OPERATOR,
        )
        self.session_id = self.auth.login(
            username="build-operator",
            password="build-operator-password-123",
        ).session_id

    def test_declared_command_provider_runs_fixed_argv_and_returns_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            provider = DeclaredCommandBuildProvider(
                project_root=temporary_directory,
                commands={"compile": ("python3", "-c", "print('build ok')")},
            )
            evidence = provider.run(target="compile")
            self.assertEqual(evidence.provider, "declared-build")
            self.assertTrue(evidence.passed)
            self.assertEqual(evidence.return_code, 0)

    def test_provider_rejects_shell_wrappers_and_forbidden_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            with self.assertRaises(ValueError):
                DeclaredCommandBuildProvider(
                    project_root=temporary_directory,
                    commands={"compile": ("sh", "-c", "echo unsafe")},
                )
            with self.assertRaises(ValueError):
                DeclaredCommandBuildProvider(
                    project_root=temporary_directory,
                    commands={"compile": ("python3", "sudo")},
                )

    def test_service_is_blocked_without_provider(self) -> None:
        service = BuildService(auth=self.auth, audit=MetadataAuditLog())
        run = service.run(session_id=self.session_id, target="compile")
        self.assertEqual(run.state, BuildExecutionState.BLOCKED_BY_DEFAULT)
        self.assertFalse(run.passed)

    def test_service_persists_only_build_metadata(self) -> None:
        class FakeBuildProvider:
            name = "fixture-build"
            live_data = False

            def run(self, *, target: str) -> BuildEvidence:
                return BuildEvidence(
                    provider=self.name,
                    target=target,
                    passed=True,
                    return_code=0,
                    duration_ms=1,
                )

        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "builds.json"
            service = BuildService(
                auth=self.auth,
                audit=MetadataAuditLog(),
                provider=FakeBuildProvider(),
                provider_enabled=True,
                state_store=JsonMetadataStore(path),
            )
            run = service.run(session_id=self.session_id, target="compile")
            self.assertEqual(run.state, BuildExecutionState.COMPLETED)
            contents = path.read_text(encoding="utf-8").lower()
            self.assertNotIn("stdout", contents)
            self.assertNotIn("stderr", contents)
            self.assertNotIn("password=", contents)


if __name__ == "__main__":
    unittest.main()
