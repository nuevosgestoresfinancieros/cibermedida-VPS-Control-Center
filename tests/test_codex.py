from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from control_center.audit import MetadataAuditLog
from control_center.auth import AuthService, Role
from control_center.codex import (
    CodexAnalysisState,
    CodexEvidence,
    CodexService,
    SyntheticCodexProvider,
)
from control_center.state import JsonMetadataStore


class CodexServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.auth = AuthService()
        self.auth.register_user(
            user_id="codex-operator-id",
            username="codex-operator",
            password="codex-operator-password-123",
            role=Role.OPERATOR,
        )
        self.session_id = self.auth.login(
            username="codex-operator",
            password="codex-operator-password-123",
        ).session_id

    def test_disabled_provider_is_blocked(self) -> None:
        service = CodexService(auth=self.auth, audit=MetadataAuditLog())
        run = service.analyze(
            session_id=self.session_id,
            project="control-center",
            request_kind="repository",
        )
        self.assertEqual(run.state, CodexAnalysisState.BLOCKED_BY_DEFAULT)
        self.assertEqual(run.files_examined, 0)

    def test_synthetic_provider_persists_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = JsonMetadataStore(Path(temporary_directory) / "codex.json")
            service = CodexService(
                auth=self.auth,
                audit=MetadataAuditLog(),
                provider=SyntheticCodexProvider(),
                provider_enabled=True,
                state_store=store,
            )
            run = service.analyze(
                session_id=self.session_id,
                project="control-center",
                request_kind="diagnosis",
            )
            self.assertEqual(run.state, CodexAnalysisState.COMPLETED)
            self.assertEqual(run.changed_files, 0)
            persisted = store.path.read_text(encoding="utf-8").lower()
            self.assertNotIn("stdout", persisted)
            self.assertNotIn("stderr", persisted)
            self.assertNotIn("password", persisted)

    def test_provider_unsafe_evidence_is_rejected(self) -> None:
        class UnsafeProvider:
            name = "password=must-not-store"
            live_data = False

            def analyze(self, *, project: str, request_kind: str) -> CodexEvidence:
                return CodexEvidence(
                    provider=self.name,
                    project=project,
                    request_kind=request_kind,
                    summary="stdout=raw output",
                    findings=(),
                    files_examined=1,
                    changed_files=0,
                    duration_ms=1,
                )

        service = CodexService(
            auth=self.auth,
            audit=MetadataAuditLog(),
            provider=UnsafeProvider(),
            provider_enabled=True,
        )
        run = service.analyze(
            session_id=self.session_id,
            project="control-center",
            request_kind="repository",
        )
        self.assertEqual(run.state, CodexAnalysisState.REJECTED)
        self.assertEqual(run.files_examined, 0)

    def test_provider_unbounded_finding_is_rejected(self) -> None:
        class UnboundedProvider:
            name = "bounded-test-provider"
            live_data = False

            def analyze(self, *, project: str, request_kind: str) -> CodexEvidence:
                return CodexEvidence(
                    provider=self.name,
                    project=project,
                    request_kind=request_kind,
                    summary="safe summary",
                    findings=("x" * 257,),
                    files_examined=1,
                    changed_files=0,
                    duration_ms=1,
                )

        service = CodexService(
            auth=self.auth,
            audit=MetadataAuditLog(),
            provider=UnboundedProvider(),
            provider_enabled=True,
        )
        run = service.analyze(
            session_id=self.session_id,
            project="control-center",
            request_kind="repository",
        )
        self.assertEqual(run.state, CodexAnalysisState.REJECTED)
        self.assertEqual(run.findings, ())


if __name__ == "__main__":
    unittest.main()
