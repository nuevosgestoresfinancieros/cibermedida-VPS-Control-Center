from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from control_center.auth import AuthService, Role
from control_center.audit import MetadataAuditLog
from control_center.state import JsonMetadataStore
from control_center.validation import ValidationState, ValidatorService


class ValidationPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.auth = AuthService()
        self.auth.register_user(
            user_id="validation-admin-id",
            username="validation-admin",
            password="validation-admin-password-123",
            role=Role.ADMIN,
        )
        self.session = self.auth.login(
            username="validation-admin",
            password="validation-admin-password-123",
        )

    def test_reports_reload_as_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "validation.json"
            service = ValidatorService(
                auth=self.auth,
                audit=MetadataAuditLog(),
                state_store=JsonMetadataStore(path),
            )
            report = service.evaluate(
                session_id=self.session.session_id,
                target="release-a",
                checks={"syntax": True, "tests": False},
            )

            reloaded = ValidatorService(
                auth=self.auth,
                audit=MetadataAuditLog(),
                state_store=JsonMetadataStore(path),
            )

            self.assertEqual(reloaded.reports, (report,))
            self.assertEqual(report.state, ValidationState.BLOCKED)
            self.assertFalse(report.executed_real_tests)
            persisted = path.read_text(encoding="utf-8")
            self.assertNotIn("stdout", persisted.lower())
            self.assertNotIn("stderr", persisted.lower())

    def test_validation_rejects_unsafe_or_non_boolean_checks(self) -> None:
        service = ValidatorService(auth=self.auth, audit=MetadataAuditLog())
        with self.assertRaises(ValueError):
            service.evaluate(
                session_id=self.session.session_id,
                target="password=secret",
                checks={"syntax": True},
            )
        with self.assertRaises(ValueError):
            service.evaluate(
                session_id=self.session.session_id,
                target="release-a",
                checks={"syntax": "true"},
            )


if __name__ == "__main__":
    unittest.main()
