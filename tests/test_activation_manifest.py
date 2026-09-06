from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from api.readonly_server import validate_activation_scope
from control_center import ActivationManifestError, load_activation_manifest


def manifest_payload(**overrides: object) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    payload: dict[str, object] = {
        "version": 1,
        "manifest_id": "activation-fixture-001",
        "decision": "approved",
        "requester": "operator-fixture",
        "requester_role": "OPERATOR",
        "approver": "admin-fixture",
        "approver_role": "ADMIN",
        "policy_version": "policy-2026-09",
        "effective_permissions": ["VIEW_CORE_OPERATOR", "RUN_READ_SAFE"],
        "scope": ["production-readiness"],
        "provider_ids": ["reviewed-provider"],
        "approved_at": (now - timedelta(minutes=5)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
    }
    payload.update(overrides)
    return payload


class ActivationManifestTests(unittest.TestCase):
    def write_manifest(self, root: Path, payload: object, name: str = "activation.json") -> Path:
        path = root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_valid_manifest_is_active_and_preserves_policy_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cibermedida-activation-") as temporary_directory:
            manifest = load_activation_manifest(
                self.write_manifest(Path(temporary_directory), manifest_payload())
            )
        self.assertTrue(manifest.is_active())
        self.assertEqual(manifest.policy_version, "policy-2026-09")
        self.assertEqual(manifest.effective_permissions, ("VIEW_CORE_OPERATOR", "RUN_READ_SAFE"))
        self.assertNotIn("/", manifest.evidence())

    def test_requester_and_approver_must_be_distinct(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cibermedida-activation-") as temporary_directory:
            path = self.write_manifest(
                Path(temporary_directory),
                manifest_payload(approver="operator-fixture"),
            )
            with self.assertRaises(ActivationManifestError):
                load_activation_manifest(path)

    def test_expired_manifest_is_loaded_but_not_active(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cibermedida-activation-") as temporary_directory:
            path = self.write_manifest(
                Path(temporary_directory),
                manifest_payload(
                    approved_at=(datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
                    expires_at=(datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
                ),
            )
            manifest = load_activation_manifest(path)
        self.assertFalse(manifest.is_active())
        self.assertEqual(manifest.status(), "expired")

    def test_unknown_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cibermedida-activation-") as temporary_directory:
            path = self.write_manifest(Path(temporary_directory), manifest_payload(extra="not allowed"))
            with self.assertRaises(ActivationManifestError):
                load_activation_manifest(path)

    def test_secret_like_and_raw_stream_metadata_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cibermedida-activation-") as temporary_directory:
            root = Path(temporary_directory)
            secret_path = self.write_manifest(root, manifest_payload(policy_version="token=fixture"), "secret.json")
            raw_path = self.write_manifest(root, manifest_payload(policy_version="stderr=fixture"), "raw.json")
            with self.assertRaises(ActivationManifestError):
                load_activation_manifest(secret_path)
            with self.assertRaises(ActivationManifestError):
                load_activation_manifest(raw_path)

    def test_unsafe_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cibermedida-activation-") as temporary_directory:
            root = Path(temporary_directory)
            logs = root / "logs"
            logs.mkdir()
            path = self.write_manifest(logs, manifest_payload())
            with self.assertRaises(ActivationManifestError):
                load_activation_manifest(path)

    def test_live_provider_scope_requires_matching_active_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cibermedida-activation-") as temporary_directory:
            manifest = load_activation_manifest(
                self.write_manifest(Path(temporary_directory), manifest_payload())
            )
        validate_activation_scope(manifest, ("reviewed-provider",))
        with self.assertRaises(ValueError):
            validate_activation_scope(None, ("reviewed-provider",))
        with self.assertRaises(ValueError):
            validate_activation_scope(manifest, ("unlisted-provider",))


if __name__ == "__main__":
    unittest.main()
