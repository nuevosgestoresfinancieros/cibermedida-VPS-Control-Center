from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from control_center.audit import JsonlAuditSink, MetadataAuditLog
from core_operator.audit import JsonlAuditStore
from core_operator.config import OperatorConfig
from core_operator.policy import RiskLevel


ROOT = Path(__file__).resolve().parents[1]


class AuditRetentionTests(unittest.TestCase):
    def test_application_audit_rotates_and_reloads_retained_segments(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            path = Path(temporary_directory) / "audit.jsonl"
            sink = JsonlAuditSink(path, max_bytes=1024, retention_files=2)
            audit = MetadataAuditLog(sink=sink)

            for index in range(5):
                audit.append(
                    user_id="operator",
                    actor="operator",
                    role="OPERATOR",
                    action=f"event-{index}",
                    result="accepted",
                    metadata={"detail": "x" * 450},
                )

            reloaded = JsonlAuditSink(path, max_bytes=1024, retention_files=2).read()
            self.assertEqual([record.action for record in reloaded], ["event-2", "event-3", "event-4"])
            self.assertTrue(path.with_name("audit.jsonl.1").is_file())
            self.assertTrue(path.with_name("audit.jsonl.2").is_file())
            self.assertFalse(path.with_name("audit.jsonl.3").exists())
            for segment in (path, path.with_name("audit.jsonl.1"), path.with_name("audit.jsonl.2")):
                self.assertEqual(segment.stat().st_mode & 0o777, 0o600)

    def test_core_audit_rotates_without_persisting_raw_streams(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            path = Path(temporary_directory) / "audit.jsonl"
            config = OperatorConfig(
                persistence_enabled=True,
                audit_to_disk=True,
                audit_path=path,
                audit_max_bytes=1024,
                audit_retention_files=2,
            )
            store = JsonlAuditStore(config=config)
            for index in range(20):
                store.append(
                    actor="operator",
                    action="execute_read_safe",
                    risk_level=RiskLevel.LOW,
                    command_id="system.memory",
                    result=f"event-{index}",
                    authorization_required=False,
                )

            reloaded = JsonlAuditStore(config=config)
            self.assertLess(len(reloaded.events), 20)
            self.assertEqual(reloaded.events[-1].result, "event-19")
            self.assertTrue(path.with_name("audit.jsonl.1").is_file())
            self.assertTrue(path.with_name("audit.jsonl.2").is_file())
            serialized = "\n".join(path.with_name(name).read_text(encoding="utf-8") for name in (
                "audit.jsonl.2",
                "audit.jsonl.1",
                "audit.jsonl",
            ))
            self.assertNotIn("stdout", serialized.lower())
            self.assertNotIn("stderr", serialized.lower())

    def test_retention_limits_are_validated(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            path = Path(temporary_directory) / "audit.jsonl"
            with self.assertRaises(ValueError):
                JsonlAuditSink(path, retention_files=0)
            with self.assertRaises(ValueError):
                OperatorConfig(
                    persistence_enabled=True,
                    audit_to_disk=True,
                    audit_path=path,
                    audit_retention_files=17,
                ).validate()


if __name__ == "__main__":
    unittest.main()
