from __future__ import annotations

import copy
import unittest

from control_center.operation_manifest import (
    OperationManifest,
    OperationStatus,
    hashes_match,
    manifest_from_dict,
    risk_level_for,
)


class OperationManifestTests(unittest.TestCase):
    def make_manifest(self) -> OperationManifest:
        return OperationManifest.create(
            operation_id="operation-1",
            project="control-center",
            server="aula-cibermedida",
            environment="laboratory",
            resource="backend",
            requested_by="operator",
            requested_action="deploy",
            risk_level="L3",
            status=OperationStatus.WAITING_APPROVAL,
            commands=("deploy.prepare",),
            services_affected=("control-center",),
            tests_required=("unit",),
            backup_required=True,
            approval_required=True,
            rollback_plan="restaurar backup verificado",
            expected_result="release validada",
            validation_steps=("health.check",),
            created_at="2026-09-06T00:00:00+00:00",
        )

    def test_manifest_contains_scope_and_verifiable_hashes(self) -> None:
        manifest = self.make_manifest()
        self.assertEqual(manifest.scope["server"], "aula-cibermedida")
        self.assertEqual(manifest.scope["environment"], "laboratory")
        self.assertTrue(manifest.operation_hash)
        self.assertTrue(manifest.plan_hash)
        self.assertTrue(hashes_match(manifest))
        self.assertEqual(manifest_from_dict(manifest.as_dict()), manifest)

    def test_stage_transition_produces_approval_and_execution_hashes(self) -> None:
        approved = self.make_manifest().with_status(
            OperationStatus.APPROVED,
            approved_at="2026-09-06T00:01:00+00:00",
        )
        executing = approved.with_status(
            OperationStatus.EXECUTING,
            executed_at="2026-09-06T00:02:00+00:00",
        )
        self.assertTrue(approved.approval_hash)
        self.assertFalse(approved.execution_hash)
        self.assertTrue(executing.execution_hash)
        self.assertNotEqual(approved.operation_hash, executing.operation_hash)
        self.assertTrue(hashes_match(executing))

    def test_tampering_or_secret_metadata_is_rejected(self) -> None:
        payload = self.make_manifest().as_dict()
        tampered = copy.deepcopy(payload)
        tampered["commit"] = "changed"
        with self.assertRaises(ValueError):
            manifest_from_dict(tampered)
        with self.assertRaises(ValueError):
            OperationManifest.create(
                operation_id="operation-2",
                project="control-center",
                server="aula-cibermedida",
                environment="laboratory",
                resource="backend",
                requested_by="operator",
                requested_action="read",
                expected_result="token=not-allowed",
                created_at="2026-09-06T00:00:00+00:00",
            )

    def test_legacy_risk_labels_map_to_documented_levels(self) -> None:
        self.assertEqual(risk_level_for("LOW"), "L1")
        self.assertEqual(risk_level_for("MEDIUM"), "L2")
        self.assertEqual(risk_level_for("HIGH"), "L3")
        self.assertEqual(risk_level_for("CRITICAL"), "L4")


if __name__ == "__main__":
    unittest.main()
