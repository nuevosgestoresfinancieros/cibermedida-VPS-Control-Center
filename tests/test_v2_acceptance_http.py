from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import Request, urlopen

from api.readonly_server import create_server
from control_center.application import ControlCenterApplication
from control_center.audit import JsonlAuditSink
from control_center.auth import JsonUserStore, Role
from control_center.backups import BackupType
from control_center.builds import SyntheticBuildProvider
from control_center.deployments import DeploymentState
from control_center.execution import ProviderEvidence
from control_center.filesystem_backup import FilesystemBackupProvider
from control_center.filesystem_release import FilesystemReleaseProvider
from control_center.incidents import IncidentSeverity, IncidentStatus
from control_center.monitoring import MetricSnapshot
from control_center.projects import SyntheticProjectProvider
from control_center.state import JsonMetadataStore
from control_center.testing import SyntheticTestProvider
from control_center.codex import SyntheticCodexProvider
from core_operator.approvals import JsonApprovalStore


class AcceptanceMonitoringProvider:
    name = "acceptance-read-safe-monitoring"

    def collect(self) -> MetricSnapshot:
        return MetricSnapshot(
            timestamp="2026-01-01T00:00:00+00:00",
            cpu_percent=12.0,
            memory_percent=24.0,
            disk_percent=35.0,
            load_1m=0.2,
        )


class AcceptanceExecutionProvider:
    name = "acceptance-read-safe-execution"

    def run(self, *, actor: str, action: str, command_id: str) -> ProviderEvidence:
        if not actor or action != "read" or command_id != "system.memory":
            raise ValueError("unexpected acceptance scope")
        return ProviderEvidence(provider=self.name, result="metadata_only", duration_ms=1)


class V2AcceptanceHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(prefix="cibermedida-v2-http-")
        root = Path(self.temporary_directory.name)
        self.source_root = root / "backup-source"
        self.destination_root = root / "backup-destination"
        self.artifact_root = root / "artifacts"
        self.release_root = root / "releases"
        for directory in (self.source_root, self.destination_root, self.artifact_root, self.release_root):
            directory.mkdir()
        (self.source_root / "declared-project").mkdir()
        (self.source_root / "declared-project" / "README.txt").write_text(
            "safe acceptance fixture\n", encoding="utf-8"
        )
        (self.artifact_root / "commit-a").mkdir()
        (self.artifact_root / "commit-a" / "app.txt").write_text("release a\n", encoding="utf-8")

        release_provider = FilesystemReleaseProvider(
            artifact_root=self.artifact_root,
            release_root=self.release_root,
        )
        self.application = ControlCenterApplication(
            user_store=JsonUserStore(root / "users.json"),
            audit_sink=JsonlAuditSink(root / "audit.jsonl"),
            approval_store=JsonApprovalStore(root / "approvals.json"),
            backup_provider=FilesystemBackupProvider(
                source_root=self.source_root,
                destination_root=self.destination_root,
            ),
            backup_state_store=JsonMetadataStore(root / "backups.json"),
            deployment_provider=release_provider,
            deployment_validator=release_provider,
            deployment_state_store=JsonMetadataStore(root / "deployments.json"),
            rollback_provider=release_provider,
            rollback_state_store=JsonMetadataStore(root / "rollbacks.json"),
            monitoring_provider=AcceptanceMonitoringProvider(),
            monitoring_state_store=JsonMetadataStore(root / "monitoring.json"),
            project_provider=SyntheticProjectProvider(),
            projects_enabled=True,
            projects_state_store=JsonMetadataStore(root / "projects.json"),
            test_provider=SyntheticTestProvider(),
            tests_enabled=True,
            tests_state_store=JsonMetadataStore(root / "tests.json"),
            build_provider=SyntheticBuildProvider(),
            builds_enabled=True,
            builds_state_store=JsonMetadataStore(root / "builds.json"),
            codex_provider=SyntheticCodexProvider(),
            codex_enabled=True,
            codex_state_store=JsonMetadataStore(root / "codex.json"),
            execution_provider=AcceptanceExecutionProvider(),
            incident_state_store=JsonMetadataStore(root / "incidents.json"),
            providers_enabled=True,
        )
        self.application.register_user(
            user_id="acceptance-operator-id",
            username="acceptance-operator",
            password="acceptance-operator-password-123",
            role=Role.OPERATOR,
        )
        self.application.register_user(
            user_id="acceptance-admin-id",
            username="acceptance-admin",
            password="acceptance-admin-password-123",
            role=Role.ADMIN,
        )
        self.server = create_server(port=0, application=self.application)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary_directory.cleanup()

    def post_json(
        self,
        path: str,
        payload: dict,
        *,
        cookie: str | None = None,
        csrf: str | None = None,
    ) -> tuple[dict, object]:
        headers = {"Content-Type": "application/json"}
        if cookie:
            headers["Cookie"] = cookie
        if csrf:
            headers["X-CSRF-Token"] = csrf
        request = Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urlopen(request, timeout=3) as response:
            return json.loads(response.read()), response

    def get_json(self, path: str, *, cookie: str | None = None) -> tuple[dict, object]:
        headers = {"Cookie": cookie} if cookie else {}
        with urlopen(Request(f"{self.base_url}{path}", headers=headers), timeout=3) as response:
            return json.loads(response.read()), response

    def login(self, username: str, password: str) -> tuple[str, str]:
        payload, response = self.post_json(
            "/api/auth/login",
            {"username": username, "password": password},
        )
        return response.headers["Set-Cookie"].split(";", 1)[0], payload["csrfToken"]

    def test_documented_v2_workflow_is_operational_with_isolated_providers(self) -> None:
        status, response = self.get_json("/api/status")
        self.assertEqual(response.status, 200)
        capability_states = {item["capability_id"]: item["state"] for item in status["capabilities"]}
        self.assertEqual(capability_states["backups"], "provider_enabled")
        self.assertEqual(capability_states["deployments"], "provider_enabled")
        self.assertEqual(capability_states["rollback"], "provider_enabled")
        self.assertEqual(capability_states["monitoring"], "provider_enabled")
        self.assertEqual(capability_states["controlled_execution"], "provider_enabled")
        self.assertEqual(capability_states["projects"], "provider_enabled")
        self.assertEqual(capability_states["testing"], "provider_enabled")
        self.assertEqual(capability_states["builds"], "provider_enabled")
        self.assertEqual(capability_states["codex"], "provider_enabled")

        operator_cookie, operator_csrf = self.login(
            "acceptance-operator", "acceptance-operator-password-123"
        )
        admin_cookie, admin_csrf = self.login("acceptance-admin", "acceptance-admin-password-123")

        projects, response = self.get_json("/api/projects", cookie=operator_cookie)
        self.assertEqual(response.status, 200)
        self.assertEqual(projects["projects"], [])
        collected_project, response = self.post_json(
            "/api/projects/collect",
            {"csrfToken": operator_csrf},
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(collected_project["state"], "collected")
        self.assertFalse(collected_project["live_data"])
        project_status, response = self.get_json(
            "/api/projects/control-center/status",
            cookie=operator_cookie,
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(project_status["project"]["branch"], "main")
        test_run, response = self.post_json(
            "/api/tests/run",
            {"target": "repository", "csrfToken": operator_csrf},
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(test_run["state"], "completed")
        self.assertTrue(test_run["passed"])
        build_run, response = self.post_json(
            "/api/builds/run",
            {"target": "production", "csrfToken": operator_csrf},
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(build_run["state"], "completed")
        self.assertTrue(build_run["passed"])
        self.assertNotIn("stdout", build_run)
        self.assertNotIn("stderr", build_run)
        codex_run, response = self.post_json(
            "/api/codex/analyze",
            {
                "project": "control-center",
                "request_kind": "repository",
                "csrfToken": operator_csrf,
            },
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(codex_run["state"], "completed")
        self.assertEqual(codex_run["changed_files"], 0)

        chat, response = self.post_json(
            "/api/chat",
            {"message": "¿Cuál es el estado?", "csrfToken": operator_csrf},
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertFalse(chat["executable"])

        diagnostic, response = self.post_json(
            "/api/diagnostics",
            {"target": "control-center", "scope": ["metadata"], "csrfToken": operator_csrf},
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertFalse(diagnostic["executed"])

        validation, response = self.post_json(
            "/api/tests",
            {"target": "control-center", "checks": {"tests": True}, "csrfToken": operator_csrf},
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(validation["state"], "passed")

        backup, response = self.post_json(
            "/api/backups/prepare",
            {
                "project": "control-center",
                "backup_type": BackupType.PRE_DEPLOY.value,
                "source_label": "declared-project",
                "destination_label": "control-center-pre-deploy.tar.gz",
                "csrfToken": operator_csrf,
            },
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        self.assertEqual(response.status, 201)
        verified, _ = self.post_json(
            "/api/backups/verify",
            {"backup_id": backup["backup_id"], "csrfToken": operator_csrf},
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        restored, _ = self.post_json(
            "/api/backups/restore-test",
            {"backup_id": verified["backup_id"], "csrfToken": operator_csrf},
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        self.assertEqual(restored["state"], "restore_tested")

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
        deployment, response = self.post_json(
            "/api/deployments/prepare",
            {
                "project": "control-center",
                "commit": "commit-a",
                "checks": checks,
                "backup_id": restored["backup_id"],
                "csrfToken": operator_csrf,
            },
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(deployment["state"], "awaiting_approval")
        approved_deployment, _ = self.post_json(
            "/api/deployments/approve",
            {"deployment_id": deployment["deployment_id"], "csrfToken": admin_csrf},
            cookie=admin_cookie,
            csrf=admin_csrf,
        )
        self.assertEqual(approved_deployment["approved_by"], "acceptance-admin")
        deployed, _ = self.post_json(
            "/api/deployments/execute",
            {"deployment_id": deployment["deployment_id"], "csrfToken": operator_csrf},
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        self.assertEqual(deployed["state"], DeploymentState.VERIFIED.value)

        rollback, _ = self.post_json(
            "/api/rollbacks/prepare",
            {
                "project": "control-center",
                "rollback_type": "release",
                "target": "commit-a",
                "csrfToken": operator_csrf,
            },
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        await_rollback, _ = self.post_json(
            "/api/rollbacks/approve",
            {"rollback_id": rollback["rollback_id"], "csrfToken": admin_csrf},
            cookie=admin_cookie,
            csrf=admin_csrf,
        )
        self.assertEqual(await_rollback["approved_by"], "acceptance-admin")
        restored_release, _ = self.post_json(
            "/api/rollbacks/execute",
            {"rollback_id": rollback["rollback_id"], "csrfToken": operator_csrf},
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        self.assertEqual(restored_release["state"], "verified")

        monitoring, _ = self.post_json(
            "/api/monitoring/collect",
            {"csrfToken": operator_csrf},
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        self.assertEqual(monitoring["state"], "collected")

        incident, _ = self.post_json(
            "/api/incidents/create",
            {
                "project": "control-center",
                "service": "readonly-api",
                "severity": IncidentSeverity.MEDIUM.value,
                "symptom": "acceptance metadata requires review",
                "csrfToken": operator_csrf,
            },
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        analyzed, _ = self.post_json(
            f"/api/incidents/{incident['incident_id']}/analyze",
            {
                "hypothesis": "isolated provider workflow is operating as designed",
                "evidence_labels": ["provider-evidence"],
                "csrfToken": operator_csrf,
            },
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        self.assertEqual(analyzed["status"], IncidentStatus.IDENTIFIED.value)

        approval, _ = self.post_json(
            "/api/approvals/request",
            {
                "action": "read",
                "command_id": "system.memory",
                "csrfToken": operator_csrf,
            },
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        approved, _ = self.post_json(
            "/api/approvals/approve",
            {"request_id": approval["id"], "csrfToken": admin_csrf},
            cookie=admin_cookie,
            csrf=admin_csrf,
        )
        self.assertEqual(approved["status"], "approved")
        execution, _ = self.post_json(
            "/api/execution/evaluate",
            {
                "action": "read",
                "command_id": "system.memory",
                "approval_id": approval["id"],
                "csrfToken": admin_csrf,
            },
            cookie=admin_cookie,
            csrf=admin_csrf,
        )
        self.assertEqual(execution["controlled_execution"]["state"], "provider_completed")

        audit, response = self.get_json("/api/audit", cookie=admin_cookie)
        self.assertEqual(response.status, 200)
        self.assertGreaterEqual(len(audit["records"]), 10)
        serialized_audit = json.dumps(audit).lower()
        self.assertNotIn("stdout", serialized_audit)
        self.assertNotIn("stderr", serialized_audit)


if __name__ == "__main__":
    unittest.main()
