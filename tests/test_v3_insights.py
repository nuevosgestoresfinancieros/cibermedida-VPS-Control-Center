from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from api.readonly_server import create_server
from control_center.application import ControlCenterApplication
from control_center.auth import AuthService, Permission, Role
from control_center.audit import MetadataAuditLog
from control_center.monitoring import MetricSnapshot
from control_center.state import JsonMetadataStore
from control_center.v3 import V3InsightsService, V3State


class V3InsightsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.auth = AuthService()
        self.auth.register_user(
            user_id="v3-admin-id",
            username="v3-admin",
            password="v3-admin-password-123",
            role=Role.ADMIN,
        )
        self.auth.register_user(
            user_id="v3-operator-id",
            username="v3-operator",
            password="v3-operator-password-123",
            role=Role.OPERATOR,
        )
        self.admin = self.auth.login(username="v3-admin", password="v3-admin-password-123")
        self.operator = self.auth.login(username="v3-operator", password="v3-operator-password-123")
        self.audit = MetadataAuditLog()
        self.service = V3InsightsService(auth=self.auth, audit=self.audit)

    def test_v3_contracts_record_declared_evidence_without_execution(self) -> None:
        twin = self.service.register_digital_twin(
            session_id=self.operator.session_id,
            project="control-center",
            nodes=(
                {"node_id": "web", "kind": "service", "label": "Web", "metadata": {"source": "declared"}},
                {"node_id": "repo", "kind": "repository", "label": "Repositorio", "metadata": {}},
            ),
            relations=({"source_id": "repo", "relation": "deploys", "target_id": "web"},),
        )
        self.assertEqual(twin.state, V3State.RECORDED)
        correlation = self.service.correlate_history(
            session_id=self.operator.session_id,
            subject="web",
            current_labels=("cpu_high", "deploy_recent"),
            historical_events=({"label": "cpu_high"}, {"label": "backup_verified"}),
        )
        self.assertEqual(correlation.matched_labels, ("cpu_high",))
        prediction = self.service.analyze_predictive(
            session_id=self.operator.session_id,
            project="control-center",
            snapshots=(
                MetricSnapshot("2026-09-05T00:00:00+00:00", 30, 40, 50, 0.4),
                MetricSnapshot("2026-09-05T01:00:00+00:00", 85, 45, 50, 0.4),
            ),
            horizon_hours=6,
        )
        self.assertEqual(prediction.trend["cpu_percent"], "rising")
        profile = self.service.set_autonomy_profile(
            session_id=self.admin.session_id,
            project="control-center",
            level=4,
        )
        self.assertEqual(profile.allowed_mode, "authorized_deploy_plan")
        self.assertEqual(profile.execution, "blocked_by_default")
        server = self.service.register_server(
            session_id=self.operator.session_id,
            server_id="lab-01",
            label="Laboratorio 01",
            environment="lab",
        )
        self.assertFalse(server.live_data)
        recovery = self.service.plan_recovery(
            session_id=self.operator.session_id,
            incident_id="incident-declared",
            project="control-center",
            target="release-a",
            strategy="restore_verified_release",
            backup_id="backup-declared",
        )
        self.assertEqual(recovery.state, V3State.BLOCKED_BY_DEFAULT)
        self.assertTrue(recovery.requires_approval)
        self.assertGreaterEqual(len(self.audit.records), 6)
        serialized = json.dumps([record.metadata for record in self.audit.records]).lower()
        self.assertNotIn("stdout", serialized)
        self.assertNotIn("stderr", serialized)

    def test_v3_rejects_unsafe_or_unbounded_metadata(self) -> None:
        with self.assertRaises(ValueError):
            self.service.register_digital_twin(
                session_id=self.operator.session_id,
                project="control-center",
                nodes=({"node_id": "x", "kind": "service", "label": "password=secret", "metadata": {}},),
                relations=(),
            )
        with self.assertRaises(ValueError):
            self.service.analyze_predictive(
                session_id=self.operator.session_id,
                project="control-center",
                snapshots=(MetricSnapshot("2026-09-05T00:00:00+00:00", 10, 10, 10, 0.1),),
                horizon_hours=169,
            )
        with self.assertRaises(ValueError):
            self.service.analyze_predictive(
                session_id=self.operator.session_id,
                project="control-center",
                snapshots=(MetricSnapshot("stdout=secret", 10, 10, 10, 0.1),),
                horizon_hours=6,
            )
        with self.assertRaises(PermissionError):
            self.service.set_autonomy_profile(
                session_id=self.operator.session_id,
                project="control-center",
                level=3,
            )

    def test_v3_state_store_reloads_all_metadata_only_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "v3-insights.json"
            service = V3InsightsService(
                auth=self.auth,
                audit=MetadataAuditLog(),
                state_store=JsonMetadataStore(state_path),
            )
            service.register_digital_twin(
                session_id=self.operator.session_id,
                project="control-center",
                nodes=({"node_id": "web", "kind": "service", "label": "Web", "metadata": {"source": "declared"}},),
                relations=(),
            )
            service.correlate_history(
                session_id=self.operator.session_id,
                subject="web",
                current_labels=("cpu_high",),
                historical_events=({"label": "cpu_high"},),
            )
            service.analyze_predictive(
                session_id=self.operator.session_id,
                project="control-center",
                snapshots=(MetricSnapshot("2026-09-05T00:00:00+00:00", 30, 40, 50, 0.4),),
                horizon_hours=6,
            )
            service.set_autonomy_profile(
                session_id=self.admin.session_id,
                project="control-center",
                level=4,
            )
            service.register_server(
                session_id=self.operator.session_id,
                server_id="lab-01",
                label="Laboratorio 01",
                environment="lab",
            )
            service.plan_recovery(
                session_id=self.operator.session_id,
                incident_id="incident-declared",
                project="control-center",
                target="release-a",
                strategy="restore_verified_release",
                backup_id="backup-declared",
            )

            reloaded = V3InsightsService(
                auth=self.auth,
                audit=MetadataAuditLog(),
                state_store=JsonMetadataStore(state_path),
            )

            self.assertEqual(len(reloaded.twins), 1)
            self.assertEqual(len(reloaded.correlations), 1)
            self.assertEqual(len(reloaded.predictions), 1)
            self.assertEqual(len(reloaded.autonomy_profiles), 1)
            self.assertEqual(len(reloaded.servers), 1)
            self.assertEqual(len(reloaded.recovery_plans), 1)
            self.assertEqual(reloaded.autonomy_profiles[0].execution, "blocked_by_default")
            self.assertEqual(reloaded.recovery_plans[0].state, V3State.BLOCKED_BY_DEFAULT)
            persisted = state_path.read_text(encoding="utf-8")
            self.assertNotIn("stdout", persisted.lower())
            self.assertNotIn("stderr", persisted.lower())


class V3HttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.application = ControlCenterApplication()
        self.application.register_user(
            user_id="http-v3-admin-id",
            username="http-v3-admin",
            password="http-v3-admin-password-123",
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

    def request(self, path: str, *, method: str = "GET", payload: dict | None = None, cookie: str | None = None, csrf: str | None = None):
        headers = {}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if cookie:
            headers["Cookie"] = cookie
        if csrf:
            headers["X-CSRF-Token"] = csrf
        request = Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
        with urlopen(request, timeout=3) as response:
            return json.loads(response.read()), response

    def test_v3_http_endpoints_are_authenticated_and_metadata_only(self) -> None:
        login, response = self.request(
            "/api/auth/login",
            method="POST",
            payload={"username": "http-v3-admin", "password": "http-v3-admin-password-123"},
        )
        cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        csrf = login["csrfToken"]
        twin, response = self.request(
            "/api/digital-twin/register",
            method="POST",
            payload={
                "project": "control-center",
                "nodes": [{"node_id": "web", "kind": "service", "label": "Web", "metadata": {}}],
                "relations": [],
                "csrfToken": csrf,
            },
            cookie=cookie,
            csrf=csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(twin["state"], "recorded")
        recovery, response = self.request(
            "/api/recovery/plan",
            method="POST",
            payload={
                "incident_id": "incident-declared",
                "project": "control-center",
                "target": "release-a",
                "strategy": "restore_verified_release",
                "csrfToken": csrf,
            },
            cookie=cookie,
            csrf=csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(recovery["execution"], "blocked_by_default")
        servers, response = self.request("/api/servers", cookie=cookie)
        self.assertEqual(response.status, 200)
        self.assertEqual(servers["servers"], [])
        with self.assertRaises(HTTPError) as context:
            self.request("/api/recovery")
        self.assertEqual(context.exception.code, 401)


if __name__ == "__main__":
    unittest.main()
