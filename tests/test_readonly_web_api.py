from __future__ import annotations

import json
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from control_center import ActivationManifest, ControlCenterApplication
from control_center.auth import Role, TotpVerifier
from control_center.monitoring import MetricSnapshot
from core_operator.policy import RiskLevel

from api.readonly_server import create_server


class ReadOnlyWebApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = create_server(port=0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        host, port = cls.server.server_address
        cls.base_url = f"http://{host}:{port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def get_json(self, path: str) -> tuple[dict, object]:
        with urlopen(f"{self.base_url}{path}", timeout=2) as response:
            return json.loads(response.read()), response

    def test_health_uses_internal_safe_checks_only(self) -> None:
        payload, response = self.get_json("/api/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertFalse(payload["real_execution"])
        self.assertFalse(payload["network_checks"])

    def test_status_is_mock_and_reports_api_transport(self) -> None:
        payload, response = self.get_json("/api/status")
        self.assertEqual(response.status, 200)
        self.assertEqual(payload["runtime"]["transport"], "local-readonly-api")
        self.assertFalse(payload["runtime"]["liveData"])
        self.assertEqual(payload["dataSource"]["backend"], True)
        self.assertEqual(payload["product"]["executionStatus"], "Ejecución real bloqueada")

    def test_status_reflects_an_explicitly_enabled_provider_without_running_it(self) -> None:
        class DeclaredProvider:
            name = "test-provider"

        application = ControlCenterApplication(
            execution_provider=DeclaredProvider(),
            providers_enabled=True,
        )
        server = create_server(port=0, application=application)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            with urlopen(f"http://{host}:{port}/api/status", timeout=2) as response:
                payload = json.loads(response.read())
            self.assertEqual(payload["runtime"]["execution"], "provider_enabled")
            self.assertEqual(payload["product"]["executionStatus"], "Ejecución READ_SAFE sintética de laboratorio")
            capability = next(item for item in payload["capabilities"] if item["capability_id"] == "controlled_execution")
            self.assertEqual(capability["state"], "provider_enabled")
            self.assertEqual(capability["provider"], "test-provider")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_read_safe_monitoring_anomaly_creates_metadata_only_incident(self) -> None:
        class FakeMonitoringProvider:
            name = "test-read-safe-monitoring"

            def collect(self) -> MetricSnapshot:
                return MetricSnapshot(
                    timestamp="2026-09-05T00:00:00+00:00",
                    cpu_percent=95,
                    memory_percent=20,
                    disk_percent=10,
                    load_1m=1.0,
                )

        application = ControlCenterApplication(
            monitoring_provider=FakeMonitoringProvider(),
            providers_enabled=True,
        )
        application.register_user(
            user_id="monitoring-admin-id",
            username="monitoring-admin",
            password="monitoring-admin-password-123",
            role=Role.ADMIN,
        )
        server = create_server(port=0, application=application)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            base_url = f"http://{host}:{port}"
            with urlopen(
                Request(
                    f"{base_url}/api/auth/login",
                    data=json.dumps(
                        {"username": "monitoring-admin", "password": "monitoring-admin-password-123"}
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                ),
                timeout=2,
            ) as response:
                login = json.loads(response.read())
                cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            csrf = login["csrfToken"]
            request = Request(
                f"{base_url}/api/monitoring/collect",
                data=json.dumps({"csrfToken": csrf}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Cookie": cookie,
                    "X-CSRF-Token": csrf,
                },
                method="POST",
            )
            with urlopen(request, timeout=2) as response:
                collected = json.loads(response.read())
            self.assertEqual(collected["state"], "collected")
            self.assertEqual(collected["incident"]["detected_by"], "read-safe-monitoring")
            self.assertEqual(collected["incident"]["status"], "OPEN")
            self.assertNotIn("stdout", json.dumps(collected).lower())
            self.assertNotIn("stderr", json.dumps(collected).lower())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_policy_and_audit_are_metadata_only(self) -> None:
        policy, _ = self.get_json("/api/policy")
        audit, _ = self.get_json("/api/audit-preview")
        self.assertGreaterEqual(len(policy["policyMatrix"]), 5)
        self.assertFalse(audit["rawOutput"])
        serialized = json.dumps(audit).lower()
        self.assertNotIn("stdout", serialized)
        self.assertNotIn("stderr", serialized)

    def test_inventory_summary_never_claims_real_collection(self) -> None:
        payload, _ = self.get_json("/api/inventory/summary")
        self.assertFalse(payload["liveData"])
        self.assertFalse(payload["persisted"])
        self.assertEqual(payload["status"], "not_collected")

    def test_production_readiness_is_authenticated_and_conservative(self) -> None:
        application = ControlCenterApplication()
        application.register_user(
            user_id="readiness-admin-id",
            username="readiness-admin",
            password="readiness-admin-password-123",
            role=Role.ADMIN,
        )
        server = create_server(port=0, application=application)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            base_url = f"http://{host}:{port}"
            with self.assertRaises(HTTPError) as context:
                urlopen(f"{base_url}/api/readiness", timeout=2)
            self.assertEqual(context.exception.code, 401)
            with urlopen(
                Request(
                    f"{base_url}/api/auth/login",
                    data=json.dumps(
                        {"username": "readiness-admin", "password": "readiness-admin-password-123"}
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                ),
                timeout=2,
            ) as response:
                login = json.loads(response.read())
                cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            with urlopen(Request(f"{base_url}/api/readiness", headers={"Cookie": cookie}), timeout=2) as response:
                report = json.loads(response.read())
            self.assertEqual(report["state"], "NO_GO")
            self.assertFalse(report["ready"])
            self.assertIn("human_authorization", report["blocking_checks"])
            self.assertIn("transport_security", report["blocking_checks"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_active_manifest_only_satisfies_human_authorization(self) -> None:
        now = datetime.now(timezone.utc)
        manifest = ActivationManifest(
            manifest_id="api-activation-001",
            decision="approved",
            requester="api-operator",
            requester_role="OPERATOR",
            approver="api-admin",
            approver_role="ADMIN",
            policy_version="policy-2026-09",
            effective_permissions=("VIEW_CORE_OPERATOR", "RUN_READ_SAFE"),
            scope=("production-readiness",),
            provider_ids=("reviewed-provider",),
            approved_at=(now - timedelta(minutes=5)).isoformat(),
            expires_at=(now + timedelta(hours=1)).isoformat(),
        )
        application = ControlCenterApplication()
        application.register_user(
            user_id="manifest-readiness-admin-id",
            username="manifest-readiness-admin",
            password="manifest-readiness-admin-password-123",
            role=Role.ADMIN,
        )
        server = create_server(
            port=0,
            application=application,
            activation_manifest=manifest,
            secure_cookies=True,
            https_terminated=True,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            base_url = f"http://{host}:{port}"
            with urlopen(
                Request(
                    f"{base_url}/api/auth/login",
                    data=json.dumps(
                        {
                            "username": "manifest-readiness-admin",
                            "password": "manifest-readiness-admin-password-123",
                        }
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                ),
                timeout=2,
            ) as response:
                login = json.loads(response.read())
                cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            with urlopen(Request(f"{base_url}/api/readiness", headers={"Cookie": cookie}), timeout=2) as response:
                report = json.loads(response.read())
            self.assertNotIn("human_authorization", report["blocking_checks"])
            self.assertNotIn("transport_security", report["blocking_checks"])
            self.assertFalse(report["ready"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_live_provider_requires_an_active_manifest_per_request(self) -> None:
        class LiveMonitoringProvider:
            name = "phase1-read-safe-monitoring"
            live_data = True

            def collect(self) -> MetricSnapshot:
                return MetricSnapshot(
                    timestamp="2026-09-05T00:00:00+00:00",
                    cpu_percent=1,
                    memory_percent=1,
                    disk_percent=1,
                    load_1m=0.1,
                )

        application = ControlCenterApplication(
            monitoring_provider=LiveMonitoringProvider(),
            providers_enabled=True,
        )
        application.register_user(
            user_id="live-provider-admin-id",
            username="live-provider-admin",
            password="live-provider-admin-password-123",
            role=Role.ADMIN,
        )
        server = create_server(port=0, application=application)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            base_url = f"http://{host}:{port}"
            with urlopen(
                Request(
                    f"{base_url}/api/auth/login",
                    data=json.dumps(
                        {
                            "username": "live-provider-admin",
                            "password": "live-provider-admin-password-123",
                        }
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                ),
                timeout=2,
            ) as response:
                cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            with self.assertRaises(HTTPError) as context:
                urlopen(Request(f"{base_url}/api/monitoring", headers={"Cookie": cookie}), timeout=2)
            self.assertEqual(context.exception.code, 403)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_live_provider_must_be_declared_in_active_manifest_scope(self) -> None:
        now = datetime.now(timezone.utc)
        manifest = ActivationManifest(
            manifest_id="api-activation-provider-scope",
            decision="approved",
            requester="api-operator",
            requester_role="OPERATOR",
            approver="api-admin",
            approver_role="ADMIN",
            policy_version="policy-2026-09",
            effective_permissions=("VIEW_MONITORING",),
            scope=("monitoring",),
            provider_ids=("another-provider",),
            approved_at=(now - timedelta(minutes=5)).isoformat(),
            expires_at=(now + timedelta(hours=1)).isoformat(),
        )

        class LiveMonitoringProvider:
            name = "phase1-read-safe-monitoring"
            live_data = True

        application = ControlCenterApplication(
            monitoring_provider=LiveMonitoringProvider(),
            providers_enabled=True,
        )
        application.register_user(
            user_id="scope-provider-admin-id",
            username="scope-provider-admin",
            password="scope-provider-admin-password-123",
            role=Role.ADMIN,
        )
        server = create_server(port=0, application=application, activation_manifest=manifest)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            base_url = f"http://{host}:{port}"
            with urlopen(
                Request(
                    f"{base_url}/api/auth/login",
                    data=json.dumps(
                        {
                            "username": "scope-provider-admin",
                            "password": "scope-provider-admin-password-123",
                        }
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                ),
                timeout=2,
            ) as response:
                cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            with self.assertRaises(HTTPError) as context:
                urlopen(Request(f"{base_url}/api/monitoring", headers={"Cookie": cookie}), timeout=2)
            self.assertEqual(context.exception.code, 403)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_live_provider_requires_the_requested_permission_in_manifest(self) -> None:
        now = datetime.now(timezone.utc)
        manifest = ActivationManifest(
            manifest_id="api-activation-provider-permission",
            decision="approved",
            requester="api-operator",
            requester_role="OPERATOR",
            approver="api-admin",
            approver_role="ADMIN",
            policy_version="policy-2026-09",
            effective_permissions=("VIEW_CORE_OPERATOR",),
            scope=("monitoring",),
            provider_ids=("phase1-read-safe-monitoring",),
            approved_at=(now - timedelta(minutes=5)).isoformat(),
            expires_at=(now + timedelta(hours=1)).isoformat(),
        )

        class LiveMonitoringProvider:
            name = "phase1-read-safe-monitoring"
            live_data = True

        application = ControlCenterApplication(
            monitoring_provider=LiveMonitoringProvider(),
            providers_enabled=True,
        )
        application.register_user(
            user_id="permission-provider-admin-id",
            username="permission-provider-admin",
            password="permission-provider-admin-password-123",
            role=Role.ADMIN,
        )
        server = create_server(port=0, application=application, activation_manifest=manifest)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            base_url = f"http://{host}:{port}"
            with urlopen(
                Request(
                    f"{base_url}/api/auth/login",
                    data=json.dumps(
                        {
                            "username": "permission-provider-admin",
                            "password": "permission-provider-admin-password-123",
                        }
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                ),
                timeout=2,
            ) as response:
                cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            with self.assertRaises(HTTPError) as context:
                urlopen(Request(f"{base_url}/api/monitoring", headers={"Cookie": cookie}), timeout=2)
            self.assertEqual(context.exception.code, 403)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_removing_manifest_file_revokes_live_provider_requests(self) -> None:
        now = datetime.now(timezone.utc)
        manifest = ActivationManifest(
            manifest_id="api-activation-revocation",
            decision="approved",
            requester="api-operator",
            requester_role="OPERATOR",
            approver="api-admin",
            approver_role="ADMIN",
            policy_version="policy-2026-09",
            effective_permissions=("VIEW_MONITORING", "VIEW_CORE_OPERATOR"),
            scope=("monitoring",),
            provider_ids=("phase1-read-safe-monitoring",),
            approved_at=(now - timedelta(minutes=5)).isoformat(),
            expires_at=(now + timedelta(hours=1)).isoformat(),
        )

        class LiveMonitoringProvider:
            name = "phase1-read-safe-monitoring"
            live_data = True

        application = ControlCenterApplication(
            monitoring_provider=LiveMonitoringProvider(),
            providers_enabled=True,
        )
        application.register_user(
            user_id="revocation-provider-admin-id",
            username="revocation-provider-admin",
            password="revocation-provider-admin-password-123",
            role=Role.ADMIN,
        )
        with TemporaryDirectory() as temporary_directory:
            manifest_path = Path(temporary_directory) / "activation.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "manifest_id": manifest.manifest_id,
                        "decision": manifest.decision,
                        "requester": manifest.requester,
                        "requester_role": manifest.requester_role,
                        "approver": manifest.approver,
                        "approver_role": manifest.approver_role,
                        "policy_version": manifest.policy_version,
                        "effective_permissions": list(manifest.effective_permissions),
                        "scope": list(manifest.scope),
                        "provider_ids": list(manifest.provider_ids),
                        "approved_at": manifest.approved_at,
                        "expires_at": manifest.expires_at,
                    }
                ),
                encoding="utf-8",
            )
            server = create_server(
                port=0,
                application=application,
                activation_manifest=manifest,
                activation_manifest_path=manifest_path,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                host, port = server.server_address
                base_url = f"http://{host}:{port}"
                with urlopen(
                    Request(
                        f"{base_url}/api/auth/login",
                        data=json.dumps(
                            {
                                "username": "revocation-provider-admin",
                                "password": "revocation-provider-admin-password-123",
                            }
                        ).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    ),
                    timeout=2,
                ) as response:
                    cookie = response.headers["Set-Cookie"].split(";", 1)[0]
                with urlopen(Request(f"{base_url}/api/monitoring", headers={"Cookie": cookie}), timeout=2) as response:
                    self.assertEqual(response.status, 200)
                manifest_path.unlink()
                with self.assertRaises(HTTPError) as context:
                    urlopen(Request(f"{base_url}/api/monitoring", headers={"Cookie": cookie}), timeout=2)
                self.assertEqual(context.exception.code, 403)
                with urlopen(Request(f"{base_url}/api/readiness", headers={"Cookie": cookie}), timeout=2) as response:
                    readiness = json.loads(response.read())
                self.assertEqual(readiness["state"], "NO_GO")
                self.assertIn("human_authorization", readiness["blocking_checks"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_documented_catalog_endpoints_are_mock_only(self) -> None:
        server, _ = self.get_json("/api/server/status")
        projects, _ = self.get_json("/api/projects")
        services, _ = self.get_json("/api/services")
        self.assertFalse(server["liveData"])
        self.assertFalse(projects["liveData"])
        self.assertFalse(services["liveData"])
        self.assertEqual(projects["projects"][0]["id"], "control-center")

    def test_raw_log_route_is_not_available(self) -> None:
        request = Request(f"{self.base_url}/api/services/web-shell/logs")
        with self.assertRaises(HTTPError) as context:
            urlopen(request, timeout=2)
        self.assertEqual(context.exception.code, 401)

    def test_document_views_are_explicitly_read_only_or_blocked(self) -> None:
        payload, _ = self.get_json("/api/views")
        self.assertGreaterEqual(len(payload["views"]), 10)
        states = {view["state"] for view in payload["views"]}
        self.assertTrue(states <= {"read_only", "planned", "blocked"})
        self.assertIn("deployments", {view["id"] for view in payload["views"]})
        self.assertIn("approval-workflow", {view["id"] for view in payload["views"]})
        self.assertIn("rollbacks", {view["id"] for view in payload["views"]})

    def test_shell_exposes_approval_and_evaluation_assets(self) -> None:
        with urlopen(f"{self.base_url}/app.js", timeout=2) as response:
            app_source = response.read().decode("utf-8")
        with urlopen(f"{self.base_url}/data/status.json", timeout=2) as response:
            status = json.loads(response.read())
        self.assertIn("appendApprovalPanel", app_source)
        self.assertIn("/api/execution/evaluate", app_source)
        self.assertIn("approval-workflow", {view["id"] for view in status["views"]})

    def test_mutating_methods_are_rejected(self) -> None:
        request = Request(f"{self.base_url}/api/status", method="POST")
        with self.assertRaises(HTTPError) as context:
            urlopen(request, timeout=2)
        self.assertEqual(context.exception.code, 405)

    def test_unknown_api_route_is_not_found(self) -> None:
        with self.assertRaises(HTTPError) as context:
            urlopen(f"{self.base_url}/api/unknown", timeout=2)
        self.assertEqual(context.exception.code, 404)

    def test_static_shell_is_served_in_spanish(self) -> None:
        with urlopen(f"{self.base_url}/", timeout=2) as response:
            body = response.read().decode("utf-8")
        self.assertEqual(response.status, 200)
        self.assertIn('<html lang="es">', body)
        self.assertIn("Ejecución real bloqueada", body)
        self.assertIn('autocomplete="one-time-code"', body)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    def test_static_shell_sends_optional_totp_value_to_login_api(self) -> None:
        with urlopen(f"{self.base_url}/app.js", timeout=2) as response:
            app_source = response.read().decode("utf-8")
        self.assertIn('payload.otp = otp', app_source)


class AuthenticatedApplicationApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        application = ControlCenterApplication()
        application.register_user(
            user_id="api-admin-id",
            username="api-admin",
            password="api-admin-password-123",
            role=Role.ADMIN,
        )
        application.register_user(
            user_id="api-operator-id",
            username="api-operator",
            password="api-operator-password-123",
            role=Role.OPERATOR,
        )
        cls.application = application
        cls.server = create_server(port=0, application=application)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        host, port = cls.server.server_address
        cls.base_url = f"http://{host}:{port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def post_json(self, path: str, payload: dict, *, cookie: str | None = None, csrf: str | None = None):
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
        with urlopen(request, timeout=2) as response:
            return json.loads(response.read()), response

    def get_json_with_cookie(self, path: str, cookie: str):
        request = Request(f"{self.base_url}{path}", headers={"Cookie": cookie})
        with urlopen(request, timeout=2) as response:
            return json.loads(response.read()), response

    def test_authentication_and_csrf_gate_application_workflows(self) -> None:
        with self.assertRaises(HTTPError) as context:
            urlopen(f"{self.base_url}/api/auth/me", timeout=2)
        self.assertEqual(context.exception.code, 401)

        payload, response = self.post_json(
            "/api/auth/login",
            {"username": "api-admin", "password": "api-admin-password-123"},
        )
        self.assertEqual(response.status, 200)
        cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        csrf = payload["csrfToken"]
        self.assertTrue(payload["authenticated"])
        self.assertIn("HttpOnly", response.headers["Set-Cookie"])

        me, _ = self.get_json_with_cookie("/api/auth/me", cookie)
        self.assertEqual(me["user"]["role"], "ADMIN")
        with self.assertRaises(HTTPError) as context:
            self.post_json("/api/chat", {"message": "estado"}, cookie=cookie)
        self.assertEqual(context.exception.code, 403)

        chat, response = self.post_json(
            "/api/chat",
            {"message": "estado", "csrfToken": csrf},
            cookie=cookie,
            csrf=csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertFalse(chat["executable"])

    def test_login_accepts_totp_for_a_user_requiring_two_factor(self) -> None:
        verifier = TotpVerifier({}, clock=lambda: 59, allowed_steps=0)
        application = ControlCenterApplication(otp_verifier=verifier)
        user = application.register_user(
            user_id="api-totp-id",
            username="api-totp",
            password="api-totp-password-123",
            role=Role.VIEWER,
            requires_2fa=True,
        )
        verifier.register_secret(user.user_id, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        server = create_server(port=0, application=application)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            request = Request(
                f"http://{host}:{port}/api/auth/login",
                data=json.dumps(
                    {
                        "username": "api-totp",
                        "password": "api-totp-password-123",
                        "otp": "287082",
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(request, timeout=2) as response:
                payload = json.loads(response.read())
            self.assertTrue(payload["authenticated"])
            self.assertEqual(payload["user"]["username"], "api-totp")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_secure_cookie_mode_marks_login_and_logout_cookies(self) -> None:
        application = ControlCenterApplication()
        application.register_user(
            user_id="secure-cookie-id",
            username="secure-cookie",
            password="secure-cookie-password-123",
            role=Role.VIEWER,
        )
        server = create_server(port=0, application=application, secure_cookies=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            base_url = f"http://{host}:{port}"
            request = Request(
                f"{base_url}/api/auth/login",
                data=json.dumps(
                    {"username": "secure-cookie", "password": "secure-cookie-password-123"}
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(request, timeout=2) as response:
                login = json.loads(response.read())
                cookie = response.headers["Set-Cookie"]
            self.assertIn("Secure", cookie)

            logout = Request(
                f"{base_url}/api/auth/logout",
                data=json.dumps({"csrfToken": login["csrfToken"]}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Cookie": cookie.split(";", 1)[0],
                    "X-CSRF-Token": login["csrfToken"],
                },
                method="POST",
            )
            with urlopen(logout, timeout=2) as response:
                expired = response.headers["Set-Cookie"]
            self.assertIn("Secure", expired)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_sensitive_plan_is_created_and_execution_remains_blocked(self) -> None:
        payload, response = self.post_json(
            "/api/auth/login",
            {"username": "api-admin", "password": "api-admin-password-123"},
        )
        cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        csrf = payload["csrfToken"]
        plan, response = self.post_json(
            "/api/operations/plan",
            {"project": "control-center", "action": "deploy", "csrfToken": csrf},
            cookie=cookie,
            csrf=csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(plan["state"], "approval_required")
        blocked, response = self.post_json(
            "/api/operations/execute",
            {"plan_id": plan["plan_id"], "csrfToken": csrf},
            cookie=cookie,
            csrf=csrf,
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(blocked["state"], "blocked_by_default")
        operations, _ = self.get_json_with_cookie("/api/operations", cookie)
        self.assertEqual(operations["plans"][0]["state"], "blocked_by_default")

    def test_read_safe_execution_requires_a_separate_explicit_approval(self) -> None:
        operator_login, response = self.post_json(
            "/api/auth/login",
            {"username": "api-operator", "password": "api-operator-password-123"},
        )
        operator_cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        operator_csrf = operator_login["csrfToken"]
        request, response = self.post_json(
            "/api/approvals/request",
            {
                "action": "read",
                "command_id": "system.memory",
                "csrfToken": operator_csrf,
            },
            cookie=operator_cookie,
            csrf=operator_csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(request["status"], "pending")
        self.assertEqual(request["actor_role"], "OPERATOR")
        self.assertEqual(request["policy_version"], "phase-3.6")
        self.assertIn("RUN_READ_SAFE", request["effective_permissions"])
        self.assertEqual(request["resource"], "command:system.memory")
        self.assertTrue(request["plan_id"].startswith("plan-"))

        admin_login, response = self.post_json(
            "/api/auth/login",
            {"username": "api-admin", "password": "api-admin-password-123"},
        )
        admin_cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        admin_csrf = admin_login["csrfToken"]
        decision, response = self.post_json(
            "/api/approvals/approve",
            {"request_id": request["id"], "csrfToken": admin_csrf},
            cookie=admin_cookie,
            csrf=admin_csrf,
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(decision["status"], "approved")
        self.assertEqual(decision["decided_by_role"], "ADMIN")
        result, response = self.post_json(
            "/api/execution/evaluate",
            {
                "action": "read",
                "command_id": "system.memory",
                "approval_id": request["id"],
                "csrfToken": admin_csrf,
            },
            cookie=admin_cookie,
            csrf=admin_csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(result["gate"]["state"], "eligible_for_controlled_execution")
        self.assertEqual(result["controlled_execution"]["state"], "blocked_by_default")

    def test_cross_cutting_contract_endpoints_are_authenticated_and_safe(self) -> None:
        payload, response = self.post_json(
            "/api/auth/login",
            {"username": "api-admin", "password": "api-admin-password-123"},
        )
        cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        csrf = payload["csrfToken"]
        report, response = self.post_json(
            "/api/validation/evaluate",
            {"target": "control-center", "checks": {"policy": True}, "csrfToken": csrf},
            cookie=cookie,
            csrf=csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(report["state"], "passed")
        impact, response = self.post_json(
            "/api/impact/analyze",
            {
                "project": "control-center",
                "action": "deploy",
                "risk": "HIGH",
                "affected_components": ["web"],
                "csrfToken": csrf,
            },
            cookie=cookie,
            csrf=csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(impact["execution"], "blocked_by_default")
        agents, _ = self.get_json_with_cookie("/api/agents", cookie)
        self.assertGreaterEqual(len(agents["agents"]), 4)
        execution, response = self.get_json_with_cookie("/api/execution", cookie)
        self.assertEqual(response.status, 200)
        self.assertFalse(execution["enabled"])
        self.assertEqual(execution["execution"], "blocked_by_default")
        self.assertEqual(execution["records"], [])
        capabilities, response = self.get_json_with_cookie("/api/capabilities", cookie)
        self.assertEqual(response.status, 200)
        capability_ids = {item["capability_id"] for item in capabilities["capabilities"]}
        self.assertIn("authentication", capability_ids)
        self.assertIn("controlled_execution", capability_ids)
        execution_capability = next(
            item for item in capabilities["capabilities"] if item["capability_id"] == "controlled_execution"
        )
        self.assertEqual(execution_capability["state"], "blocked_by_default")

    def test_execution_endpoint_rebuilds_the_core_chain_from_an_approval(self) -> None:
        approval = self.application.approvals.create_pending(
            actor="api-admin",
            action="read",
            risk_level=RiskLevel.LOW,
            reason="HTTP pipeline contract test",
            command_id="system.memory",
        )
        self.application.approvals.approve(approval.id, decided_by="independent-reviewer")
        payload, response = self.post_json(
            "/api/auth/login",
            {"username": "api-admin", "password": "api-admin-password-123"},
        )
        cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        result, response = self.post_json(
            "/api/execution/evaluate",
            {
                "action": "read",
                "command_id": "system.memory",
                "approval_id": approval.id,
                "csrfToken": payload["csrfToken"],
            },
            cookie=cookie,
            csrf=payload["csrfToken"],
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(result["plan"]["state"], "ready_to_execute")
        self.assertEqual(result["dry_run"]["state"], "completed")
        self.assertEqual(result["gate"]["state"], "eligible_for_controlled_execution")
        self.assertEqual(result["controlled_execution"]["state"], "blocked_by_default")

    def test_diagnostics_tests_and_incident_analysis_remain_metadata_only(self) -> None:
        payload, response = self.post_json(
            "/api/auth/login",
            {"username": "api-admin", "password": "api-admin-password-123"},
        )
        cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        csrf = payload["csrfToken"]
        diagnostic, response = self.post_json(
            "/api/diagnostics",
            {"target": "control-center", "scope": ["policy"], "csrfToken": csrf},
            cookie=cookie,
            csrf=csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(diagnostic["state"], "blocked_by_default")
        self.assertFalse(diagnostic["executed"])

        snapshot, response = self.post_json(
            "/api/monitoring/snapshot",
            {
                "cpu_percent": 95,
                "memory_percent": 20,
                "disk_percent": 10,
                "load_1m": 1.5,
                "service_restarts": 0,
                "csrfToken": csrf,
            },
            cookie=cookie,
            csrf=csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertFalse(snapshot["liveData"])
        self.assertIn("cpu_high", snapshot["anomalies"])

        collection, response = self.post_json(
            "/api/monitoring/collect",
            {"csrfToken": csrf},
            cookie=cookie,
            csrf=csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(collection["state"], "blocked_by_default")
        self.assertIsNone(collection["snapshot"])

        report, response = self.post_json(
            "/api/tests",
            {"target": "control-center", "checks": {"policy": True}, "csrfToken": csrf},
            cookie=cookie,
            csrf=csrf,
        )
        self.assertEqual(response.status, 201)
        self.assertFalse(report["executed_real_tests"])

        incident, response = self.post_json(
            "/api/incidents/create",
            {
                "project": "control-center",
                "service": "web-shell",
                "severity": "LOW",
                "symptom": "mock health metadata",
                "csrfToken": csrf,
            },
            cookie=cookie,
            csrf=csrf,
        )
        self.assertEqual(response.status, 201)
        analyzed, response = self.post_json(
            f"/api/incidents/{incident['incident_id']}/analyze",
            {
                "hypothesis": "caller metadata requires review",
                "evidence_labels": ["mock-health"],
                "csrfToken": csrf,
            },
            cookie=cookie,
            csrf=csrf,
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(analyzed["status"], "IDENTIFIED")
        resolved, response = self.post_json(
            "/api/incidents/transition",
            {
                "incident_id": incident["incident_id"],
                "status": "RESOLVED",
                "note": "metadata-only review completed",
                "resolution": "validated caller-supplied evidence",
                "rollback": "no rollback executed",
                "csrfToken": csrf,
            },
            cookie=cookie,
            csrf=csrf,
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(resolved["status"], "RESOLVED")
        self.assertEqual(resolved["resolution"], "validated caller-supplied evidence")
        self.assertEqual(resolved["rollback"], "no rollback executed")


if __name__ == "__main__":
    unittest.main()
