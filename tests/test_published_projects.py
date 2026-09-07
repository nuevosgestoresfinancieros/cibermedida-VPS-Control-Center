from __future__ import annotations

import json
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from api.readonly_server import create_server
from control_center import (
    ActivationManifest,
    ControlCenterApplication,
    ReadSafePublishedProjectsProvider,
)
from control_center.auth import Role
from control_center.published_projects import PROVIDER_NAME


class PublishedProjectProviderTests(unittest.TestCase):
    def test_provider_lists_only_direct_non_symlink_directories(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            node = root / "app-node"
            node.mkdir()
            node.joinpath("package.json").write_text('{"fixture": true}', encoding="utf-8")
            node.joinpath("nested").mkdir()
            python_app = root / "app-python"
            python_app.mkdir()
            python_app.joinpath("pyproject.toml").write_text("[project]\nname = 'fixture'\n", encoding="utf-8")
            (root / "logs").mkdir()
            (root / ".hidden-app").mkdir()
            (root / "not-a-project.txt").write_text("not inspected", encoding="utf-8")
            try:
                (root / "linked-app").symlink_to(node, target_is_directory=True)
            except OSError:
                pass

            evidence = ReadSafePublishedProjectsProvider(root, allowed_root=root).collect()

            self.assertEqual({item.name for item in evidence.projects}, {"app-node", "app-python"})
            self.assertEqual({item.relative_path for item in evidence.projects}, {"app-node", "app-python"})
            by_name = {item.name: item for item in evidence.projects}
            self.assertEqual(by_name["app-node"].kind, "node")
            self.assertIn("package.json", by_name["app-node"].markers)
            self.assertTrue(by_name["app-node"].git_repository is False)
            self.assertEqual(by_name["app-python"].kind, "python")
            self.assertGreaterEqual(evidence.skipped_entries, 4)

    def test_provider_rejects_non_authorized_roots(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "nested").mkdir()
            with self.assertRaises(ValueError):
                ReadSafePublishedProjectsProvider(root / "nested", allowed_root=root)
            with self.assertRaises(ValueError):
                ReadSafePublishedProjectsProvider(Path("var/www"), allowed_root=root)

    def test_service_requires_permission_and_audits_metadata_only(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "safe-app").mkdir()
            application = ControlCenterApplication(
                published_projects_provider=ReadSafePublishedProjectsProvider(root, allowed_root=root),
                published_projects_enabled=True,
            )
            application.register_user(
                user_id="published-viewer-id",
                username="published-viewer",
                password="published-viewer-password-123",
                role=Role.VIEWER,
            )
            session = application.auth.login(
                username="published-viewer",
                password="published-viewer-password-123",
            )

            result = application.published_projects.collect(session_id=session.session_id)

            self.assertEqual(result.state.value, "collected")
            self.assertEqual(len(result.projects), 1)
            records = application.audit.query(action="published_project_catalog_read")
            self.assertEqual(len(records), 1)
            serialized = json.dumps(records[0].metadata).lower()
            self.assertNotIn("stdout", serialized)
            self.assertNotIn("stderr", serialized)
            self.assertNotIn("secret", serialized)

    def test_disabled_service_fails_closed(self) -> None:
        application = ControlCenterApplication()
        application.register_user(
            user_id="published-disabled-id",
            username="published-disabled",
            password="published-disabled-password-123",
            role=Role.VIEWER,
        )
        session = application.auth.login(
            username="published-disabled",
            password="published-disabled-password-123",
        )

        result = application.published_projects.collect(session_id=session.session_id)

        self.assertEqual(result.state.value, "blocked_by_default")
        self.assertFalse(result.live_data)
        self.assertEqual(result.projects, ())


class PublishedProjectApiTests(unittest.TestCase):
    def test_endpoint_is_authenticated_manifest_scoped_and_metadata_only(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "control-center").mkdir()
            (root / "control-center" / "index.html").write_text("fixture", encoding="utf-8")
            now = datetime.now(timezone.utc)
            manifest = ActivationManifest(
                manifest_id="published-catalog-test",
                decision="approved",
                requester="published-operator",
                requester_role="OPERATOR",
                approver="published-admin",
                approver_role="ADMIN",
                policy_version="policy-test",
                effective_permissions=("VIEW_PROJECTS",),
                scope=("published-project-catalog",),
                provider_ids=(PROVIDER_NAME,),
                approved_at=(now - timedelta(minutes=1)).isoformat(),
                expires_at=(now + timedelta(hours=1)).isoformat(),
            )
            application = ControlCenterApplication(
                published_projects_provider=ReadSafePublishedProjectsProvider(root, allowed_root=root),
                published_projects_enabled=True,
            )
            application.register_user(
                user_id="published-api-viewer-id",
                username="published-api-viewer",
                password="published-api-viewer-password-123",
                role=Role.VIEWER,
            )
            server = create_server(port=0, application=application, activation_manifest=manifest)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                host, port = server.server_address
                base_url = f"http://{host}:{port}"
                with self.assertRaises(HTTPError) as context:
                    urlopen(f"{base_url}/api/projects/published", timeout=2)
                self.assertEqual(context.exception.code, 401)
                with urlopen(
                    Request(
                        f"{base_url}/api/auth/login",
                        data=json.dumps(
                            {
                                "username": "published-api-viewer",
                                "password": "published-api-viewer-password-123",
                            }
                        ).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    ),
                    timeout=2,
                ) as response:
                    cookie = response.headers["Set-Cookie"].split(";", 1)[0]
                with urlopen(
                    Request(f"{base_url}/api/projects/published", headers={"Cookie": cookie}),
                    timeout=2,
                ) as response:
                    payload = json.loads(response.read())
                self.assertEqual(payload["state"], "collected")
                self.assertEqual(payload["provider"], PROVIDER_NAME)
                self.assertEqual(payload["projects"][0]["name"], "control-center")
                self.assertEqual(payload["scope"], "direct_children_only")
                self.assertNotIn("fixture", json.dumps(payload))
                with urlopen(f"{base_url}/api/status", timeout=2) as response:
                    status = json.loads(response.read())
                self.assertEqual(status["runtime"]["publishedProjects"], "provider_enabled")
                self.assertTrue(status["dataSource"]["liveData"])
                self.assertEqual(status["publishedProjects"]["projects"], [])
                self.assertNotIn("control-center", json.dumps(status["publishedProjects"]))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
