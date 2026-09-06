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
from control_center.audit import MetadataAuditLog
from control_center.auth import AuthService, Role
from control_center.inventory import (
    InventoryCollectionState,
    InventoryService,
    SyntheticInventoryProvider,
)
from control_center.state import JsonMetadataStore


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "inventory.schema.json"


class CountingProvider:
    name = "counting-provider"
    live_data = False

    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.calls = 0

    def collect(self) -> dict:
        self.calls += 1
        return self.payload


class InventoryServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.auth = AuthService()
        self.user = self.auth.register_user(
            user_id="inventory-operator-id",
            username="inventory-operator",
            password="inventory-operator-password-123",
            role=Role.OPERATOR,
        )
        self.session = self.auth.login(
            username="inventory-operator",
            password="inventory-operator-password-123",
        )
        self.audit = MetadataAuditLog()

    def test_disabled_provider_does_not_collect_or_persist(self) -> None:
        provider = CountingProvider({})
        service = InventoryService(
            auth=self.auth,
            audit=self.audit,
            provider=provider,
            provider_enabled=False,
            schema_path=SCHEMA,
        )

        result = service.collect(session_id=self.session.session_id)

        self.assertEqual(result.state, InventoryCollectionState.NOT_COLLECTED)
        self.assertIsNone(result.inventory)
        self.assertFalse(result.persisted)
        self.assertEqual(provider.calls, 0)
        self.assertEqual(self.audit.records[-1].result, "not_collected")

    def test_synthetic_provider_is_validated_and_retained_only_in_memory(self) -> None:
        service = InventoryService(
            auth=self.auth,
            audit=self.audit,
            provider=SyntheticInventoryProvider(SCHEMA),
            provider_enabled=True,
            schema_path=SCHEMA,
        )

        result = service.collect(session_id=self.session.session_id)

        self.assertEqual(result.state, InventoryCollectionState.COLLECTED)
        self.assertFalse(result.live_data)
        self.assertFalse(result.persisted)
        self.assertEqual(result.inventory["schema_version"], "0.2.0")
        self.assertEqual(service.latest, result)
        serialized_audit = json.dumps(self.audit.records, default=str).lower()
        self.assertNotIn("stdout", serialized_audit)
        self.assertNotIn("stderr", serialized_audit)
        self.assertNotIn("inventory.json", serialized_audit)

    def test_inventory_persistence_is_opt_in_and_survives_reload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_path = Path(temporary_directory) / "inventory-workflow.json"
            service = InventoryService(
                auth=self.auth,
                audit=self.audit,
                provider=SyntheticInventoryProvider(SCHEMA),
                provider_enabled=True,
                schema_path=SCHEMA,
                state_store=JsonMetadataStore(state_path),
            )
            result = service.collect(session_id=self.session.session_id)
            reloaded = InventoryService(
                auth=self.auth,
                audit=self.audit,
                provider=SyntheticInventoryProvider(SCHEMA),
                provider_enabled=True,
                schema_path=SCHEMA,
                state_store=JsonMetadataStore(state_path),
            )

            self.assertTrue(result.persisted)
            self.assertEqual(reloaded.latest.state, InventoryCollectionState.COLLECTED)
            self.assertTrue(reloaded.latest.persisted)
            self.assertEqual(reloaded.latest.inventory["collection"]["host_alias"], "laboratory")
            self.assertNotEqual(state_path.name, "INVENTORY.json")
            self.assertNotIn("stdout", state_path.read_text(encoding="utf-8").lower())

    def test_persisted_inventory_is_hidden_when_provider_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_path = Path(temporary_directory) / "inventory-workflow.json"
            enabled = InventoryService(
                auth=self.auth,
                audit=self.audit,
                provider=SyntheticInventoryProvider(SCHEMA),
                provider_enabled=True,
                schema_path=SCHEMA,
                state_store=JsonMetadataStore(state_path),
            )
            enabled.collect(session_id=self.session.session_id)

            disabled = InventoryService(
                auth=self.auth,
                audit=self.audit,
                provider=SyntheticInventoryProvider(SCHEMA),
                provider_enabled=False,
                schema_path=SCHEMA,
                state_store=JsonMetadataStore(state_path),
            )

            self.assertIsNone(disabled.latest)
            self.assertEqual(disabled.summary()["status"], InventoryCollectionState.NOT_COLLECTED.value)

    def test_persisted_inventory_must_match_enabled_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_path = Path(temporary_directory) / "inventory-workflow.json"
            enabled = InventoryService(
                auth=self.auth,
                audit=self.audit,
                provider=SyntheticInventoryProvider(SCHEMA),
                provider_enabled=True,
                schema_path=SCHEMA,
                state_store=JsonMetadataStore(state_path),
            )
            enabled.collect(session_id=self.session.session_id)

            with self.assertRaises(ValueError):
                InventoryService(
                    auth=self.auth,
                    audit=self.audit,
                    provider=CountingProvider({}),
                    provider_enabled=True,
                    schema_path=SCHEMA,
                    state_store=JsonMetadataStore(state_path),
                )

    def test_unsafe_provider_result_fails_closed_without_audit_leak(self) -> None:
        provider = CountingProvider({"token": "password=fictitious-secret"})
        service = InventoryService(
            auth=self.auth,
            audit=self.audit,
            provider=provider,
            provider_enabled=True,
            schema_path=SCHEMA,
        )

        result = service.collect(session_id=self.session.session_id)

        self.assertEqual(result.state, InventoryCollectionState.FAILED)
        self.assertIsNone(result.inventory)
        self.assertNotIn("fictitious-secret", json.dumps(self.audit.records, default=str))


class InventoryHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.application = ControlCenterApplication(
            inventory_provider=SyntheticInventoryProvider(SCHEMA),
            inventory_enabled=True,
            inventory_schema_path=SCHEMA,
        )
        self.application.register_user(
            user_id="inventory-http-operator-id",
            username="inventory-http-operator",
            password="inventory-http-operator-password-123",
            role=Role.OPERATOR,
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

    def get_json(self, path: str, *, cookie: str | None = None) -> dict:
        headers = {"Cookie": cookie} if cookie else {}
        with urlopen(Request(f"{self.base_url}{path}", headers=headers), timeout=2) as response:
            return json.loads(response.read())

    def post_json(self, path: str, payload: dict, *, cookie: str, csrf: str) -> dict:
        request = Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": csrf,
            },
            method="POST",
        )
        with urlopen(request, timeout=2) as response:
            return json.loads(response.read())

    def test_inventory_endpoint_requires_authentication(self) -> None:
        with self.assertRaises(HTTPError) as context:
            urlopen(f"{self.base_url}/api/inventory", timeout=2)
        self.assertEqual(context.exception.code, 401)

    def test_enabled_inventory_is_visible_and_collectable_over_http(self) -> None:
        login_request = Request(
            f"{self.base_url}/api/auth/login",
            data=json.dumps(
                {
                    "username": "inventory-http-operator",
                    "password": "inventory-http-operator-password-123",
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(login_request, timeout=2) as response:
            login = json.loads(response.read())
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]

        status = self.get_json("/api/status")
        capability = next(item for item in status["capabilities"] if item["capability_id"] == "inventory")
        self.assertEqual(capability["state"], "provider_enabled")
        self.assertFalse(capability["live_data"])

        collected = self.post_json(
            "/api/inventory/collect",
            {"csrfToken": login["csrfToken"]},
            cookie=cookie,
            csrf=login["csrfToken"],
        )
        self.assertEqual(collected["state"], "collected")
        self.assertFalse(collected["persisted"])
        self.assertEqual(collected["inventory"]["collection"]["host_alias"], "laboratory")

        current = self.get_json("/api/inventory", cookie=cookie)
        self.assertEqual(current["summary"]["status"], "collected")
        self.assertEqual(current["collection"]["provider"], "synthetic-read-safe-inventory")
        self.assertFalse((ROOT / "INVENTORY.json").exists())


if __name__ == "__main__":
    unittest.main()
