from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = ROOT / "web" / "readonly-shell"


class ControlCenterVNextContractTests(unittest.TestCase):
    def test_dashboard_mock_contains_visual_operational_contract(self) -> None:
        payload = json.loads((WEB_ROOT / "data" / "status.json").read_text(encoding="utf-8"))
        dashboard = payload["dashboard"]
        self.assertGreaterEqual(dashboard["healthScore"], 0)
        self.assertLessEqual(dashboard["healthScore"], 100)
        self.assertEqual(len(dashboard["metrics"]), 4)
        self.assertGreaterEqual(len(dashboard["infrastructure"]), 2)
        self.assertTrue(dashboard["activity"])
        self.assertTrue(dashboard["projects"])
        serialized = json.dumps(payload).lower()
        self.assertNotIn("stdout=", serialized)
        self.assertNotIn("stderr=", serialized)
        self.assertNotIn("secret=", serialized)

    def test_ui_shell_preserves_read_only_visual_contract(self) -> None:
        html = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
        javascript = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
        self.assertIn('lang="es"', html)
        self.assertIn('data-infrastructure-map', html)
        self.assertIn('data-command-palette', html)
        self.assertIn('data-sidebar-toggle', html)
        self.assertIn('data-sidebar-context-copy', html)
        self.assertIn('data-detail-drawer', html)
        self.assertIn('id="client-guide"', html)
        self.assertIn("Guía para el cliente", html)
        self.assertIn("Ejecución real bloqueada", html)
        self.assertIn("blocked_by_default", html)
        self.assertIn("navigationGroups", javascript)
        self.assertIn("createCompactTable", javascript)
        self.assertIn("section.hidden = section.id !== currentTarget", javascript)
        self.assertIn("window.location.hash", javascript)
        self.assertIn("data-command-results", javascript)
        self.assertNotIn("localStorage", javascript)
        self.assertNotIn("sessionStorage", javascript)
        self.assertNotIn("shell=True", javascript)

    def test_client_guide_is_part_of_the_static_contract(self) -> None:
        payload = json.loads((WEB_ROOT / "data" / "status.json").read_text(encoding="utf-8"))
        navigation_targets = {item["target"] for item in payload["navigation"]}
        self.assertIn("client-guide", navigation_targets)
        document = (ROOT / "docs" / "client-guide.md").read_text(encoding="utf-8")
        self.assertIn("# Guía para el cliente", document)
        self.assertIn("blocked_by_default", document)
        self.assertIn("sin ejecutar comandos reales", document)

    def test_documentation_describes_current_boundaries(self) -> None:
        architecture = (ROOT / "docs" / "CURRENT_ARCHITECTURE.md").read_text(encoding="utf-8")
        gaps = (ROOT / "docs" / "GAP_ANALYSIS.md").read_text(encoding="utf-8")
        plan = (ROOT / "docs" / "IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
        for document in (architecture, gaps, plan):
            self.assertIn("blocked_by_default", document)
            self.assertIn("producción", document)
        self.assertIn("OperationManifest", architecture)
        self.assertIn("HTTPS", gaps)
        self.assertIn("Ejecución controlada futura", plan)


if __name__ == "__main__":
    unittest.main()
