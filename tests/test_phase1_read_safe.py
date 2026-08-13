from __future__ import annotations

import ast
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from phase1_inventory.commands import COMMANDS, READ_SAFE_COMMANDS
from phase1_inventory.executor import CommandRejectedError, CommandResult, RestrictedExecutor
from phase1_inventory.inventory import build_inventory
from phase1_inventory.normalizers import normalize_disk_usage, normalize_memory
from phase1_inventory.redaction import SecretDetectedError, redact, scan_for_secrets
from phase1_inventory.validation import PersistenceDisabledError, persist_inventory, validate_inventory

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "inventory.schema.json"
PACKAGE = ROOT / "phase1_inventory"


class RestrictedExecutorTests(unittest.TestCase):
    def test_allowed_command_executes_as_argument_array(self) -> None:
        completed = subprocess.CompletedProcess(args=["free", "-b"], returncode=0, stdout="ok", stderr="")
        with patch("phase1_inventory.executor.subprocess.run", return_value=completed) as run:
            result = RestrictedExecutor(cwd=ROOT).execute("system.memory")
        self.assertEqual(result.stdout, "ok")
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["free", "-b"])
        self.assertNotIn("shell", kwargs)

    def test_unknown_command_is_rejected(self) -> None:
        with self.assertRaises(KeyError):
            RestrictedExecutor().execute("missing.command")

    def test_read_sensitive_is_rejected(self) -> None:
        with self.assertRaises(CommandRejectedError):
            RestrictedExecutor().execute("system.os_release")

    def test_read_privileged_is_rejected(self) -> None:
        with self.assertRaises(CommandRejectedError):
            RestrictedExecutor().execute("privileged.firewall_summary")

    def test_forbidden_is_rejected(self) -> None:
        with self.assertRaises(CommandRejectedError):
            RestrictedExecutor().execute("forbidden.docker_inspect")

    def test_timeout_is_reported_without_raise(self) -> None:
        with patch("phase1_inventory.executor.subprocess.run", side_effect=subprocess.TimeoutExpired(["free"], 1)):
            result = RestrictedExecutor().execute("system.memory")
        self.assertTrue(result.timed_out)
        self.assertEqual(result.error_code, "timeout")

    def test_missing_command_is_reported(self) -> None:
        with patch("phase1_inventory.executor.subprocess.run", side_effect=FileNotFoundError("not found")):
            result = RestrictedExecutor().execute("system.memory")
        self.assertEqual(result.error_code, "command_unavailable")

    def test_permission_denied_is_reported(self) -> None:
        with patch("phase1_inventory.executor.subprocess.run", side_effect=PermissionError("denied")):
            result = RestrictedExecutor().execute("system.memory")
        self.assertEqual(result.error_code, "permission_denied")


class NormalizationTests(unittest.TestCase):
    def test_disk_usage_normalization(self) -> None:
        result = CommandResult(
            "system.disk_usage",
            0,
            "Filesystem Type 1B-blocks Used Available Use% Mounted on\n/dev/root ext4 100 40 60 40% /\n",
            "",
        )
        volumes = normalize_disk_usage(result)
        self.assertEqual(volumes[0]["mount"], "/")
        self.assertEqual(volumes[0]["size_bytes"], 100)

    def test_memory_normalization(self) -> None:
        result = CommandResult(
            "system.memory",
            0,
            "               total        used        free      shared  buff/cache   available\nMem:            100          40          10           0          50          60\nSwap:            20           1          19\n",
            "",
        )
        normalized = normalize_memory(result)
        self.assertEqual(normalized["memory"]["total_bytes"], 100)
        self.assertEqual(normalized["swap"]["total_bytes"], 20)


class RedactionAndScanTests(unittest.TestCase):
    def test_redaction_masks_fictitious_secret_patterns(self) -> None:
        payload = {
            "url": "postgres://demo_user:demo_pass@example.invalid/db",
            "header": "Authorization: Bearer fictitiousTokenValue12345",
            "plain": "safe",
        }
        result = redact(payload)
        self.assertIn("url_credentials", result.rules)
        self.assertIn("authorization_header", result.rules)
        self.assertNotIn("demo_pass", str(result.value))

    def test_secret_scan_fails_closed_on_fictitious_secret(self) -> None:
        with self.assertRaises(SecretDetectedError):
            scan_for_secrets({"token": "token=fictitiousTokenValue12345"})


class InventoryValidationTests(unittest.TestCase):
    def test_inventory_validates_against_schema(self) -> None:
        results = {
            "system.memory": CommandResult("system.memory", 0, "               total        used        free      shared  buff/cache   available\nMem:            100          40          10           0          50          60\nSwap:            20           1          19\n", ""),
            "system.disk_usage": CommandResult("system.disk_usage", 0, "Filesystem Type 1B-blocks Used Available Use% Mounted on\n/dev/root ext4 100 40 60 40% /\n", ""),
            "system.uptime": CommandResult("system.uptime", 0, "up 1 day, load average: 0.01, 0.02, 0.03\n", ""),
            "git.status": CommandResult("git.status", 0, "## agent/fase1-inventory...origin/agent/fase1-inventory\n", ""),
        }
        inventory = build_inventory(results, host_alias="test-host")
        validate_inventory(inventory, SCHEMA)

    def test_persistence_disabled_by_default(self) -> None:
        with TemporaryDirectory() as directory:
            with self.assertRaises(PersistenceDisabledError):
                persist_inventory({"safe": "value"}, Path(directory) / "INVENTORY.json")


class StaticSafetyTests(unittest.TestCase):
    def test_no_subprocess_shell_keyword_enabled(self) -> None:
        for path in PACKAGE.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    for keyword in node.keywords:
                        if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                            self.assertIsNot(keyword.value.value, True, path)

    def test_no_sudo_in_defined_commands(self) -> None:
        for spec in COMMANDS.values():
            self.assertNotIn("sudo", spec.argv)
        for spec in READ_SAFE_COMMANDS.values():
            self.assertFalse(spec.requires_sudo)


if __name__ == "__main__":
    unittest.main()
