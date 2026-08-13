from __future__ import annotations

import ast
import inspect
import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from phase1_inventory.collectors import collect_os_release
from phase1_inventory.commands import COMMANDS, READ_SAFE_COMMANDS
from phase1_inventory.executor import CommandRejectedError, CommandResult, RestrictedExecutor
from phase1_inventory.inventory import build_inventory
from phase1_inventory.normalizers import (
    normalize_cpu_summary,
    normalize_disk_usage,
    normalize_git_head_commit,
    normalize_git_status,
    normalize_memory,
    normalize_os_release,
)
from phase1_inventory.pipeline import collect_read_safe_inventory
from phase1_inventory.redaction import SecretDetectedError, redact, scan_for_secrets
from phase1_inventory.validation import PersistenceDisabledError, persist_inventory, validate_inventory

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "inventory.schema.json"
PACKAGE = ROOT / "phase1_inventory"

OS_RELEASE_FIXTURE = """NAME=\"Ubuntu\"
ID=ubuntu
VERSION_ID=\"24.04\"
VERSION_CODENAME=noble
PRETTY_NAME=\"Ubuntu 24.04 LTS\"
HOME_URL=\"https://ubuntu.com/\"
"""

LSCPU_FIXTURE = json.dumps(
    {
        "lscpu": [
            {"field": "Architecture:", "data": "x86_64"},
            {"field": "CPU(s):", "data": "8"},
            {"field": "Thread(s) per core:", "data": "2"},
            {"field": "Core(s) per socket:", "data": "4"},
            {"field": "Socket(s):", "data": "1"},
            {"field": "Model name:", "data": "Synthetic CPU 3.00GHz"},
            {"field": "Flags:", "data": "fpu vme de pse tsc"},
            {"field": "Vulnerability Itlb multihit:", "data": "Not affected"},
            {"field": "L3 cache:", "data": "16 MiB"},
            {"field": "NUMA node0 CPU(s):", "data": "0-7"},
        ]
    }
)


def a2_results() -> dict[str, CommandResult]:
    return {
        "system.os_release": CommandResult("system.os_release", 0, "NAME=Ubuntu\nID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\nEXTRA=drop\n", ""),
        "system.kernel": CommandResult("system.kernel", 0, "6.8.0-synthetic\n", ""),
        "system.architecture": CommandResult("system.architecture", 0, "x86_64\n", ""),
        "system.cpu_summary": CommandResult("system.cpu_summary", 0, LSCPU_FIXTURE, ""),
        "git.status": CommandResult("git.status", 0, "## agent/fase1-inventory...origin/agent/fase1-inventory\n M secret.env\n", ""),
        "git.head_commit": CommandResult("git.head_commit", 0, "abcdef123456\n", ""),
    }


class RestrictedExecutorTests(unittest.TestCase):
    def test_allowed_command_executes_as_argument_array(self) -> None:
        completed = subprocess.CompletedProcess(args=["free", "-b"], returncode=0, stdout="ok", stderr="")
        with patch("phase1_inventory.executor.subprocess.run", return_value=completed) as run:
            result = RestrictedExecutor().execute("system.memory")
        self.assertEqual(result.stdout, "ok")
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["free", "-b"])
        self.assertNotIn("shell", kwargs)
        self.assertIsNone(kwargs["cwd"])

    def test_unknown_command_is_rejected(self) -> None:
        with self.assertRaises(KeyError):
            RestrictedExecutor().execute("missing.command")

    def test_os_release_is_internal_not_executor_command(self) -> None:
        with self.assertRaises(KeyError):
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

    def test_git_cwd_is_fixed_to_project_root(self) -> None:
        completed = subprocess.CompletedProcess(args=["git"], returncode=0, stdout="## main\n", stderr="")
        with patch("phase1_inventory.executor.subprocess.run", return_value=completed) as run:
            RestrictedExecutor().execute("git.status")
        self.assertEqual(run.call_args.kwargs["cwd"], ROOT)

    def test_executor_accepts_no_external_cwd(self) -> None:
        signature = inspect.signature(RestrictedExecutor)
        self.assertEqual(len(signature.parameters), 0)


class OsReleaseCollectorTests(unittest.TestCase):
    def test_os_release_valid(self) -> None:
        result = CommandResult("system.os_release", 0, "NAME=Ubuntu\nID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n", "")
        normalized = normalize_os_release(result)
        self.assertEqual(normalized["name"], "Ubuntu")
        self.assertEqual(normalized["version"], "24.04")
        self.assertEqual(normalized["codename"], "noble")

    def test_os_release_discards_unapproved_keys(self) -> None:
        seen_paths = []

        def read_text(path: Path, encoding: str) -> str:
            seen_paths.append(path)
            self.assertEqual(encoding, "utf-8")
            return OS_RELEASE_FIXTURE

        with patch("pathlib.Path.read_text", read_text):
            result = collect_os_release()
        self.assertEqual(seen_paths, [Path("/etc/os-release")])
        self.assertIn("NAME=Ubuntu", result.stdout)
        self.assertIn("VERSION_CODENAME=noble", result.stdout)
        self.assertNotIn("PRETTY_NAME", result.stdout)
        self.assertNotIn("HOME_URL", result.stdout)

    def test_os_release_collector_accepts_no_external_path(self) -> None:
        signature = inspect.signature(collect_os_release)
        self.assertEqual(len(signature.parameters), 0)


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

    def test_cpu_valid(self) -> None:
        cpu = normalize_cpu_summary(CommandResult("system.cpu_summary", 0, LSCPU_FIXTURE, ""))
        self.assertEqual(cpu["architecture"], "x86_64")
        self.assertEqual(cpu["model"], "Synthetic CPU 3.00GHz")
        self.assertEqual(cpu["logical_cpus"], 8)
        self.assertEqual(cpu["sockets"], 1)
        self.assertEqual(cpu["cores_per_socket"], 4)
        self.assertEqual(cpu["threads_per_core"], 2)

    def test_cpu_discards_flags(self) -> None:
        cpu = normalize_cpu_summary(CommandResult("system.cpu_summary", 0, LSCPU_FIXTURE, ""))
        self.assertNotIn("flags", {key.lower() for key in cpu})
        self.assertNotIn("fpu", str(cpu))

    def test_cpu_discards_unapproved_fields(self) -> None:
        cpu = normalize_cpu_summary(CommandResult("system.cpu_summary", 0, LSCPU_FIXTURE, ""))
        self.assertNotIn("vulnerability", str(cpu).lower())
        self.assertNotIn("cache", str(cpu).lower())
        self.assertNotIn("numa", str(cpu).lower())

    def test_cpu_parse_error_is_recorded_without_raw_output(self) -> None:
        result = CommandResult("system.cpu_summary", 0, "not-json password=synthetic-secret", "raw stderr")
        cpu = normalize_cpu_summary(result)
        self.assertEqual(cpu["metadata"]["collection_status"], "unknown")
        self.assertEqual(cpu["metadata"]["errors"][0]["category"], "parse_error")
        self.assertNotIn("not-json", str(cpu))
        self.assertNotIn("synthetic-secret", str(cpu))
        self.assertNotIn("raw stderr", str(cpu))

    def test_git_status_clean(self) -> None:
        repo = normalize_git_status(CommandResult("git.status", 0, "## main...origin/main\n", ""))
        self.assertEqual(repo["branch"], "main")
        self.assertFalse(repo["dirty"])

    def test_git_status_dirty_without_filenames(self) -> None:
        repo = normalize_git_status(CommandResult("git.status", 0, "## main...origin/main\n M app.py\n?? .env\n", ""))
        self.assertTrue(repo["dirty"])
        self.assertNotIn("app.py", str(repo))
        self.assertNotIn(".env", str(repo))

    def test_git_head_commit_valid(self) -> None:
        self.assertEqual(normalize_git_head_commit(CommandResult("git.head_commit", 0, "AbCdEf123456\n", "")), "abcdef123456")

    def test_git_head_commit_invalid(self) -> None:
        invalid_values = ["abcdef1234567", "abcxyz123", "abc def", "HEAD"]
        for value in invalid_values:
            with self.subTest(value=value):
                self.assertIsNone(normalize_git_head_commit(CommandResult("git.head_commit", 0, value + "\n", "")))


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

    def test_a2_instance_validates_against_schema(self) -> None:
        inventory = build_inventory(a2_results(), host_alias="synthetic-host")
        validate_inventory(inventory, SCHEMA)
        self.assertEqual(inventory["server"]["cpu"]["logical_cpus"], 8)
        self.assertEqual(inventory["repositories"][0]["head_commit"], "abcdef123456")

    def test_secret_scan_passes_with_synthetic_a2_inventory(self) -> None:
        inventory = build_inventory(a2_results(), host_alias="synthetic-host")
        scan_for_secrets(inventory)

    def test_repository_partial_metadata_is_not_collected_without_git_status(self) -> None:
        inventory = build_inventory({"git.head_commit": CommandResult("git.head_commit", 0, "abcdef123456\n", "")}, host_alias="synthetic-host")
        self.assertEqual(inventory["repositories"][0]["metadata"]["collection_status"], "unknown")
        self.assertEqual(inventory["repositories"][0]["head_commit"], "abcdef123456")

    def test_pipeline_complete_a2_with_mocks(self) -> None:
        command_results = a2_results()

        def execute(command_id: str) -> CommandResult:
            return command_results[command_id]

        with patch("phase1_inventory.pipeline.INTERNAL_READ_SAFE_COLLECTORS", {"system.os_release": lambda: command_results["system.os_release"]}), patch(
            "phase1_inventory.pipeline.RestrictedExecutor.execute", side_effect=execute
        ):
            inventory = collect_read_safe_inventory(SCHEMA, command_ids=tuple(command_results))
        self.assertEqual(inventory["server"]["os"]["name"], "Ubuntu")
        self.assertTrue(inventory["repositories"][0]["dirty"])
        self.assertNotIn("secret.env", str(inventory))

    def test_pipeline_rejects_unknown_command_before_subprocess(self) -> None:
        with patch("phase1_inventory.executor.subprocess.run") as run:
            with self.assertRaises(KeyError):
                collect_read_safe_inventory(SCHEMA, command_ids=("missing.command",))
        run.assert_not_called()

    def test_pipeline_rejects_read_sensitive_command_before_subprocess(self) -> None:
        with patch("phase1_inventory.executor.subprocess.run") as run:
            with self.assertRaises(CommandRejectedError):
                collect_read_safe_inventory(SCHEMA, command_ids=("system.ports",))
        run.assert_not_called()

    def test_pipeline_rejects_forbidden_command_before_subprocess(self) -> None:
        with patch("phase1_inventory.executor.subprocess.run") as run:
            with self.assertRaises(CommandRejectedError):
                collect_read_safe_inventory(SCHEMA, command_ids=("forbidden.docker_inspect",))
        run.assert_not_called()

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

    def test_no_python3_dash_c_command(self) -> None:
        for spec in COMMANDS.values():
            self.assertNotEqual(spec.argv[:2], ("python3", "-c"))
        for path in PACKAGE.glob("*.py"):
            self.assertNotIn('"python3", "-c"', path.read_text(encoding="utf-8"))

    def test_no_shell_true_in_source(self) -> None:
        for path in PACKAGE.glob("*.py"):
            self.assertNotIn("shell=True", path.read_text(encoding="utf-8"))



if __name__ == "__main__":
    unittest.main()
