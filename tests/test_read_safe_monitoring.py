from __future__ import annotations

import unittest

from phase1_inventory.executor import CommandResult

from control_center.monitoring import MonitoringCollectionState, MonitoringService
from control_center.read_safe_execution import ReadSafeExecutionProvider, SyntheticReadSafeExecutionProvider
from control_center.read_safe_monitoring import ReadSafeMonitoringProvider, SyntheticReadSafeMonitoringProvider


class FakeReadSafeExecutor:
    def __init__(self, results: dict[str, CommandResult]) -> None:
        self.results = results
        self.calls: list[str] = []

    def execute(self, command_id: str) -> CommandResult:
        self.calls.append(command_id)
        return self.results[command_id]


class ReadSafeMonitoringProviderTests(unittest.TestCase):
    def test_collects_bounded_metrics_without_returning_command_output(self) -> None:
        executor = FakeReadSafeExecutor(
            {
                "system.memory": CommandResult(
                    "system.memory",
                    0,
                    "              total        used        free      shared  buff/cache   available\nMem: 100 40 10 0 50 60\n",
                    "",
                ),
                "system.disk_usage": CommandResult(
                    "system.disk_usage",
                    0,
                    "Filesystem Type 1B-blocks Used Available Use% Mounted on\n/dev/root ext4 100 40 60 40% /\n",
                    "",
                ),
            }
        )
        provider = ReadSafeMonitoringProvider(executor=executor, clock=lambda: "2026-01-01T00:00:00+00:00")
        snapshot = provider.collect()
        self.assertEqual(executor.calls, ["system.memory", "system.disk_usage"])
        self.assertEqual(snapshot.timestamp, "2026-01-01T00:00:00+00:00")
        self.assertEqual(snapshot.memory_percent, 40.0)
        self.assertEqual(snapshot.disk_percent, 40.0)
        self.assertGreaterEqual(snapshot.cpu_percent, 0.0)
        self.assertNotIn("Mem:", str(snapshot))

    def test_provider_failure_is_rejected_without_raw_output(self) -> None:
        executor = FakeReadSafeExecutor(
            {
                "system.memory": CommandResult("system.memory", 1, "", "password=secret"),
                "system.disk_usage": CommandResult("system.disk_usage", 0, "unused", ""),
            }
        )
        service = MonitoringService(provider=ReadSafeMonitoringProvider(executor=executor), provider_enabled=True)
        result = service.collect()
        self.assertEqual(result.state, MonitoringCollectionState.REJECTED)
        self.assertIsNone(result.snapshot)
        self.assertNotIn("secret", str(result).lower())

    def test_execution_provider_accepts_only_allowlisted_read_safe_commands(self) -> None:
        executor = FakeReadSafeExecutor(
            {
                "system.memory": CommandResult("system.memory", 0, "safe metadata", ""),
                "system.ports": CommandResult("system.ports", 0, "sensitive metadata", ""),
            }
        )
        provider = ReadSafeExecutionProvider(executor=executor)
        evidence = provider.run(actor="operator", action="read", command_id="system.memory")
        self.assertEqual(evidence.provider, "phase1-read-safe-execution")
        self.assertEqual(evidence.result, "read_safe_metadata_collected")
        self.assertEqual(executor.calls, ["system.memory"])
        with self.assertRaises(ValueError):
            provider.run(actor="operator", action="read", command_id="system.ports")
        with self.assertRaises(ValueError):
            provider.run(actor="operator", action="deploy", command_id="system.memory")

    def test_execution_provider_fails_closed_on_raw_or_secret_output(self) -> None:
        executor = FakeReadSafeExecutor(
            {"system.memory": CommandResult("system.memory", 0, "password=secret", "")}
        )
        provider = ReadSafeExecutionProvider(executor=executor)
        with self.assertRaises(ValueError):
            provider.run(actor="operator", action="read", command_id="system.memory")

    def test_synthetic_monitoring_provider_does_not_read_the_host(self) -> None:
        provider = SyntheticReadSafeMonitoringProvider()
        snapshot = provider.collect()
        self.assertFalse(provider.live_data)
        self.assertEqual(provider.name, "synthetic-read-safe-monitoring")
        self.assertEqual(snapshot.memory_percent, 31.0)

    def test_synthetic_execution_provider_does_not_need_an_executor(self) -> None:
        provider = SyntheticReadSafeExecutionProvider()
        evidence = provider.run(actor="operator", action="read", command_id="system.memory")
        self.assertFalse(provider.live_data)
        self.assertEqual(evidence.provider, "synthetic-read-safe-execution")
        self.assertEqual(evidence.result, "synthetic_read_safe_metadata_collected")
        with self.assertRaises(ValueError):
            provider.run(actor="operator", action="read", command_id="system.ports")


if __name__ == "__main__":
    unittest.main()
