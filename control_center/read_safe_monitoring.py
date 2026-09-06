"""READ_SAFE monitoring adapter built on the Phase 1 restricted executor.

The adapter is opt-in. It consumes only the allowlisted ``system.memory`` and
``system.disk_usage`` command identifiers, converts their bounded output into
numeric metrics, and never returns command output or error text.
"""

from __future__ import annotations

import math
import os
from datetime import datetime, timezone
from typing import Callable, Protocol

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret
from phase1_inventory.executor import CommandResult, RestrictedExecutor

from .monitoring import MetricSnapshot


class ReadSafeCommandRunner(Protocol):
    def execute(self, command_id: str) -> CommandResult:
        ...


class ReadSafeMonitoringProvider:
    """Collect bounded host metrics through approved READ_SAFE commands."""

    name = "phase1-read-safe-monitoring"
    live_data = True

    def __init__(
        self,
        *,
        executor: ReadSafeCommandRunner | None = None,
        clock: Callable[[], str] | None = None,
    ) -> None:
        self.executor = executor or RestrictedExecutor()
        self.clock = clock or _now

    def collect(self) -> MetricSnapshot:
        memory = _run_safe(self.executor, "system.memory")
        disk = _run_safe(self.executor, "system.disk_usage")
        memory_percent = _parse_memory_percent(memory)
        disk_percent = _parse_disk_percent(disk)
        cpu_count = max(1, os.cpu_count() or 1)
        load_1m = float(os.getloadavg()[0])
        cpu_percent = min(100.0, max(0.0, (load_1m / cpu_count) * 100.0))
        return MetricSnapshot(
            timestamp=self.clock(),
            cpu_percent=round(cpu_percent, 3),
            memory_percent=round(memory_percent, 3),
            disk_percent=round(disk_percent, 3),
            load_1m=round(load_1m, 3),
            http_error_rate=0.0,
            service_restarts=0,
        )


def _run_safe(executor: ReadSafeCommandRunner, command_id: str) -> str:
    result = executor.execute(command_id)
    if not isinstance(result, CommandResult):
        raise ValueError("READ_SAFE executor returned an invalid result")
    if result.returncode != 0 or result.timed_out or result.error_code:
        raise ValueError("READ_SAFE collection failed")
    output = result.stdout
    if not isinstance(output, str) or not output.strip() or contains_secret(output) or RAW_STREAM_PATTERN.search(output):
        raise ValueError("READ_SAFE output is unsafe")
    return output


def _parse_memory_percent(output: str) -> float:
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0].rstrip(":") == "Mem":
            total = _positive_number(fields[1])
            available = _positive_number(fields[6]) if len(fields) >= 7 else _positive_number(fields[-1])
            used = max(0.0, total - available)
            return _bounded_percent((used / total) * 100.0)
    raise ValueError("memory output has no approved Mem row")


def _parse_disk_percent(output: str) -> float:
    for line in output.splitlines():
        fields = line.split()
        if not fields or fields[-1] != "/":
            continue
        percent_field = next((field for field in fields if field.endswith("%")), None)
        if percent_field is None:
            continue
        try:
            return _bounded_percent(float(percent_field.rstrip("%")))
        except ValueError as exc:
            raise ValueError("disk output has an invalid percentage") from exc
    raise ValueError("disk output has no approved root row")


def _positive_number(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise ValueError("metric value is not numeric") from exc
    if not math.isfinite(number) or number <= 0:
        raise ValueError("metric value is outside the allowed range")
    return number


def _bounded_percent(value: float) -> float:
    if not math.isfinite(value) or value < 0 or value > 100:
        raise ValueError("metric percentage is outside the allowed range")
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SyntheticReadSafeMonitoringProvider:
    """Return deterministic metrics for the isolated laboratory profile."""

    name = "synthetic-read-safe-monitoring"
    live_data = False

    def collect(self) -> MetricSnapshot:
        return MetricSnapshot(
            timestamp="2026-01-01T00:00:00+00:00",
            cpu_percent=12.5,
            memory_percent=31.0,
            disk_percent=42.0,
            load_1m=0.25,
            http_error_rate=0.0,
            service_restarts=0,
        )
