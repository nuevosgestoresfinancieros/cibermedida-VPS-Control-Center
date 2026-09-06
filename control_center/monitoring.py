"""In-memory monitoring and anomaly detection contracts.

The default service only evaluates caller-supplied snapshots. A collector can
be injected explicitly, but its output must first pass the same bounded,
metadata-only validation before it is recorded.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Mapping, Protocol

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret

from .state import JsonMetadataStore

@dataclass(frozen=True)
class MetricSnapshot:
    timestamp: str
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    load_1m: float
    http_error_rate: float = 0.0
    service_restarts: int = 0
    http_latency_ms: float = 0.0
    http_requests_per_minute: int = 0
    process_count: int = 0
    container_count: int = 0
    deployment_ids: tuple[str, ...] = ()
    incident_ids: tuple[str, ...] = ()


class MonitoringProvider(Protocol):
    name: str

    def collect(self) -> MetricSnapshot:
        """Return a bounded snapshot without exposing raw operational output."""


class MonitoringCollectionState(str, Enum):
    BLOCKED_BY_DEFAULT = "blocked_by_default"
    COLLECTED = "collected"
    REJECTED = "rejected"


@dataclass(frozen=True)
class MonitoringCollectionResult:
    state: str
    provider: str | None
    snapshot: MetricSnapshot | None
    anomalies: tuple[str, ...]
    reason: str


class MonitoringService:
    def __init__(
        self,
        *,
        max_history: int = 256,
        provider: MonitoringProvider | None = None,
        provider_enabled: bool = False,
        state_store: JsonMetadataStore | None = None,
    ) -> None:
        self.max_history = max_history
        self.provider = provider
        self.provider_enabled = provider_enabled
        self.state_store = state_store
        self._snapshots: list[MetricSnapshot] = []
        if self.state_store is not None:
            for raw_snapshot in self.state_store.load():
                snapshot = _decode_snapshot(raw_snapshot)
                self._snapshots.append(snapshot)
            del self._snapshots[:-self.max_history]

    @property
    def snapshots(self) -> tuple[MetricSnapshot, ...]:
        return tuple(self._snapshots)

    def record(self, snapshot: MetricSnapshot) -> MetricSnapshot:
        if not _valid_snapshot(snapshot):
            raise ValueError("snapshot is invalid")
        updated_snapshots = [*self._snapshots, snapshot]
        del updated_snapshots[:-self.max_history]
        if self.state_store is not None:
            self.state_store.save(_encode_snapshot(item) for item in updated_snapshots)
        self._snapshots = updated_snapshots
        return snapshot

    def latest(self) -> MetricSnapshot | None:
        return self._snapshots[-1] if self._snapshots else None

    def anomalies(self, snapshot: MetricSnapshot | None = None) -> tuple[str, ...]:
        current = snapshot or self.latest()
        if current is None:
            return ()
        findings: list[str] = []
        if current.cpu_percent >= 90:
            findings.append("cpu_high")
        if current.memory_percent >= 90:
            findings.append("memory_high")
        if current.disk_percent >= 90:
            findings.append("disk_high")
        if current.http_error_rate >= 0.10:
            findings.append("http_error_rate_high")
        if current.service_restarts >= 10:
            findings.append("service_restarts_high")
        if current.http_latency_ms >= 1_000:
            findings.append("http_latency_high")
        return tuple(findings)

    def collect(self) -> MonitoringCollectionResult:
        if not self.provider_enabled or self.provider is None:
            return MonitoringCollectionResult(
                state=MonitoringCollectionState.BLOCKED_BY_DEFAULT,
                provider=None,
                snapshot=None,
                anomalies=(),
                reason="monitoring provider is disabled",
            )
        provider_name = getattr(self.provider, "name", "injected")
        try:
            snapshot = self.provider.collect()
        except Exception:
            return MonitoringCollectionResult(
                state=MonitoringCollectionState.REJECTED,
                provider=str(provider_name),
                snapshot=None,
                anomalies=(),
                reason="monitoring provider failed without raw output",
            )
        if not _valid_snapshot(snapshot):
            return MonitoringCollectionResult(
                state=MonitoringCollectionState.REJECTED,
                provider=str(provider_name),
                snapshot=None,
                anomalies=(),
                reason="monitoring provider returned unsafe data",
            )
        recorded = self.record(snapshot)
        return MonitoringCollectionResult(
            state=MonitoringCollectionState.COLLECTED,
            provider=str(provider_name),
            snapshot=recorded,
            anomalies=self.anomalies(recorded),
            reason="snapshot accepted as metadata-only evidence",
        )


def empty_snapshot() -> MetricSnapshot:
    return MetricSnapshot(
        timestamp=datetime.now(timezone.utc).isoformat(),
        cpu_percent=0.0,
        memory_percent=0.0,
        disk_percent=0.0,
        load_1m=0.0,
    )


def _valid_snapshot(value: object) -> bool:
    if not isinstance(value, MetricSnapshot):
        return False
    if not isinstance(value.timestamp, str) or not value.timestamp.strip() or len(value.timestamp) > 128:
        return False
    if contains_secret(value.timestamp) or RAW_STREAM_PATTERN.search(value.timestamp):
        return False
    numeric = (
        value.cpu_percent, value.memory_percent, value.disk_percent, value.load_1m,
        value.http_error_rate, value.http_latency_ms,
    )
    if any(isinstance(item, bool) or not isinstance(item, (int, float)) or not math.isfinite(float(item)) for item in numeric):
        return False
    if any(float(item) < 0 for item in numeric):
        return False
    if any(float(item) > 100 for item in (value.cpu_percent, value.memory_percent, value.disk_percent)):
        return False
    if value.http_error_rate > 1:
        return False
    if not isinstance(value.service_restarts, int) or isinstance(value.service_restarts, bool) or not 0 <= value.service_restarts <= 1_000_000:
        return False
    if any(
        not isinstance(item, int) or isinstance(item, bool) or item < 0 or item > 10_000_000
        for item in (value.http_requests_per_minute, value.process_count, value.container_count)
    ):
        return False
    for values in (value.deployment_ids, value.incident_ids):
        if not isinstance(values, tuple) or len(values) > 128 or any(not isinstance(item, str) or not item.strip() or contains_secret(item) for item in values):
            return False
    return True


def _encode_snapshot(snapshot: MetricSnapshot) -> dict[str, object]:
    return {
        "timestamp": snapshot.timestamp,
        "cpu_percent": snapshot.cpu_percent,
        "memory_percent": snapshot.memory_percent,
        "disk_percent": snapshot.disk_percent,
        "load_1m": snapshot.load_1m,
        "http_error_rate": snapshot.http_error_rate,
        "service_restarts": snapshot.service_restarts,
        "http_latency_ms": snapshot.http_latency_ms,
        "http_requests_per_minute": snapshot.http_requests_per_minute,
        "process_count": snapshot.process_count,
        "container_count": snapshot.container_count,
        "deployment_ids": list(snapshot.deployment_ids),
        "incident_ids": list(snapshot.incident_ids),
    }


def _decode_snapshot(value: Mapping[str, object]) -> MetricSnapshot:
    try:
        snapshot = MetricSnapshot(
            timestamp=value["timestamp"],
            cpu_percent=value["cpu_percent"],
            memory_percent=value["memory_percent"],
            disk_percent=value["disk_percent"],
            load_1m=value["load_1m"],
            http_error_rate=value.get("http_error_rate", 0.0),
            service_restarts=value.get("service_restarts", 0),
            http_latency_ms=value.get("http_latency_ms", 0.0),
            http_requests_per_minute=value.get("http_requests_per_minute", 0),
            process_count=value.get("process_count", 0),
            container_count=value.get("container_count", 0),
            deployment_ids=tuple(value.get("deployment_ids", [])),
            incident_ids=tuple(value.get("incident_ids", [])),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("monitoring state record is invalid") from exc
    if not _valid_snapshot(snapshot):
        raise ValueError("monitoring state snapshot is invalid")
    return snapshot
