"""Metadata-only V3 insight and recovery contracts.

These services make the V3 concepts usable from the application without
discovering the VPS or performing operational work. Every input is declared
by the caller, bounded, audited and kept separate from execution providers.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Sequence
from uuid import uuid4

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret

from .audit import MetadataAuditLog
from .auth import AuthService, Permission
from .monitoring import MetricSnapshot
from .state import JsonMetadataStore


class V3State(str, Enum):
    RECORDED = "recorded"
    BLOCKED_BY_DEFAULT = "blocked_by_default"


@dataclass(frozen=True)
class DigitalTwinNode:
    node_id: str
    kind: str
    label: str
    metadata: Mapping[str, str]


@dataclass(frozen=True)
class DigitalTwinRelation:
    source_id: str
    relation: str
    target_id: str


@dataclass(frozen=True)
class DigitalTwinRecord:
    twin_id: str
    project: str
    nodes: tuple[DigitalTwinNode, ...]
    relations: tuple[DigitalTwinRelation, ...]
    state: V3State
    source: str
    created_at: str


@dataclass(frozen=True)
class HistoricalCorrelation:
    correlation_id: str
    subject: str
    current_labels: tuple[str, ...]
    matched_labels: tuple[str, ...]
    event_count: int
    confidence: float
    state: V3State
    source: str
    created_at: str


@dataclass(frozen=True)
class PredictiveReport:
    report_id: str
    project: str
    horizon_hours: int
    trend: Mapping[str, str]
    findings: tuple[str, ...]
    confidence: float
    state: V3State
    source: str
    created_at: str


@dataclass(frozen=True)
class ProjectAutonomyProfile:
    profile_id: str
    project: str
    level: int
    allowed_mode: str
    requires_approval: bool
    execution: str
    state: V3State
    created_at: str


@dataclass(frozen=True)
class ServerRecord:
    server_id: str
    label: str
    environment: str
    connection_state: str
    live_data: bool
    state: V3State
    created_at: str


@dataclass(frozen=True)
class RecoveryPlan:
    recovery_id: str
    incident_id: str
    project: str
    target: str
    strategy: str
    requested_by: str
    backup_id: str | None
    requires_approval: bool
    execution: str
    state: V3State
    reason: str
    created_at: str


class V3InsightsService:
    """Store declared V3 evidence and plans without activating operations."""

    def __init__(
        self,
        *,
        auth: AuthService,
        audit: MetadataAuditLog,
        state_store: JsonMetadataStore | None = None,
    ) -> None:
        self.auth = auth
        self.audit = audit
        self.state_store = state_store
        self._twins: dict[str, DigitalTwinRecord] = {}
        self._correlations: dict[str, HistoricalCorrelation] = {}
        self._predictions: dict[str, PredictiveReport] = {}
        self._autonomy: dict[str, ProjectAutonomyProfile] = {}
        self._servers: dict[str, ServerRecord] = {}
        self._recovery: dict[str, RecoveryPlan] = {}
        if self.state_store is not None:
            self._load_state()

    @property
    def twins(self) -> tuple[DigitalTwinRecord, ...]:
        return tuple(self._twins.values())

    @property
    def correlations(self) -> tuple[HistoricalCorrelation, ...]:
        return tuple(self._correlations.values())

    @property
    def predictions(self) -> tuple[PredictiveReport, ...]:
        return tuple(self._predictions.values())

    @property
    def autonomy_profiles(self) -> tuple[ProjectAutonomyProfile, ...]:
        return tuple(self._autonomy.values())

    @property
    def servers(self) -> tuple[ServerRecord, ...]:
        return tuple(self._servers.values())

    @property
    def recovery_plans(self) -> tuple[RecoveryPlan, ...]:
        return tuple(self._recovery.values())

    def register_digital_twin(
        self,
        *,
        session_id: str,
        project: str,
        nodes: Sequence[Mapping[str, Any]],
        relations: Sequence[Mapping[str, Any]],
    ) -> DigitalTwinRecord:
        user = self.auth.require(session_id, Permission.VIEW_PROJECTS)
        project = _safe_text(project, "project")
        if len(nodes) > 64 or len(relations) > 128:
            raise ValueError("digital twin is too large")
        parsed_nodes = tuple(_node(value) for value in nodes)
        node_ids = {node.node_id for node in parsed_nodes}
        if len(node_ids) != len(parsed_nodes):
            raise ValueError("digital twin contains duplicate nodes")
        parsed_relations = tuple(_relation(value) for value in relations)
        if any(item.source_id not in node_ids or item.target_id not in node_ids for item in parsed_relations):
            raise ValueError("digital twin relation references an unknown node")
        record = DigitalTwinRecord(
            twin_id=f"twin-{uuid4()}",
            project=project,
            nodes=parsed_nodes,
            relations=parsed_relations,
            state=V3State.RECORDED,
            source="caller_metadata",
            created_at=_now(),
        )
        self._store(self._twins, record.twin_id, record)
        self._audit(user, project, "digital_twin_recorded", "LOW", record.state.value, {"twin_id": record.twin_id, "node_count": len(parsed_nodes), "relation_count": len(parsed_relations)})
        return record

    def correlate_history(
        self,
        *,
        session_id: str,
        subject: str,
        current_labels: Sequence[str],
        historical_events: Sequence[Mapping[str, Any]],
    ) -> HistoricalCorrelation:
        user = self.auth.require(session_id, Permission.VIEW_MONITORING)
        subject = _safe_text(subject, "subject")
        labels = tuple(_safe_text(item, "current label") for item in current_labels)
        if len(labels) > 32 or len(historical_events) > 256:
            raise ValueError("historical correlation is too large")
        historical_labels = tuple(
            _safe_text(event.get("label"), "event label")
            for event in historical_events
            if isinstance(event, Mapping)
        )
        if len(historical_labels) != len(historical_events):
            raise ValueError("historical event is invalid")
        matched = tuple(sorted(set(labels).intersection(historical_labels)))
        confidence = round(len(matched) / max(len(set(labels)), 1), 3)
        result = HistoricalCorrelation(
            correlation_id=f"correlation-{uuid4()}",
            subject=subject,
            current_labels=labels,
            matched_labels=matched,
            event_count=len(historical_events),
            confidence=confidence,
            state=V3State.RECORDED,
            source="caller_metadata",
            created_at=_now(),
        )
        self._store(self._correlations, result.correlation_id, result)
        self._audit(user, subject, "historical_correlation_recorded", "MEDIUM", result.state.value, {"correlation_id": result.correlation_id, "matched_count": len(matched)})
        return result

    def analyze_predictive(
        self,
        *,
        session_id: str,
        project: str,
        snapshots: Sequence[MetricSnapshot],
        horizon_hours: int,
    ) -> PredictiveReport:
        user = self.auth.require(session_id, Permission.VIEW_MONITORING)
        project = _safe_text(project, "project")
        if not isinstance(horizon_hours, int) or isinstance(horizon_hours, bool) or not 1 <= horizon_hours <= 168:
            raise ValueError("horizon_hours must be between 1 and 168")
        if not 1 <= len(snapshots) <= 64 or any(not _valid_snapshot(item) for item in snapshots):
            raise ValueError("snapshots are invalid or outside the bounded range")
        first, last = snapshots[0], snapshots[-1]
        trend: dict[str, str] = {}
        findings: list[str] = []
        for name in ("cpu_percent", "memory_percent", "disk_percent", "load_1m", "http_error_rate"):
            start = float(getattr(first, name))
            end = float(getattr(last, name))
            delta = end - start
            trend[name] = "rising" if delta > 5 else "falling" if delta < -5 else "stable"
            if end >= 90 or (delta >= 20 and end >= 70):
                findings.append(f"{name}_requires_review")
        confidence = round(min(0.95, 0.45 + (len(snapshots) * 0.05)), 3)
        report = PredictiveReport(
            report_id=f"prediction-{uuid4()}",
            project=project,
            horizon_hours=horizon_hours,
            trend=trend,
            findings=tuple(sorted(findings)),
            confidence=confidence,
            state=V3State.RECORDED,
            source="caller_metadata",
            created_at=_now(),
        )
        self._store(self._predictions, report.report_id, report)
        self._audit(user, project, "predictive_analysis_recorded", "MEDIUM", report.state.value, {"report_id": report.report_id, "snapshot_count": len(snapshots), "confidence": confidence})
        return report

    def set_autonomy_profile(self, *, session_id: str, project: str, level: int) -> ProjectAutonomyProfile:
        user = self.auth.require(session_id, Permission.MANAGE_POLICIES)
        project = _safe_text(project, "project")
        if not isinstance(level, int) or isinstance(level, bool) or not 0 <= level <= 5:
            raise ValueError("autonomy level must be between 0 and 5")
        modes = (
            "observation",
            "diagnosis",
            "proposals",
            "low_risk_proposals",
            "authorized_deploy_plan",
            "limited_recovery_plan",
        )
        profile = ProjectAutonomyProfile(
            profile_id=f"autonomy-{uuid4()}",
            project=project,
            level=level,
            allowed_mode=modes[level],
            requires_approval=level >= 2,
            execution="blocked_by_default",
            state=V3State.RECORDED,
            created_at=_now(),
        )
        self._store(self._autonomy, project, profile)
        self._audit(user, project, "autonomy_profile_recorded", "HIGH" if level >= 3 else "MEDIUM", profile.execution, {"profile_id": profile.profile_id, "level": level})
        return profile

    def register_server(self, *, session_id: str, server_id: str, label: str, environment: str) -> ServerRecord:
        user = self.auth.require(session_id, Permission.VIEW_PROJECTS)
        server_id = _safe_text(server_id, "server_id")
        label = _safe_text(label, "label")
        environment = _safe_text(environment, "environment")
        record = ServerRecord(
            server_id=server_id,
            label=label,
            environment=environment,
            connection_state="not_connected",
            live_data=False,
            state=V3State.RECORDED,
            created_at=_now(),
        )
        self._store(self._servers, server_id, record)
        self._audit(user, label, "server_metadata_registered", "LOW", record.state.value, {"server_id": server_id, "live_data": False})
        return record

    def plan_recovery(
        self,
        *,
        session_id: str,
        incident_id: str,
        project: str,
        target: str,
        strategy: str,
        backup_id: str | None = None,
    ) -> RecoveryPlan:
        user = self.auth.require(session_id, Permission.ROLLBACK)
        values = (_safe_text(incident_id, "incident_id"), _safe_text(project, "project"), _safe_text(target, "target"), _safe_text(strategy, "strategy"))
        if backup_id is not None:
            backup_id = _safe_text(backup_id, "backup_id")
        plan = RecoveryPlan(
            recovery_id=f"recovery-{uuid4()}",
            incident_id=values[0],
            project=values[1],
            target=values[2],
            strategy=values[3],
            requested_by=user.username,
            backup_id=backup_id,
            requires_approval=True,
            execution="blocked_by_default",
            state=V3State.BLOCKED_BY_DEFAULT,
            reason="recovery requires independent approval and a reviewed provider",
            created_at=_now(),
        )
        self._store(self._recovery, plan.recovery_id, plan)
        self._audit(user, plan.project, "recovery_plan_recorded", "CRITICAL", plan.state.value, {"recovery_id": plan.recovery_id, "incident_id": plan.incident_id})
        return plan

    def _audit(self, user: Any, project: str, action: str, risk: str, result: str, metadata: Mapping[str, Any]) -> None:
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=project,
            action=action,
            risk=risk,
            authorization="metadata-only-contract",
            result=result,
            metadata=dict(metadata),
        )

    def _store(self, collection: dict[str, Any], key: str, value: Any) -> None:
        previous = collection.get(key)
        collection[key] = value
        try:
            self._persist()
        except Exception:
            if previous is None:
                collection.pop(key, None)
            else:
                collection[key] = previous
            raise

    def _persist(self) -> None:
        if self.state_store is None:
            return
        records = [
            *(_encode_record("twin", item) for item in self._twins.values()),
            *(_encode_record("correlation", item) for item in self._correlations.values()),
            *(_encode_record("prediction", item) for item in self._predictions.values()),
            *(_encode_record("autonomy", item) for item in self._autonomy.values()),
            *(_encode_record("server", item) for item in self._servers.values()),
            *(_encode_record("recovery", item) for item in self._recovery.values()),
        ]
        if len(records) > 1024:
            raise ValueError("V3 metadata state is too large")
        self.state_store.save(records)

    def _load_state(self) -> None:
        assert self.state_store is not None
        for raw_record in self.state_store.load():
            if set(raw_record) != {"kind", "data"}:
                raise ValueError("V3 state record format is invalid")
            kind = raw_record["kind"]
            data = raw_record["data"]
            if not isinstance(kind, str) or not isinstance(data, Mapping):
                raise ValueError("V3 state record format is invalid")
            if kind == "twin":
                item = _decode_twin(data)
                _ensure_new_id(self._twins, item.twin_id, "twin")
                self._twins[item.twin_id] = item
            elif kind == "correlation":
                item = _decode_correlation(data)
                _ensure_new_id(self._correlations, item.correlation_id, "correlation")
                self._correlations[item.correlation_id] = item
            elif kind == "prediction":
                item = _decode_prediction(data)
                _ensure_new_id(self._predictions, item.report_id, "prediction")
                self._predictions[item.report_id] = item
            elif kind == "autonomy":
                item = _decode_autonomy(data)
                _ensure_new_id(self._autonomy, item.project, "autonomy project")
                self._autonomy[item.project] = item
            elif kind == "server":
                item = _decode_server(data)
                _ensure_new_id(self._servers, item.server_id, "server")
                self._servers[item.server_id] = item
            elif kind == "recovery":
                item = _decode_recovery(data)
                _ensure_new_id(self._recovery, item.recovery_id, "recovery")
                self._recovery[item.recovery_id] = item
            else:
                raise ValueError("V3 state record kind is invalid")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise ValueError(f"{label} is invalid")
    if contains_secret(value) or RAW_STREAM_PATTERN.search(value) or any(ord(char) < 32 for char in value):
        raise ValueError(f"{label} contains unsafe metadata")
    return value.strip()


def _metadata(value: object) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > 16:
        raise ValueError("node metadata is invalid")
    result: dict[str, str] = {}
    for key, item in value.items():
        safe_key = _safe_text(key, "metadata key")
        safe_value = _safe_text(item, "metadata value")
        result[safe_key] = safe_value
    return result


def _node(value: object) -> DigitalTwinNode:
    if not isinstance(value, Mapping):
        raise ValueError("digital twin node is invalid")
    return DigitalTwinNode(
        node_id=_safe_text(value.get("node_id"), "node_id"),
        kind=_safe_text(value.get("kind"), "node kind"),
        label=_safe_text(value.get("label"), "node label"),
        metadata=_metadata(value.get("metadata")),
    )


def _relation(value: object) -> DigitalTwinRelation:
    if not isinstance(value, Mapping):
        raise ValueError("digital twin relation is invalid")
    return DigitalTwinRelation(
        source_id=_safe_text(value.get("source_id"), "relation source"),
        relation=_safe_text(value.get("relation"), "relation"),
        target_id=_safe_text(value.get("target_id"), "relation target"),
    )


def _encode_record(kind: str, value: object) -> dict[str, object]:
    if isinstance(value, DigitalTwinRecord):
        data = {
            "twin_id": value.twin_id,
            "project": value.project,
            "nodes": [_encode_node(item) for item in value.nodes],
            "relations": [_encode_relation(item) for item in value.relations],
            "state": value.state.value,
            "source": value.source,
            "created_at": value.created_at,
        }
    elif isinstance(value, HistoricalCorrelation):
        data = {
            "correlation_id": value.correlation_id,
            "subject": value.subject,
            "current_labels": list(value.current_labels),
            "matched_labels": list(value.matched_labels),
            "event_count": value.event_count,
            "confidence": value.confidence,
            "state": value.state.value,
            "source": value.source,
            "created_at": value.created_at,
        }
    elif isinstance(value, PredictiveReport):
        data = {
            "report_id": value.report_id,
            "project": value.project,
            "horizon_hours": value.horizon_hours,
            "trend": dict(value.trend),
            "findings": list(value.findings),
            "confidence": value.confidence,
            "state": value.state.value,
            "source": value.source,
            "created_at": value.created_at,
        }
    elif isinstance(value, ProjectAutonomyProfile):
        data = {
            "profile_id": value.profile_id,
            "project": value.project,
            "level": value.level,
            "allowed_mode": value.allowed_mode,
            "requires_approval": value.requires_approval,
            "execution": value.execution,
            "state": value.state.value,
            "created_at": value.created_at,
        }
    elif isinstance(value, ServerRecord):
        data = {
            "server_id": value.server_id,
            "label": value.label,
            "environment": value.environment,
            "connection_state": value.connection_state,
            "live_data": value.live_data,
            "state": value.state.value,
            "created_at": value.created_at,
        }
    elif isinstance(value, RecoveryPlan):
        data = {
            "recovery_id": value.recovery_id,
            "incident_id": value.incident_id,
            "project": value.project,
            "target": value.target,
            "strategy": value.strategy,
            "requested_by": value.requested_by,
            "backup_id": value.backup_id,
            "requires_approval": value.requires_approval,
            "execution": value.execution,
            "state": value.state.value,
            "reason": value.reason,
            "created_at": value.created_at,
        }
    else:
        raise ValueError("V3 metadata record type is invalid")
    return {"kind": kind, "data": data}


def _encode_node(value: DigitalTwinNode) -> dict[str, object]:
    return {
        "node_id": value.node_id,
        "kind": value.kind,
        "label": value.label,
        "metadata": dict(value.metadata),
    }


def _encode_relation(value: DigitalTwinRelation) -> dict[str, str]:
    return {
        "source_id": value.source_id,
        "relation": value.relation,
        "target_id": value.target_id,
    }


def _decode_twin(value: Mapping[str, Any]) -> DigitalTwinRecord:
    _require_fields(value, {"twin_id", "project", "nodes", "relations", "state", "source", "created_at"})
    try:
        raw_nodes = value["nodes"]
        raw_relations = value["relations"]
        if not isinstance(raw_nodes, list) or not isinstance(raw_relations, list):
            raise ValueError("digital twin collections are invalid")
        nodes = tuple(_node(item) for item in raw_nodes)
        relations = tuple(_relation(item) for item in raw_relations)
        node_ids = {item.node_id for item in nodes}
        if len(node_ids) != len(nodes) or len(nodes) > 64 or len(relations) > 128:
            raise ValueError("digital twin collections are invalid")
        if any(item.source_id not in node_ids or item.target_id not in node_ids for item in relations):
            raise ValueError("digital twin relation references an unknown node")
        return DigitalTwinRecord(
            twin_id=_safe_text(value["twin_id"], "twin_id"),
            project=_safe_text(value["project"], "project"),
            nodes=nodes,
            relations=relations,
            state=_expected_state(value["state"], V3State.RECORDED),
            source=_safe_text(value["source"], "source"),
            created_at=_safe_text(value["created_at"], "created_at"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("V3 twin state record is invalid") from exc


def _decode_correlation(value: Mapping[str, Any]) -> HistoricalCorrelation:
    _require_fields(value, {"correlation_id", "subject", "current_labels", "matched_labels", "event_count", "confidence", "state", "source", "created_at"})
    try:
        current_labels = _text_tuple(value["current_labels"], "current labels", 32)
        matched_labels = _text_tuple(value["matched_labels"], "matched labels", 32)
        event_count = _bounded_int(value["event_count"], "event count", 0, 256)
        confidence = _bounded_float(value["confidence"], "confidence", 0.0, 1.0)
        return HistoricalCorrelation(
            correlation_id=_safe_text(value["correlation_id"], "correlation_id"),
            subject=_safe_text(value["subject"], "subject"),
            current_labels=current_labels,
            matched_labels=matched_labels,
            event_count=event_count,
            confidence=confidence,
            state=_expected_state(value["state"], V3State.RECORDED),
            source=_safe_text(value["source"], "source"),
            created_at=_safe_text(value["created_at"], "created_at"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("V3 correlation state record is invalid") from exc


def _decode_prediction(value: Mapping[str, Any]) -> PredictiveReport:
    _require_fields(value, {"report_id", "project", "horizon_hours", "trend", "findings", "confidence", "state", "source", "created_at"})
    try:
        trend = _metadata(value["trend"])
        findings = _text_tuple(value["findings"], "findings", 32)
        return PredictiveReport(
            report_id=_safe_text(value["report_id"], "report_id"),
            project=_safe_text(value["project"], "project"),
            horizon_hours=_bounded_int(value["horizon_hours"], "horizon_hours", 1, 168),
            trend=trend,
            findings=findings,
            confidence=_bounded_float(value["confidence"], "confidence", 0.0, 1.0),
            state=_expected_state(value["state"], V3State.RECORDED),
            source=_safe_text(value["source"], "source"),
            created_at=_safe_text(value["created_at"], "created_at"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("V3 prediction state record is invalid") from exc


def _decode_autonomy(value: Mapping[str, Any]) -> ProjectAutonomyProfile:
    _require_fields(value, {"profile_id", "project", "level", "allowed_mode", "requires_approval", "execution", "state", "created_at"})
    try:
        level = _bounded_int(value["level"], "autonomy level", 0, 5)
        modes = (
            "observation",
            "diagnosis",
            "proposals",
            "low_risk_proposals",
            "authorized_deploy_plan",
            "limited_recovery_plan",
        )
        if value["allowed_mode"] != modes[level] or value["execution"] != "blocked_by_default":
            raise ValueError("autonomy state is invalid")
        if not isinstance(value["requires_approval"], bool) or value["requires_approval"] != (level >= 2):
            raise ValueError("autonomy approval state is invalid")
        return ProjectAutonomyProfile(
            profile_id=_safe_text(value["profile_id"], "profile_id"),
            project=_safe_text(value["project"], "project"),
            level=level,
            allowed_mode=_safe_text(value["allowed_mode"], "allowed_mode"),
            requires_approval=value["requires_approval"],
            execution=_safe_text(value["execution"], "execution"),
            state=_expected_state(value["state"], V3State.RECORDED),
            created_at=_safe_text(value["created_at"], "created_at"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("V3 autonomy state record is invalid") from exc


def _decode_server(value: Mapping[str, Any]) -> ServerRecord:
    _require_fields(value, {"server_id", "label", "environment", "connection_state", "live_data", "state", "created_at"})
    try:
        if value["connection_state"] != "not_connected" or value["live_data"] is not False:
            raise ValueError("server state is invalid")
        return ServerRecord(
            server_id=_safe_text(value["server_id"], "server_id"),
            label=_safe_text(value["label"], "label"),
            environment=_safe_text(value["environment"], "environment"),
            connection_state=_safe_text(value["connection_state"], "connection_state"),
            live_data=False,
            state=_expected_state(value["state"], V3State.RECORDED),
            created_at=_safe_text(value["created_at"], "created_at"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("V3 server state record is invalid") from exc


def _decode_recovery(value: Mapping[str, Any]) -> RecoveryPlan:
    _require_fields(value, {"recovery_id", "incident_id", "project", "target", "strategy", "requested_by", "backup_id", "requires_approval", "execution", "state", "reason", "created_at"})
    try:
        backup_id = value["backup_id"]
        if backup_id is not None:
            backup_id = _safe_text(backup_id, "backup_id")
        if value["execution"] != "blocked_by_default" or value["requires_approval"] is not True:
            raise ValueError("recovery state is invalid")
        return RecoveryPlan(
            recovery_id=_safe_text(value["recovery_id"], "recovery_id"),
            incident_id=_safe_text(value["incident_id"], "incident_id"),
            project=_safe_text(value["project"], "project"),
            target=_safe_text(value["target"], "target"),
            strategy=_safe_text(value["strategy"], "strategy"),
            requested_by=_safe_text(value["requested_by"], "requested_by"),
            backup_id=backup_id,
            requires_approval=True,
            execution=_safe_text(value["execution"], "execution"),
            state=_expected_state(value["state"], V3State.BLOCKED_BY_DEFAULT),
            reason=_safe_text(value["reason"], "reason"),
            created_at=_safe_text(value["created_at"], "created_at"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("V3 recovery state record is invalid") from exc


def _require_fields(value: Mapping[str, Any], fields: set[str]) -> None:
    if set(value) != fields:
        raise ValueError("V3 state record fields are invalid")


def _ensure_new_id(collection: Mapping[str, Any], key: str, label: str) -> None:
    if key in collection:
        raise ValueError(f"V3 state contains duplicate {label} ids")


def _expected_state(value: object, expected: V3State) -> V3State:
    if value != expected.value:
        raise ValueError("V3 state value is invalid")
    return expected


def _text_tuple(value: object, label: str, maximum: int) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{label} are invalid")
    return tuple(_safe_text(item, label) for item in value)


def _bounded_int(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} is invalid")
    return value


def _bounded_float(value: object, label: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise ValueError(f"{label} is invalid")
    result = float(value)
    if not minimum <= result <= maximum:
        raise ValueError(f"{label} is invalid")
    return result


def _valid_snapshot(value: object) -> bool:
    if (
        not isinstance(value, MetricSnapshot)
        or not isinstance(value.timestamp, str)
        or not value.timestamp.strip()
        or len(value.timestamp) > 128
        or contains_secret(value.timestamp)
        or RAW_STREAM_PATTERN.search(value.timestamp)
        or any(ord(char) < 32 for char in value.timestamp)
    ):
        return False
    numeric = (value.cpu_percent, value.memory_percent, value.disk_percent, value.load_1m, value.http_error_rate)
    if any(isinstance(item, bool) or not isinstance(item, (int, float)) or not math.isfinite(float(item)) for item in numeric):
        return False
    if any(float(item) < 0 for item in numeric):
        return False
    return (
        0 <= value.cpu_percent <= 100
        and 0 <= value.memory_percent <= 100
        and 0 <= value.disk_percent <= 100
        and 0 <= value.http_error_rate <= 1
        and isinstance(value.service_restarts, int)
        and not isinstance(value.service_restarts, bool)
        and 0 <= value.service_restarts <= 1_000_000
    )
