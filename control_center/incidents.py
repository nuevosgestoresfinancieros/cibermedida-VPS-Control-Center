"""Incident lifecycle and metadata-only root-cause notes."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret

from .audit import MetadataAuditLog
from .auth import AuthService, Permission
from .state import JsonMetadataStore


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    ROOT_CAUSE_FOUND = "ROOT_CAUSE_FOUND"
    FIX_PREPARED = "FIX_PREPARED"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    RECOVERING = "RECOVERING"
    IDENTIFIED = "IDENTIFIED"
    MITIGATING = "MITIGATING"
    MONITORING = "MONITORING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class Incident:
    incident_id: str
    project: str
    service: str
    severity: IncidentSeverity
    symptom: str
    detected_by: str
    status: IncidentStatus
    suspected_cause: str | None
    diagnostic_steps: tuple[str, ...]
    actions: tuple[str, ...]
    resolution: str | None
    rollback: str | None
    created_at: str
    closed_at: str | None = None
    started_at: str | None = None
    related_logs: tuple[str, ...] = ()
    related_metrics: tuple[str, ...] = ()
    related_deployments: tuple[str, ...] = ()
    related_changes: tuple[str, ...] = ()
    related_backups: tuple[str, ...] = ()
    related_conversations: tuple[str, ...] = ()
    related_operations: tuple[str, ...] = ()


class IncidentManager:
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
        self._incidents: dict[str, Incident] = {}
        if self.state_store is not None:
            for raw_incident in self.state_store.load():
                incident = _decode_incident(raw_incident)
                if incident.incident_id in self._incidents:
                    raise ValueError("incident state contains duplicate ids")
                self._incidents[incident.incident_id] = incident

    @property
    def incidents(self) -> tuple[Incident, ...]:
        return tuple(self._incidents.values())

    def create(
        self,
        *,
        session_id: str,
        project: str,
        service: str,
        severity: IncidentSeverity,
        symptom: str,
        detected_by: str = "operator",
        related_logs: tuple[str, ...] = (),
        related_metrics: tuple[str, ...] = (),
        related_deployments: tuple[str, ...] = (),
        related_changes: tuple[str, ...] = (),
        related_backups: tuple[str, ...] = (),
        related_conversations: tuple[str, ...] = (),
        related_operations: tuple[str, ...] = (),
    ) -> Incident:
        user = self.auth.require(session_id, Permission.RUN_DIAGNOSTICS)
        for value in (project, service, symptom, detected_by):
            _assert_safe_note(value)
        for values in (
            related_logs, related_metrics, related_deployments, related_changes,
            related_backups, related_conversations, related_operations,
        ):
            for value in values:
                _assert_safe_note(value)
        incident = Incident(
            incident_id=f"incident-{uuid4()}",
            project=project,
            service=service,
            severity=severity,
            symptom=symptom,
            detected_by=detected_by,
            status=IncidentStatus.OPEN,
            suspected_cause=None,
            diagnostic_steps=("observe", "collect authorized metadata", "correlate", "validate hypothesis"),
            actions=(),
            resolution=None,
            rollback=None,
            created_at=_now(),
            started_at=_now(),
            related_logs=tuple(related_logs),
            related_metrics=tuple(related_metrics),
            related_deployments=tuple(related_deployments),
            related_changes=tuple(related_changes),
            related_backups=tuple(related_backups),
            related_conversations=tuple(related_conversations),
            related_operations=tuple(related_operations),
        )
        updated_incidents = dict(self._incidents)
        updated_incidents[incident.incident_id] = incident
        self._persist(updated_incidents)
        self._incidents = updated_incidents
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=project,
            action="incident_created",
            risk=severity.value,
            authorization="permission:RUN_DIAGNOSTICS",
            result=incident.status.value,
            metadata={"service": service, "detected_by": detected_by},
        )
        return incident

    def transition(
        self,
        *,
        session_id: str,
        incident_id: str,
        status: IncidentStatus,
        note: str | None = None,
        resolution: str | None = None,
        rollback: str | None = None,
    ) -> Incident:
        user = self.auth.require(session_id, Permission.RUN_DIAGNOSTICS)
        incident = self._get(incident_id)
        for value in (note, resolution, rollback):
            if value is not None:
                _assert_safe_note(value)
        updated = replace(
            incident,
            status=status,
            actions=incident.actions + ((note,) if note else ()),
            resolution=resolution.strip() if resolution is not None else incident.resolution,
            rollback=rollback.strip() if rollback is not None else incident.rollback,
            closed_at=_now() if status in {IncidentStatus.RESOLVED, IncidentStatus.CLOSED} else incident.closed_at,
        )
        updated_incidents = dict(self._incidents)
        updated_incidents[incident_id] = updated
        self._persist(updated_incidents)
        self._incidents = updated_incidents
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=incident.project,
            action="incident_transitioned",
            risk=incident.severity.value,
            authorization="permission:RUN_DIAGNOSTICS",
            result=status.value,
            metadata={"incident_id": incident_id},
        )
        return updated

    def analyze(
        self,
        *,
        session_id: str,
        incident_id: str,
        hypothesis: str,
        evidence_labels: tuple[str, ...] = (),
    ) -> Incident:
        """Record a caller-supplied hypothesis without reading operational data."""

        user = self.auth.require(session_id, Permission.RUN_DIAGNOSTICS)
        incident = self._get(incident_id)
        _assert_safe_note(hypothesis)
        for label in evidence_labels:
            _assert_safe_note(label)
        updated = replace(
            incident,
            status=IncidentStatus.IDENTIFIED,
            suspected_cause=hypothesis.strip(),
            diagnostic_steps=incident.diagnostic_steps + ("validate caller-provided hypothesis",),
        )
        updated_incidents = dict(self._incidents)
        updated_incidents[incident_id] = updated
        self._persist(updated_incidents)
        self._incidents = updated_incidents
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=incident.project,
            action="incident_analyzed",
            risk=incident.severity.value,
            authorization="permission:RUN_DIAGNOSTICS",
            result=updated.status.value,
            metadata={"incident_id": incident_id, "evidence_count": len(evidence_labels)},
        )
        return updated

    def _get(self, incident_id: str) -> Incident:
        try:
            return self._incidents[incident_id]
        except KeyError as exc:
            raise ValueError("incident does not exist") from exc

    def _persist(self, incidents: dict[str, Incident]) -> None:
        if self.state_store is not None:
            self.state_store.save(_encode_incident(incident) for incident in incidents.values())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _assert_safe_note(value: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise ValueError("incident metadata is invalid")
    if contains_secret(value) or RAW_STREAM_PATTERN.search(value):
        raise ValueError("incident metadata contains unsafe content")


def _encode_incident(incident: Incident) -> dict[str, object]:
    return {
        "incident_id": incident.incident_id,
        "project": incident.project,
        "service": incident.service,
        "severity": incident.severity.value,
        "symptom": incident.symptom,
        "detected_by": incident.detected_by,
        "status": incident.status.value,
        "suspected_cause": incident.suspected_cause,
        "diagnostic_steps": list(incident.diagnostic_steps),
        "actions": list(incident.actions),
        "resolution": incident.resolution,
        "rollback": incident.rollback,
        "created_at": incident.created_at,
        "closed_at": incident.closed_at,
        "started_at": incident.started_at,
        "related_logs": list(incident.related_logs),
        "related_metrics": list(incident.related_metrics),
        "related_deployments": list(incident.related_deployments),
        "related_changes": list(incident.related_changes),
        "related_backups": list(incident.related_backups),
        "related_conversations": list(incident.related_conversations),
        "related_operations": list(incident.related_operations),
    }


def _decode_incident(value: dict[str, object]) -> Incident:
    diagnostic_steps = value.get("diagnostic_steps")
    actions = value.get("actions")
    relation_lists = {
        key: value.get(key, [])
        for key in (
            "related_logs", "related_metrics", "related_deployments", "related_changes",
            "related_backups", "related_conversations", "related_operations",
        )
    }
    if (
        not isinstance(diagnostic_steps, list)
        or not isinstance(actions, list)
        or any(not isinstance(item, str) for item in (*diagnostic_steps, *actions))
        or any(not isinstance(items, list) or any(not isinstance(item, str) for item in items) for items in relation_lists.values())
    ):
        raise ValueError("incident state lists are invalid")
    try:
        incident = Incident(
            incident_id=_required_text(value, "incident_id"),
            project=_required_text(value, "project"),
            service=_required_text(value, "service"),
            severity=IncidentSeverity(value["severity"]),
            symptom=_required_text(value, "symptom"),
            detected_by=_required_text(value, "detected_by"),
            status=IncidentStatus(value["status"]),
            suspected_cause=_optional_text(value, "suspected_cause"),
            diagnostic_steps=tuple(diagnostic_steps),
            actions=tuple(actions),
            resolution=_optional_text(value, "resolution"),
            rollback=_optional_text(value, "rollback"),
            created_at=_required_text(value, "created_at"),
            closed_at=_optional_text(value, "closed_at"),
            started_at=_optional_text(value, "started_at"),
            **{key: tuple(items) for key, items in relation_lists.items()},
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("incident state record is invalid") from exc
    return incident


def _required_text(value: dict[str, object], key: str) -> str:
    item = value[key]
    _assert_safe_note(item)
    return item.strip()


def _optional_text(value: dict[str, object], key: str) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    return _required_text(value, key)
