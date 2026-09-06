"""Safe project knowledge, impact, drift and change contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4

from core_operator.audit import RAW_STREAM_PATTERN
from core_operator.safe_logging import SECRET_PATTERNS

from .audit import MetadataAuditLog
from .auth import AuthService, Permission


class ContractState(str, Enum):
    RECORDED = "recorded"
    BLOCKED_BY_DEFAULT = "blocked_by_default"


@dataclass(frozen=True)
class KnowledgeRecord:
    knowledge_id: str
    project: str
    repository_label: str
    branch_label: str
    deployment_label: str
    services: tuple[str, ...]
    state: ContractState
    created_at: str
    server: str = "local-lab"
    environment: str = "laboratory"
    domains: tuple[str, ...] = ()
    databases: tuple[str, ...] = ()
    containers: tuple[str, ...] = ()
    ports: tuple[str, ...] = ()
    certificates: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    endpoints: tuple[str, ...] = ()
    health_checks: tuple[str, ...] = ()
    processes: tuple[str, ...] = ()
    related_backups: tuple[str, ...] = ()
    related_deployments: tuple[str, ...] = ()
    related_incidents: tuple[str, ...] = ()
    source: str = "caller_metadata"
    confidence: float = 0.5
    last_verified: str | None = None


@dataclass(frozen=True)
class ImpactReport:
    impact_id: str
    project: str
    action: str
    risk: str
    affected_components: tuple[str, ...]
    requires_backup: bool
    requires_approval: bool
    execution: ContractState
    created_at: str


@dataclass(frozen=True)
class DriftReport:
    drift_id: str
    project: str
    changed_keys: tuple[str, ...]
    desired: Mapping[str, Any]
    observed: Mapping[str, Any]
    state: ContractState
    created_at: str


@dataclass(frozen=True)
class ChangeRecord:
    change_id: str
    project: str
    action: str
    requested_by: str
    risk: str
    approval_required: bool
    backup_required: bool
    execution: ContractState
    created_at: str


class KnowledgeService:
    def __init__(self, *, auth: AuthService, audit: MetadataAuditLog) -> None:
        self.auth = auth
        self.audit = audit
        self._records: dict[str, KnowledgeRecord] = {}

    @property
    def records(self) -> tuple[KnowledgeRecord, ...]:
        return tuple(self._records.values())

    def register(
        self,
        *,
        session_id: str,
        project: str,
        repository_label: str,
        branch_label: str,
        deployment_label: str,
        services: tuple[str, ...],
        server: str = "local-lab",
        environment: str = "laboratory",
        domains: tuple[str, ...] = (),
        databases: tuple[str, ...] = (),
        containers: tuple[str, ...] = (),
        ports: tuple[str, ...] = (),
        certificates: tuple[str, ...] = (),
        dependencies: tuple[str, ...] = (),
        endpoints: tuple[str, ...] = (),
        health_checks: tuple[str, ...] = (),
        processes: tuple[str, ...] = (),
        related_backups: tuple[str, ...] = (),
        related_deployments: tuple[str, ...] = (),
        related_incidents: tuple[str, ...] = (),
        source: str = "caller_metadata",
        confidence: float = 0.5,
        last_verified: str | None = None,
    ) -> KnowledgeRecord:
        user = self.auth.require(session_id, Permission.VIEW_PROJECTS)
        _assert_safe_values((project, repository_label, branch_label, deployment_label, server, environment, source, *services))
        for values in (
            domains, databases, containers, ports, certificates, dependencies, endpoints,
            health_checks, processes, related_backups, related_deployments, related_incidents,
        ):
            _assert_safe_values(tuple(values))
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= float(confidence) <= 1:
            raise ValueError("knowledge confidence is invalid")
        if last_verified is not None:
            _assert_safe_values((last_verified,))
        record = KnowledgeRecord(
            knowledge_id=f"knowledge-{uuid4()}",
            project=project,
            repository_label=repository_label,
            branch_label=branch_label,
            deployment_label=deployment_label,
            services=services,
            state=ContractState.RECORDED,
            created_at=_now(),
            server=server,
            environment=environment,
            domains=tuple(domains),
            databases=tuple(databases),
            containers=tuple(containers),
            ports=tuple(ports),
            certificates=tuple(certificates),
            dependencies=tuple(dependencies),
            endpoints=tuple(endpoints),
            health_checks=tuple(health_checks),
            processes=tuple(processes),
            related_backups=tuple(related_backups),
            related_deployments=tuple(related_deployments),
            related_incidents=tuple(related_incidents),
            source=source,
            confidence=float(confidence),
            last_verified=last_verified or _now(),
        )
        self._records[record.knowledge_id] = record
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=project,
            action="knowledge_recorded",
            risk="LOW",
            authorization="permission:VIEW_PROJECTS",
            result=record.state.value,
            metadata={"knowledge_id": record.knowledge_id, "source": "caller_metadata"},
        )
        return record


class ImpactAnalysisService:
    def __init__(self, *, auth: AuthService, audit: MetadataAuditLog) -> None:
        self.auth = auth
        self.audit = audit
        self._reports: dict[str, ImpactReport] = {}

    @property
    def reports(self) -> tuple[ImpactReport, ...]:
        return tuple(self._reports.values())

    def analyze(
        self,
        *,
        session_id: str,
        project: str,
        action: str,
        risk: str,
        affected_components: tuple[str, ...],
    ) -> ImpactReport:
        user = self.auth.require(session_id, Permission.VIEW_PROJECTS)
        _assert_safe_values((project, action, risk, *affected_components))
        requires_backup = risk.upper() in {"HIGH", "CRITICAL"} or action in {"deploy", "rollback", "modify"}
        report = ImpactReport(
            impact_id=f"impact-{uuid4()}",
            project=project,
            action=action,
            risk=risk.upper(),
            affected_components=affected_components,
            requires_backup=requires_backup,
            requires_approval=requires_backup,
            execution=ContractState.BLOCKED_BY_DEFAULT,
            created_at=_now(),
        )
        self._reports[report.impact_id] = report
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=project,
            action="impact_analyzed",
            risk=report.risk,
            authorization="permission:VIEW_PROJECTS",
            result=report.execution.value,
            metadata={"impact_id": report.impact_id, "requires_backup": requires_backup},
        )
        return report


class ConfigurationDriftService:
    def __init__(self, *, auth: AuthService, audit: MetadataAuditLog) -> None:
        self.auth = auth
        self.audit = audit
        self._reports: dict[str, DriftReport] = {}

    @property
    def reports(self) -> tuple[DriftReport, ...]:
        return tuple(self._reports.values())

    def compare(
        self,
        *,
        session_id: str,
        project: str,
        desired: Mapping[str, Any],
        observed: Mapping[str, Any],
    ) -> DriftReport:
        user = self.auth.require(session_id, Permission.VIEW_PROJECTS)
        _assert_safe_values(tuple(desired.values()) + tuple(observed.values()))
        changed = tuple(sorted(set(desired) | set(observed)))
        changed = tuple(key for key in changed if desired.get(key) != observed.get(key))
        report = DriftReport(
            drift_id=f"drift-{uuid4()}",
            project=project,
            changed_keys=changed,
            desired=dict(desired),
            observed=dict(observed),
            state=ContractState.RECORDED,
            created_at=_now(),
        )
        self._reports[report.drift_id] = report
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=project,
            action="configuration_drift_compared",
            risk="MEDIUM",
            authorization="permission:VIEW_PROJECTS",
            result=report.state.value,
            metadata={"drift_id": report.drift_id, "changed_count": len(changed), "source": "caller_metadata"},
        )
        return report


class ChangeManager:
    def __init__(self, *, auth: AuthService, audit: MetadataAuditLog) -> None:
        self.auth = auth
        self.audit = audit
        self._changes: dict[str, ChangeRecord] = {}

    @property
    def changes(self) -> tuple[ChangeRecord, ...]:
        return tuple(self._changes.values())

    def propose(self, *, session_id: str, project: str, action: str, risk: str) -> ChangeRecord:
        user = self.auth.require(session_id, Permission.REQUEST_APPROVAL)
        _assert_safe_values((project, action, risk))
        normalized_risk = risk.upper()
        change = ChangeRecord(
            change_id=f"change-{uuid4()}",
            project=project,
            action=action,
            requested_by=user.username,
            risk=normalized_risk,
            approval_required=normalized_risk in {"MEDIUM", "HIGH", "CRITICAL"},
            backup_required=normalized_risk in {"HIGH", "CRITICAL"},
            execution=ContractState.BLOCKED_BY_DEFAULT,
            created_at=_now(),
        )
        self._changes[change.change_id] = change
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            project=project,
            action="change_proposed",
            risk=normalized_risk,
            authorization="permission:REQUEST_APPROVAL",
            result=change.execution.value,
            metadata={"change_id": change.change_id, "approval_required": change.approval_required},
        )
        return change


def _assert_safe_values(values: tuple[Any, ...]) -> None:
    for value in values:
        serialized = str(value)
        if any(pattern.search(serialized) for pattern in SECRET_PATTERNS) or RAW_STREAM_PATTERN.search(serialized):
            raise ValueError("metadata contains secret-like content")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
