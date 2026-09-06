"""Shared, metadata-only operation contract and integrity helpers.

Every workflow that can affect a project or server should be representable by
one manifest.  The manifest is deliberately data-only: it never constructs a
shell command and never performs an operation.  Its hashes make it possible
to compare the approved snapshot with later execution evidence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Mapping

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret


class OperationStatus(str, Enum):
    PLANNED = "planned"
    DRY_RUN = "dry_run"
    WAITING_APPROVAL = "waiting_approval"
    APPROVED = "approved"
    READY = "ready"
    EXECUTING = "executing"
    VALIDATING = "validating"
    MONITORING = "monitoring"
    COMPLETED = "completed"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"
    REJECTED = "rejected"
    BLOCKED = "blocked"
    FAILED = "failed"


@dataclass(frozen=True)
class OperationManifest:
    """Canonical operation snapshot shared across application workflows."""

    operation_id: str
    project: str
    server: str
    environment: str
    resource: str
    requested_by: str
    requested_action: str
    agent: str
    risk_level: str
    status: OperationStatus
    commands: tuple[str, ...] = ()
    files: tuple[str, ...] = ()
    services_affected: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    tests_required: tuple[str, ...] = ()
    backup_required: bool = False
    approval_required: bool = False
    backup_id: str | None = None
    branch: str | None = None
    commit: str | None = None
    rollback_plan: str = ""
    expected_result: str = ""
    validation_steps: tuple[str, ...] = ()
    downtime_possible: bool = False
    data_risk: str = "none"
    created_at: str = ""
    approved_at: str | None = None
    executed_at: str | None = None
    completed_at: str | None = None
    operation_hash: str = ""
    plan_hash: str = ""
    approval_hash: str = ""
    execution_hash: str = ""

    def __post_init__(self) -> None:
        required = (
            self.operation_id,
            self.project,
            self.server,
            self.environment,
            self.resource,
            self.requested_by,
            self.requested_action,
            self.agent,
            self.risk_level,
            self.created_at,
        )
        for value in required:
            _assert_safe_text(value)
        if not isinstance(self.status, OperationStatus):
            raise ValueError("operation status is invalid")
        for values in (
            self.commands,
            self.files,
            self.services_affected,
            self.dependencies,
            self.tests_required,
            self.validation_steps,
        ):
            if len(values) > 128:
                raise ValueError("operation manifest list is too large")
            for value in values:
                _assert_safe_text(value)
        for value in (
            self.backup_id,
            self.branch,
            self.commit,
            self.rollback_plan,
            self.expected_result,
            self.approved_at,
            self.executed_at,
            self.completed_at,
            self.operation_hash,
            self.plan_hash,
            self.approval_hash,
            self.execution_hash,
        ):
            if value is not None and value != "":
                _assert_safe_text(value)
        if not isinstance(self.backup_required, bool) or not isinstance(self.approval_required, bool):
            raise ValueError("operation flags are invalid")
        if not isinstance(self.downtime_possible, bool):
            raise ValueError("downtime flag is invalid")
        _assert_safe_text(self.data_risk)

    @property
    def scope(self) -> Mapping[str, str]:
        return {
            "server": self.server,
            "project": self.project,
            "environment": self.environment,
            "resource": self.resource,
            "action": self.requested_action,
        }

    @classmethod
    def create(
        cls,
        *,
        operation_id: str,
        project: str,
        server: str,
        environment: str,
        resource: str,
        requested_by: str,
        requested_action: str,
        agent: str = "control_center",
        risk_level: str = "L1",
        status: OperationStatus = OperationStatus.PLANNED,
        commands: tuple[str, ...] = (),
        files: tuple[str, ...] = (),
        services_affected: tuple[str, ...] = (),
        dependencies: tuple[str, ...] = (),
        tests_required: tuple[str, ...] = (),
        backup_required: bool = False,
        approval_required: bool = False,
        backup_id: str | None = None,
        branch: str | None = None,
        commit: str | None = None,
        rollback_plan: str = "",
        expected_result: str = "",
        validation_steps: tuple[str, ...] = (),
        downtime_possible: bool = False,
        data_risk: str = "none",
        created_at: str,
    ) -> "OperationManifest":
        manifest = cls(
            operation_id=operation_id,
            project=project,
            server=server,
            environment=environment,
            resource=resource,
            requested_by=requested_by,
            requested_action=requested_action,
            agent=agent,
            risk_level=risk_level,
            status=status,
            commands=tuple(commands),
            files=tuple(files),
            services_affected=tuple(services_affected),
            dependencies=tuple(dependencies),
            tests_required=tuple(tests_required),
            backup_required=backup_required,
            approval_required=approval_required,
            backup_id=backup_id,
            branch=branch,
            commit=commit,
            rollback_plan=rollback_plan,
            expected_result=expected_result,
            validation_steps=tuple(validation_steps),
            downtime_possible=downtime_possible,
            data_risk=data_risk,
            created_at=created_at,
        )
        return manifest.refresh_integrity()

    def with_status(self, status: OperationStatus, **changes: Any) -> "OperationManifest":
        """Return a new snapshot and recompute all applicable hashes."""

        return replace(self, status=status, **changes).refresh_integrity()

    def refresh_integrity(self) -> "OperationManifest":
        """Recalculate the operation and current-stage hashes."""

        operation_hash = _digest(self._payload(include_hashes=False))
        plan_hash = _digest({"stage": "plan", "operation": operation_hash, "payload": self._payload(include_hashes=False)})
        approval_hash = (
            _digest({"stage": "approval", "operation": operation_hash, "plan": plan_hash})
            if self.status
            in {
                OperationStatus.APPROVED,
                OperationStatus.READY,
                OperationStatus.EXECUTING,
                OperationStatus.VALIDATING,
                OperationStatus.MONITORING,
                OperationStatus.COMPLETED,
            }
            else ""
        )
        execution_hash = (
            _digest({"stage": "execution", "operation": operation_hash, "plan": plan_hash, "approval": approval_hash})
            if self.status
            in {
                OperationStatus.EXECUTING,
                OperationStatus.VALIDATING,
                OperationStatus.MONITORING,
                OperationStatus.COMPLETED,
            }
            else ""
        )
        return replace(
            self,
            operation_hash=operation_hash,
            plan_hash=plan_hash,
            approval_hash=approval_hash,
            execution_hash=execution_hash,
        )

    def as_dict(self) -> dict[str, Any]:
        payload = dict(self._payload(include_hashes=True))
        payload["scope"] = dict(self.scope)
        payload["status"] = self.status.value
        return payload

    def _payload(self, *, include_hashes: bool) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "operation_id": self.operation_id,
            "project": self.project,
            "server": self.server,
            "environment": self.environment,
            "resource": self.resource,
            "requested_by": self.requested_by,
            "requested_action": self.requested_action,
            "agent": self.agent,
            "risk_level": self.risk_level,
            "status": self.status.value,
            "commands": list(self.commands),
            "files": list(self.files),
            "services_affected": list(self.services_affected),
            "dependencies": list(self.dependencies),
            "tests_required": list(self.tests_required),
            "backup_required": self.backup_required,
            "approval_required": self.approval_required,
            "backup_id": self.backup_id,
            "branch": self.branch,
            "commit": self.commit,
            "rollback_plan": self.rollback_plan,
            "expected_result": self.expected_result,
            "validation_steps": list(self.validation_steps),
            "downtime_possible": self.downtime_possible,
            "data_risk": self.data_risk,
            "created_at": self.created_at,
            "approved_at": self.approved_at,
            "executed_at": self.executed_at,
            "completed_at": self.completed_at,
        }
        if include_hashes:
            payload.update(
                {
                    "operation_hash": self.operation_hash,
                    "plan_hash": self.plan_hash,
                    "approval_hash": self.approval_hash,
                    "execution_hash": self.execution_hash,
                }
            )
        return payload


def _assert_safe_text(value: object) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 512
        or any(ord(character) < 32 for character in value)
        or contains_secret(value)
        or RAW_STREAM_PATTERN.search(value) is not None
    ):
        raise ValueError("operation manifest contains unsafe metadata")


def _digest(value: object) -> str:
    serialized = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def risk_level_for(risk: str) -> str:
    """Normalize legacy risk labels to the document's L1-L4 scale."""

    normalized = str(risk).strip().upper()
    mapping = {
        "LOW": "L1",
        "MEDIUM": "L2",
        "HIGH": "L3",
        "CRITICAL": "L4",
    }
    if normalized in mapping:
        return mapping[normalized]
    if normalized in {"L1", "L2", "L3", "L4"}:
        return normalized
    raise ValueError("risk level must be LOW, MEDIUM, HIGH, CRITICAL or L1-L4")


def manifest_from_dict(value: Mapping[str, Any]) -> OperationManifest:
    """Decode a persisted/API manifest with strict bounded metadata."""

    lists = {}
    for key in ("commands", "files", "services_affected", "dependencies", "tests_required", "validation_steps"):
        raw = value.get(key, [])
        if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
            raise ValueError(f"operation manifest field {key} is invalid")
        lists[key] = tuple(raw)
    try:
        manifest = OperationManifest(
            operation_id=value["operation_id"],
            project=value["project"],
            server=value["server"],
            environment=value["environment"],
            resource=value["resource"],
            requested_by=value["requested_by"],
            requested_action=value["requested_action"],
            agent=value.get("agent", "control_center"),
            risk_level=risk_level_for(value["risk_level"]),
            status=OperationStatus(value["status"]),
            **lists,
            backup_required=value.get("backup_required", False),
            approval_required=value.get("approval_required", False),
            backup_id=value.get("backup_id"),
            branch=value.get("branch"),
            commit=value.get("commit"),
            rollback_plan=value.get("rollback_plan", ""),
            expected_result=value.get("expected_result", ""),
            downtime_possible=value.get("downtime_possible", False),
            data_risk=value.get("data_risk", "none"),
            created_at=value["created_at"],
            approved_at=value.get("approved_at"),
            executed_at=value.get("executed_at"),
            completed_at=value.get("completed_at"),
            operation_hash=value.get("operation_hash", ""),
            plan_hash=value.get("plan_hash", ""),
            approval_hash=value.get("approval_hash", ""),
            execution_hash=value.get("execution_hash", ""),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("operation manifest is invalid") from exc
    if not manifest.operation_hash:
        return manifest.refresh_integrity()
    if not hashes_match(manifest):
        raise ValueError("operation manifest integrity hash does not match")
    return manifest


def hashes_match(manifest: OperationManifest) -> bool:
    """Verify every applicable integrity hash against the immutable snapshot."""

    expected = manifest.refresh_integrity()
    return (
        manifest.operation_hash == expected.operation_hash
        and manifest.plan_hash == expected.plan_hash
        and manifest.approval_hash == expected.approval_hash
        and manifest.execution_hash == expected.execution_hash
    )
