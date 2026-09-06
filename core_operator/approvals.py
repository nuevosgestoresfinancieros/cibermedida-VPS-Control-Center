"""Approval workflows with an in-memory default and opt-in JSON persistence."""

from __future__ import annotations

import json
import fcntl
import hashlib
import os
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Iterator, Protocol
from uuid import uuid4

from .audit import RAW_STREAM_PATTERN, contains_secret
from .audit import AuditStore
from .policy import Decision, PolicyDecision, RiskLevel
from .safe_logging import redact_text


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass(frozen=True)
class ApprovalRequest:
    id: str
    timestamp: str
    actor: str
    action: str
    risk_level: RiskLevel
    command_id: str | None
    reason: str
    status: ApprovalStatus
    decided_by: str | None
    decided_at: str | None
    decided_by_role: str | None = None
    actor_role: str = "UNKNOWN"
    policy_version: str = "legacy"
    effective_permissions: tuple[str, ...] = ()
    resource: str = "unknown"
    plan_id: str | None = None
    expires_at: str | None = None
    operation_id: str | None = None
    branch: str | None = None
    commit: str | None = None
    backup_id: str | None = None
    commands: tuple[str, ...] = ()
    files: tuple[str, ...] = ()
    services_affected: tuple[str, ...] = ()
    impact: tuple[str, ...] = ()
    operation_hash: str | None = None
    plan_hash: str | None = None
    approval_hash: str | None = None
    execution_hash: str | None = None


@dataclass(frozen=True)
class ApprovalDecision:
    id: str
    timestamp: str
    actor: str
    action: str
    risk_level: RiskLevel
    command_id: str | None
    reason: str
    status: ApprovalStatus
    decided_by: str
    decided_at: str
    actor_role: str = "UNKNOWN"
    decided_by_role: str = "UNKNOWN"
    policy_version: str = "legacy"
    effective_permissions: tuple[str, ...] = ()
    resource: str = "unknown"
    plan_id: str | None = None
    expires_at: str | None = None
    operation_id: str | None = None
    branch: str | None = None
    commit: str | None = None
    backup_id: str | None = None
    commands: tuple[str, ...] = ()
    files: tuple[str, ...] = ()
    services_affected: tuple[str, ...] = ()
    impact: tuple[str, ...] = ()
    operation_hash: str | None = None
    plan_hash: str | None = None
    approval_hash: str | None = None
    execution_hash: str | None = None


class ApprovalStore(Protocol):
    @property
    def requests(self) -> tuple[ApprovalRequest, ...]:
        ...

    @property
    def pending_requests(self) -> tuple[ApprovalRequest, ...]:
        ...

    def get(self, request_id: str) -> ApprovalRequest:
        ...

    def create_pending(
        self,
        *,
        actor: str,
        action: str,
        risk_level: RiskLevel,
        reason: str,
        command_id: str | None = None,
        actor_role: str = "UNKNOWN",
        policy_version: str = "legacy",
        effective_permissions: tuple[str, ...] = (),
        resource: str = "unknown",
        plan_id: str | None = None,
        expires_at: str | None = None,
        operation_id: str | None = None,
        branch: str | None = None,
        commit: str | None = None,
        backup_id: str | None = None,
        commands: tuple[str, ...] = (),
        files: tuple[str, ...] = (),
        services_affected: tuple[str, ...] = (),
        impact: tuple[str, ...] = (),
        operation_hash: str | None = None,
        plan_hash: str | None = None,
        approval_hash: str | None = None,
        execution_hash: str | None = None,
    ) -> ApprovalRequest:
        ...

    def create_denied(
        self,
        *,
        actor: str,
        action: str,
        risk_level: RiskLevel,
        reason: str,
        command_id: str | None = None,
        actor_role: str = "UNKNOWN",
        policy_version: str = "legacy",
        effective_permissions: tuple[str, ...] = (),
        resource: str = "unknown",
        plan_id: str | None = None,
        expires_at: str | None = None,
        operation_id: str | None = None,
        branch: str | None = None,
        commit: str | None = None,
        backup_id: str | None = None,
        commands: tuple[str, ...] = (),
        files: tuple[str, ...] = (),
        services_affected: tuple[str, ...] = (),
        impact: tuple[str, ...] = (),
        operation_hash: str | None = None,
        plan_hash: str | None = None,
        approval_hash: str | None = None,
        execution_hash: str | None = None,
    ) -> ApprovalRequest:
        ...

    def approve(
        self,
        request_id: str,
        *,
        decided_by: str,
        decided_by_role: str = "UNKNOWN",
        reason: str = "approved",
    ) -> ApprovalDecision:
        ...

    def deny(
        self,
        request_id: str,
        *,
        decided_by: str,
        decided_by_role: str = "UNKNOWN",
        reason: str = "denied",
    ) -> ApprovalDecision:
        ...

    def apply_policy_decision(
        self,
        *,
        actor: str,
        action: str,
        policy_decision: PolicyDecision,
        command_id: str | None = None,
        actor_role: str = "UNKNOWN",
        policy_version: str = "legacy",
        effective_permissions: tuple[str, ...] = (),
        resource: str = "unknown",
        plan_id: str | None = None,
        expires_at: str | None = None,
        operation_id: str | None = None,
        branch: str | None = None,
        commit: str | None = None,
        backup_id: str | None = None,
        commands: tuple[str, ...] = (),
        files: tuple[str, ...] = (),
        services_affected: tuple[str, ...] = (),
        impact: tuple[str, ...] = (),
        operation_hash: str | None = None,
        plan_hash: str | None = None,
        approval_hash: str | None = None,
        execution_hash: str | None = None,
    ) -> ApprovalRequest | None:
        ...


class ApprovalStateError(ValueError):
    pass


class InMemoryApprovalStore:
    def __init__(self, *, audit: AuditStore | None = None) -> None:
        self.audit = audit
        self._requests: dict[str, ApprovalRequest] = {}

    @property
    def requests(self) -> tuple[ApprovalRequest, ...]:
        self._refresh_expired()
        return tuple(self._requests.values())

    @property
    def pending_requests(self) -> tuple[ApprovalRequest, ...]:
        self._refresh_expired()
        return tuple(request for request in self._requests.values() if request.status is ApprovalStatus.PENDING)

    def get(self, request_id: str) -> ApprovalRequest:
        return self._get_request(request_id)

    def create_pending(
        self,
        *,
        actor: str,
        action: str,
        risk_level: RiskLevel,
        reason: str,
        command_id: str | None = None,
        actor_role: str = "UNKNOWN",
        policy_version: str = "legacy",
        effective_permissions: tuple[str, ...] = (),
        resource: str = "unknown",
        plan_id: str | None = None,
        expires_at: str | None = None,
        operation_id: str | None = None,
        branch: str | None = None,
        commit: str | None = None,
        backup_id: str | None = None,
        commands: tuple[str, ...] = (),
        files: tuple[str, ...] = (),
        services_affected: tuple[str, ...] = (),
        impact: tuple[str, ...] = (),
        operation_hash: str | None = None,
        plan_hash: str | None = None,
        approval_hash: str | None = None,
        execution_hash: str | None = None,
    ) -> ApprovalRequest:
        request = self._build_request(
            actor=actor,
            action=action,
            risk_level=risk_level,
            command_id=command_id,
            reason=reason,
            status=ApprovalStatus.PENDING,
            decided_by=None,
            decided_at=None,
            actor_role=actor_role,
            policy_version=policy_version,
            effective_permissions=effective_permissions,
            resource=resource,
            plan_id=plan_id,
            expires_at=expires_at,
            operation_id=operation_id,
            branch=branch,
            commit=commit,
            backup_id=backup_id,
            commands=commands,
            files=files,
            services_affected=services_affected,
            impact=impact,
            operation_hash=operation_hash,
            plan_hash=plan_hash,
            approval_hash=approval_hash,
            execution_hash=execution_hash,
        )
        self._requests[request.id] = request
        try:
            self._persist()
        except Exception:
            self._requests.pop(request.id, None)
            raise
        self._audit(actor, "approval_requested", risk_level, command_id, request.status.value)
        return request

    def create_denied(
        self,
        *,
        actor: str,
        action: str,
        risk_level: RiskLevel,
        reason: str,
        command_id: str | None = None,
        actor_role: str = "UNKNOWN",
        policy_version: str = "legacy",
        effective_permissions: tuple[str, ...] = (),
        resource: str = "unknown",
        plan_id: str | None = None,
        expires_at: str | None = None,
        operation_id: str | None = None,
        branch: str | None = None,
        commit: str | None = None,
        backup_id: str | None = None,
        commands: tuple[str, ...] = (),
        files: tuple[str, ...] = (),
        services_affected: tuple[str, ...] = (),
        impact: tuple[str, ...] = (),
        operation_hash: str | None = None,
        plan_hash: str | None = None,
        approval_hash: str | None = None,
        execution_hash: str | None = None,
    ) -> ApprovalRequest:
        request = self._build_request(
            actor=actor,
            action=action,
            risk_level=risk_level,
            command_id=command_id,
            reason=reason,
            status=ApprovalStatus.DENIED,
            decided_by="policy",
            decided_at=_utc_now(),
            decided_by_role="POLICY",
            actor_role=actor_role,
            policy_version=policy_version,
            effective_permissions=effective_permissions,
            resource=resource,
            plan_id=plan_id,
            expires_at=expires_at,
            operation_id=operation_id,
            branch=branch,
            commit=commit,
            backup_id=backup_id,
            commands=commands,
            files=files,
            services_affected=services_affected,
            impact=impact,
            operation_hash=operation_hash,
            plan_hash=plan_hash,
            approval_hash=approval_hash,
            execution_hash=execution_hash,
        )
        self._requests[request.id] = request
        try:
            self._persist()
        except Exception:
            self._requests.pop(request.id, None)
            raise
        self._audit(actor, "approval_denied", risk_level, command_id, request.status.value)
        return request

    def approve(
        self,
        request_id: str,
        *,
        decided_by: str,
        decided_by_role: str = "UNKNOWN",
        reason: str = "approved",
    ) -> ApprovalDecision:
        return self._decide(
            request_id,
            status=ApprovalStatus.APPROVED,
            decided_by=decided_by,
            decided_by_role=decided_by_role,
            reason=reason,
        )

    def deny(
        self,
        request_id: str,
        *,
        decided_by: str,
        decided_by_role: str = "UNKNOWN",
        reason: str = "denied",
    ) -> ApprovalDecision:
        return self._decide(
            request_id,
            status=ApprovalStatus.DENIED,
            decided_by=decided_by,
            decided_by_role=decided_by_role,
            reason=reason,
        )

    def apply_policy_decision(
        self,
        *,
        actor: str,
        action: str,
        policy_decision: PolicyDecision,
        command_id: str | None = None,
        actor_role: str = "UNKNOWN",
        policy_version: str = "legacy",
        effective_permissions: tuple[str, ...] = (),
        resource: str = "unknown",
        plan_id: str | None = None,
        expires_at: str | None = None,
        operation_id: str | None = None,
        branch: str | None = None,
        commit: str | None = None,
        backup_id: str | None = None,
        commands: tuple[str, ...] = (),
        files: tuple[str, ...] = (),
        services_affected: tuple[str, ...] = (),
        impact: tuple[str, ...] = (),
        operation_hash: str | None = None,
        plan_hash: str | None = None,
        approval_hash: str | None = None,
        execution_hash: str | None = None,
    ) -> ApprovalRequest | None:
        if policy_decision.decision is Decision.APPROVAL_REQUIRED:
            return self.create_pending(
                actor=actor,
                action=action,
                risk_level=policy_decision.risk_level,
                reason=policy_decision.reason,
                command_id=command_id,
                actor_role=actor_role,
                policy_version=policy_version,
                effective_permissions=effective_permissions,
                resource=resource,
                plan_id=plan_id,
                expires_at=expires_at,
                operation_id=operation_id,
                branch=branch,
                commit=commit,
                backup_id=backup_id,
                commands=commands,
                files=files,
                services_affected=services_affected,
                impact=impact,
                operation_hash=operation_hash,
                plan_hash=plan_hash,
                approval_hash=approval_hash,
                execution_hash=execution_hash,
            )
        if policy_decision.decision is Decision.DENY:
            return self.create_denied(
                actor=actor,
                action=action,
                risk_level=policy_decision.risk_level,
                reason=policy_decision.reason,
                command_id=command_id,
                actor_role=actor_role,
                policy_version=policy_version,
                effective_permissions=effective_permissions,
                resource=resource,
                plan_id=plan_id,
                expires_at=expires_at,
                operation_id=operation_id,
                branch=branch,
                commit=commit,
                backup_id=backup_id,
                commands=commands,
                files=files,
                services_affected=services_affected,
                impact=impact,
                operation_hash=operation_hash,
                plan_hash=plan_hash,
                approval_hash=approval_hash,
                execution_hash=execution_hash,
            )
        return None

    def _decide(
        self,
        request_id: str,
        *,
        status: ApprovalStatus,
        decided_by: str,
        decided_by_role: str,
        reason: str,
    ) -> ApprovalDecision:
        request = self._get_request(request_id)
        if request.status is not ApprovalStatus.PENDING:
            raise ApprovalStateError("approval request is already decided")
        safe_decided_by = redact_text(decided_by)
        if request.actor == safe_decided_by:
            raise ApprovalStateError("requester and approver must be different users")
        _validate_snapshot_text(decided_by_role, field="decided_by_role")

        updated = replace(
            request,
            status=status,
            decided_by=safe_decided_by,
            decided_by_role=redact_text(decided_by_role),
            decided_at=_utc_now(),
            reason=redact_text(reason),
        )
        updated = replace(
            updated,
            approval_hash=(
                _approval_hash(updated)
                if status in {ApprovalStatus.APPROVED, ApprovalStatus.DENIED}
                else updated.approval_hash
            ),
        )
        self._requests[request_id] = updated
        try:
            self._persist()
        except Exception:
            self._requests[request_id] = request
            raise
        self._audit(updated.actor, f"approval_{status.value}", updated.risk_level, None, updated.status.value)
        return ApprovalDecision(
            id=updated.id,
            timestamp=updated.timestamp,
            actor=updated.actor,
            action=updated.action,
            risk_level=updated.risk_level,
            command_id=updated.command_id,
            reason=updated.reason,
            status=updated.status,
            decided_by=updated.decided_by or "",
            decided_at=updated.decided_at or "",
            actor_role=updated.actor_role,
            decided_by_role=updated.decided_by_role or "UNKNOWN",
            policy_version=updated.policy_version,
            effective_permissions=updated.effective_permissions,
            resource=updated.resource,
            plan_id=updated.plan_id,
            expires_at=updated.expires_at,
            operation_id=updated.operation_id,
            branch=updated.branch,
            commit=updated.commit,
            backup_id=updated.backup_id,
            commands=updated.commands,
            files=updated.files,
            services_affected=updated.services_affected,
            impact=updated.impact,
            operation_hash=updated.operation_hash,
            plan_hash=updated.plan_hash,
            approval_hash=updated.approval_hash,
            execution_hash=updated.execution_hash,
        )

    def _get_request(self, request_id: str) -> ApprovalRequest:
        self._refresh_expired()
        try:
            return self._requests[request_id]
        except KeyError as exc:
            raise ApprovalStateError("approval request does not exist") from exc

    def _refresh_expired(self) -> None:
        now = datetime.now(timezone.utc)
        updates: dict[str, ApprovalRequest] = {}
        for request_id, request in self._requests.items():
            if request.status not in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}:
                continue
            if not _is_expired(request.expires_at, now=now):
                continue
            updates[request_id] = replace(
                request,
                status=ApprovalStatus.EXPIRED,
                decided_by="system",
                decided_by_role="SYSTEM",
                decided_at=_utc_now(),
                reason="approval expired",
            )
        if not updates:
            return
        previous = {request_id: self._requests[request_id] for request_id in updates}
        self._requests.update(updates)
        try:
            self._persist()
        except Exception:
            self._requests.update(previous)
            raise
        for request in updates.values():
            self._audit(request.actor, "approval_expired", request.risk_level, request.command_id, request.status.value)

    def _build_request(
        self,
        *,
        actor: str,
        action: str,
        risk_level: RiskLevel,
        command_id: str | None,
        reason: str,
        status: ApprovalStatus,
        decided_by: str | None,
        decided_at: str | None,
        actor_role: str,
        policy_version: str,
        effective_permissions: tuple[str, ...],
        resource: str,
        plan_id: str | None,
        expires_at: str | None,
        decided_by_role: str | None = None,
        operation_id: str | None = None,
        branch: str | None = None,
        commit: str | None = None,
        backup_id: str | None = None,
        commands: tuple[str, ...] = (),
        files: tuple[str, ...] = (),
        services_affected: tuple[str, ...] = (),
        impact: tuple[str, ...] = (),
        operation_hash: str | None = None,
        plan_hash: str | None = None,
        approval_hash: str | None = None,
        execution_hash: str | None = None,
    ) -> ApprovalRequest:
        normalized_permissions = _normalize_permissions(effective_permissions)
        _validate_snapshot_text(actor_role, field="actor_role")
        _validate_snapshot_text(policy_version, field="policy_version")
        _validate_snapshot_text(resource, field="resource")
        if plan_id:
            _validate_snapshot_text(plan_id, field="plan_id")
        safe_plan_id = redact_text(plan_id) if plan_id else f"plan-{uuid4()}"
        _validate_snapshot_text(safe_plan_id, field="plan_id")
        safe_expires_at = expires_at or _future_expiry()
        _validate_expiry(safe_expires_at)
        if policy_version != "legacy" and not normalized_permissions:
            raise ApprovalStateError("effective permissions are required for versioned approvals")
        if decided_by_role is not None:
            _validate_snapshot_text(decided_by_role, field="decided_by_role")
        snapshot_values = (
            operation_id,
            branch,
            commit,
            backup_id,
            operation_hash,
            plan_hash,
            approval_hash,
            execution_hash,
        )
        for field, value in zip(
            ("operation_id", "branch", "commit", "backup_id", "operation_hash", "plan_hash", "approval_hash", "execution_hash"),
            snapshot_values,
        ):
            if value is not None:
                _validate_snapshot_text(value, field=field)
        for field, values in (
            ("commands", commands),
            ("files", files),
            ("services_affected", services_affected),
            ("impact", impact),
        ):
            if not isinstance(values, (tuple, list)) or len(values) > 128:
                raise ApprovalStateError(f"{field} is invalid")
            for value in values:
                _validate_snapshot_text(value, field=field)
        return ApprovalRequest(
            id=str(uuid4()),
            timestamp=_utc_now(),
            actor=redact_text(actor),
            action=redact_text(action),
            risk_level=risk_level,
            command_id=redact_text(command_id) if command_id else None,
            reason=redact_text(reason),
            status=status,
            decided_by=redact_text(decided_by) if decided_by else None,
            decided_at=decided_at,
            decided_by_role=redact_text(decided_by_role) if decided_by_role else None,
            actor_role=redact_text(actor_role),
            policy_version=redact_text(policy_version),
            effective_permissions=normalized_permissions,
            resource=redact_text(resource),
            plan_id=safe_plan_id,
            expires_at=safe_expires_at,
            operation_id=redact_text(operation_id) if operation_id else safe_plan_id,
            branch=redact_text(branch) if branch else None,
            commit=redact_text(commit) if commit else None,
            backup_id=redact_text(backup_id) if backup_id else None,
            commands=tuple(redact_text(value) for value in commands),
            files=tuple(redact_text(value) for value in files),
            services_affected=tuple(redact_text(value) for value in services_affected),
            impact=tuple(redact_text(value) for value in impact),
            operation_hash=redact_text(operation_hash) if operation_hash else None,
            plan_hash=redact_text(plan_hash) if plan_hash else None,
            approval_hash=redact_text(approval_hash) if approval_hash else None,
            execution_hash=redact_text(execution_hash) if execution_hash else None,
        )

    def _audit(
        self,
        actor: str,
        action: str,
        risk_level: RiskLevel,
        command_id: str | None,
        result: str,
    ) -> None:
        if self.audit is None:
            return
        self.audit.append(
            actor=actor,
            action=action,
            risk_level=risk_level,
            command_id=command_id,
            result=result,
            authorization_required=True,
        )

    def _persist(self) -> None:
        """Hook for durable stores; the default deliberately writes nothing."""

        return


class JsonApprovalStore(InMemoryApprovalStore):
    """Opt-in approval store with fail-closed, atomic JSON persistence.

    The file contains approval metadata only. It is not a database and does
    not persist command output, credentials, or raw operational records.
    """

    VERSION = 2
    MAX_BYTES = 4 * 1024 * 1024

    def __init__(self, path: str | Path, *, audit: AuditStore | None = None) -> None:
        self.path = _validate_approval_path(Path(path))
        self._file_lock = threading.Lock()
        super().__init__(audit=audit)
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        if self.path.stat().st_size > self.MAX_BYTES:
            raise ValueError("approval store is too large")
        try:
            with _approval_path_lock(self.path, exclusive=False):
                with self.path.open("r", encoding="utf-8") as handle:
                    payload = json.load(handle)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("approval store cannot be loaded") from exc
        if not isinstance(payload, dict) or payload.get("version") not in {1, self.VERSION}:
            raise ValueError("approval store format is invalid")
        entries = payload.get("requests")
        if not isinstance(entries, list):
            raise ValueError("approval store requests are invalid")
        loaded: dict[str, ApprovalRequest] = {}
        for entry in entries:
            request = _decode_request(entry)
            if request.id in loaded:
                raise ValueError("approval store contains duplicate request ids")
            loaded[request.id] = request
        self._requests = loaded

    def _persist(self) -> None:
        entries = [_encode_request(request) for request in self._requests.values()]
        serialized = json.dumps(
            {"version": self.VERSION, "requests": entries},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
        if len(serialized.encode("utf-8")) > self.MAX_BYTES:
            raise ValueError("approval store size limit reached")
        if not self.path.parent.exists() or not self.path.parent.is_dir():
            raise ValueError("approval store parent directory must exist")
        temporary_path: str | None = None
        with self._file_lock:
            with _approval_path_lock(self.path, exclusive=True):
                try:
                    with tempfile.NamedTemporaryFile(
                        mode="w",
                        encoding="utf-8",
                        dir=self.path.parent,
                        prefix=f".{self.path.name}.",
                        suffix=".tmp",
                        delete=False,
                    ) as handle:
                        temporary_path = handle.name
                        os.chmod(handle.name, 0o600)
                        handle.write(serialized)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(temporary_path, self.path)
                    temporary_path = None
                    os.chmod(self.path, 0o600)
                except OSError as exc:
                    raise ValueError("approval store cannot be saved") from exc
                finally:
                    if temporary_path is not None:
                        try:
                            os.unlink(temporary_path)
                        except FileNotFoundError:
                            pass


def _encode_request(request: ApprovalRequest) -> dict[str, object]:
    return {
        "id": request.id,
        "timestamp": request.timestamp,
        "actor": request.actor,
        "action": request.action,
        "risk_level": request.risk_level.value,
        "command_id": request.command_id,
        "reason": request.reason,
        "status": request.status.value,
        "decided_by": request.decided_by,
        "decided_at": request.decided_at,
        "decided_by_role": request.decided_by_role,
        "actor_role": request.actor_role,
        "policy_version": request.policy_version,
        "effective_permissions": list(request.effective_permissions),
        "resource": request.resource,
        "plan_id": request.plan_id,
        "expires_at": request.expires_at,
        "operation_id": request.operation_id,
        "branch": request.branch,
        "commit": request.commit,
        "backup_id": request.backup_id,
        "commands": list(request.commands),
        "files": list(request.files),
        "services_affected": list(request.services_affected),
        "impact": list(request.impact),
        "operation_hash": request.operation_hash,
        "plan_hash": request.plan_hash,
        "approval_hash": request.approval_hash,
        "execution_hash": request.execution_hash,
    }


def _decode_request(value: object) -> ApprovalRequest:
    if not isinstance(value, dict):
        raise ValueError("approval request record is invalid")
    try:
        effective_permissions = value.get("effective_permissions", [])
        if not isinstance(effective_permissions, list):
            raise ValueError("approval permissions are invalid")
        snapshot_lists: dict[str, tuple[str, ...]] = {}
        for key in ("commands", "files", "services_affected", "impact"):
            raw_values = value.get(key, [])
            if not isinstance(raw_values, list) or any(not isinstance(item, str) for item in raw_values):
                raise ValueError(f"approval {key} are invalid")
            snapshot_lists[key] = tuple(raw_values)
        request = ApprovalRequest(
            id=value["id"],
            timestamp=value["timestamp"],
            actor=value["actor"],
            action=value["action"],
            risk_level=RiskLevel(value["risk_level"]),
            command_id=value["command_id"],
            reason=value["reason"],
            status=ApprovalStatus(value["status"]),
            decided_by=value["decided_by"],
            decided_at=value["decided_at"],
            decided_by_role=value.get("decided_by_role"),
            actor_role=value.get("actor_role", "UNKNOWN"),
            policy_version=value.get("policy_version", "legacy"),
            effective_permissions=tuple(effective_permissions),
            resource=value.get("resource", "unknown"),
            plan_id=value.get("plan_id"),
            expires_at=value.get("expires_at"),
            operation_id=value.get("operation_id"),
            branch=value.get("branch"),
            commit=value.get("commit"),
            backup_id=value.get("backup_id"),
            commands=snapshot_lists["commands"],
            files=snapshot_lists["files"],
            services_affected=snapshot_lists["services_affected"],
            impact=snapshot_lists["impact"],
            operation_hash=value.get("operation_hash"),
            plan_hash=value.get("plan_hash"),
            approval_hash=value.get("approval_hash"),
            execution_hash=value.get("execution_hash"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("approval request record is invalid") from exc
    fields = (
        request.id,
        request.timestamp,
        request.actor,
        request.action,
        request.command_id,
        request.reason,
        request.decided_by,
        request.decided_at,
        request.decided_by_role,
        request.actor_role,
        request.policy_version,
        request.resource,
        request.plan_id,
        request.expires_at,
        request.operation_id,
        request.branch,
        request.commit,
        request.backup_id,
        request.operation_hash,
        request.plan_hash,
        request.approval_hash,
        request.execution_hash,
        *request.commands,
        *request.files,
        *request.services_affected,
        *request.impact,
    )
    if (
        any(value is not None and (not isinstance(value, str) or not value.strip() or len(value) > 512) for value in fields)
        or not isinstance(request.command_id, (str, type(None)))
        or not isinstance(request.decided_by, (str, type(None)))
        or not isinstance(request.decided_at, (str, type(None)))
        or not isinstance(request.decided_by_role, (str, type(None)))
        or not isinstance(request.actor_role, str)
        or not isinstance(request.policy_version, str)
        or not isinstance(request.resource, str)
        or not isinstance(request.plan_id, (str, type(None)))
        or not isinstance(request.expires_at, (str, type(None)))
        or any(not isinstance(item, str) for item in (*request.commands, *request.files, *request.services_affected, *request.impact))
        or any(len(item) > 512 for item in (*request.commands, *request.files, *request.services_affected, *request.impact))
        or any(not isinstance(item, (str, type(None))) for item in (request.operation_id, request.branch, request.commit, request.backup_id, request.operation_hash, request.plan_hash, request.approval_hash, request.execution_hash))
        or any(not isinstance(item, str) for item in request.effective_permissions)
        or any(contains_secret(value) or RAW_STREAM_PATTERN.search(value) for value in fields if isinstance(value, str))
    ):
        raise ValueError("approval request record contains unsafe metadata")
    try:
        _normalize_permissions(request.effective_permissions)
        _validate_expiry(request.expires_at or _future_expiry())
    except ApprovalStateError as exc:
        raise ValueError("approval request record contains unsafe metadata") from exc
    if request.status is ApprovalStatus.PENDING and (request.decided_by is not None or request.decided_at is not None):
        raise ValueError("pending approval request contains a decision")
    if request.status in {ApprovalStatus.APPROVED, ApprovalStatus.DENIED, ApprovalStatus.EXPIRED}:
        if request.decided_by is None or request.decided_at is None:
            raise ValueError("decided approval request is incomplete")
        if request.status is ApprovalStatus.APPROVED and request.actor == request.decided_by:
            raise ValueError("approval request contains a self-approval")
    if request.plan_id is None or request.expires_at is None:
        request = replace(
            request,
            plan_id=request.plan_id or f"plan-{request.id}",
            expires_at=request.expires_at or _expiry_from_timestamp(request.timestamp),
        )
    if request.operation_id is None:
        request = replace(request, operation_id=request.plan_id)
    if request.approval_hash is not None and request.status in {ApprovalStatus.APPROVED, ApprovalStatus.DENIED}:
        if request.approval_hash != _approval_hash(request):
            raise ValueError("approval request integrity hash does not match")
    return request


def _validate_approval_path(path: Path) -> Path:
    critical_names = {".env", "AGENTS.md", "INVENTORY.json", "Cibermedida VPS Control Center.md"}
    if not path.is_absolute() or path.suffix != ".json" or path.name in critical_names:
        raise ValueError("unsafe approval store path")
    if ".git" in path.parts or any(part.startswith(".env") for part in path.parts):
        raise ValueError("unsafe approval store path")
    if path.parent.exists() and not path.parent.is_dir():
        raise ValueError("approval store parent is not a directory")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("approval store path must be a regular file")
    return path


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _future_expiry() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()


def _expiry_from_timestamp(value: str) -> str:
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError
    except ValueError:
        return _future_expiry()
    return (timestamp + timedelta(hours=24)).isoformat()


def _validate_snapshot_text(value: str, *, field: str) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 512
        or contains_secret(value)
        or RAW_STREAM_PATTERN.search(value)
        or any(ord(character) < 32 for character in value)
    ):
        raise ApprovalStateError(f"{field} contains unsafe metadata")


def _normalize_permissions(values: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)):
        raise ApprovalStateError("effective permissions must be a list of strings")
    normalized = tuple(sorted({value.strip() for value in values if isinstance(value, str) and value.strip()}))
    if len(normalized) != len(values):
        raise ApprovalStateError("effective permissions contain invalid values")
    for value in normalized:
        _validate_snapshot_text(value, field="effective_permissions")
    return normalized


def _validate_expiry(value: str) -> None:
    if not isinstance(value, str) or len(value) > 64:
        raise ApprovalStateError("approval expiry is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApprovalStateError("approval expiry is invalid") from exc
    if parsed.tzinfo is None:
        raise ApprovalStateError("approval expiry must include a timezone")


def _is_expired(value: str | None, *, now: datetime | None = None) -> bool:
    if value is None:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return True
    if parsed.tzinfo is None:
        return True
    return (now or datetime.now(timezone.utc)) >= parsed


def _approval_hash(request: ApprovalRequest) -> str:
    """Hash the immutable approval snapshot without storing raw output."""

    payload = {
        "id": request.id,
        "operation_id": request.operation_id,
        "operation_hash": request.operation_hash,
        "plan_hash": request.plan_hash,
        "actor": request.actor,
        "actor_role": request.actor_role,
        "decided_by": request.decided_by,
        "decided_by_role": request.decided_by_role,
        "action": request.action,
        "risk_level": request.risk_level.value,
        "command_id": request.command_id,
        "resource": request.resource,
        "branch": request.branch,
        "commit": request.commit,
        "backup_id": request.backup_id,
        "commands": request.commands,
        "files": request.files,
        "services_affected": request.services_affected,
        "impact": request.impact,
        "policy_version": request.policy_version,
        "effective_permissions": request.effective_permissions,
        "expires_at": request.expires_at,
        "reason": request.reason,
        "status": request.status.value,
    }
    serialized = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


@contextmanager
def _approval_path_lock(path: Path, *, exclusive: bool) -> Iterator[None]:
    """Coordinate approval snapshots across application processes."""

    lock_path = path.with_name(f".{path.name}.lock")
    try:
        with lock_path.open("a+", encoding="utf-8") as lock_handle:
            os.chmod(lock_path, 0o600)
            operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            fcntl.flock(lock_handle.fileno(), operation)
            try:
                yield
            finally:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
    except OSError as exc:
        raise ValueError("approval store lock cannot be acquired") from exc
