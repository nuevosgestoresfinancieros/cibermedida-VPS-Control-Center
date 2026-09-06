"""Local Control Center server with safe in-memory application workflows.

The server exposes the Spanish read-only shell plus explicit authentication,
planning and metadata-only workflow endpoints. It binds to loopback by
default, never reads operational VPS data and never executes a production
action.
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import shlex
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from getpass import getpass
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit
from uuid import uuid4

from control_center import (
    ControlCenterApplication,
    ActivationManifest,
    ActivationManifestError,
    FilesystemBackupProvider,
    FilesystemReleaseProvider,
    DeclaredCommandBuildProvider,
    SyntheticBuildProvider,
    CodexCliProvider,
    ReadSafeInventoryProvider,
    JsonUserStore,
    JsonlAuditSink,
    JsonMetadataStore,
    load_activation_manifest,
    ReadSafeExecutionProvider,
    ReadSafeMonitoringProvider,
    ReadSafeProjectProvider,
    SyntheticReadSafeExecutionProvider,
    SyntheticReadSafeMonitoringProvider,
    SyntheticInventoryProvider,
    SyntheticProjectProvider,
    InProcessTestProvider,
    SyntheticTestProvider,
    SyntheticCodexProvider,
    OpenAICompatibleChatProvider,
    evaluate_production_readiness,
)
from control_center.auth import (
    AuthenticationError,
    AuthorizationError,
    CSRFError,
    Permission,
    RateLimitError,
    Role,
    TotpVerifier,
)
from control_center.backups import BackupType
from control_center.incidents import IncidentSeverity, IncidentStatus
from control_center.monitoring import MetricSnapshot
from phase1_inventory.executor import RestrictedExecutor
from core_operator import (
    CoreHealthChecker,
    Decision,
    InMemoryAuditStore,
    InMemoryStructuredLogger,
    JsonApprovalStore,
    PolicyEngine,
    PolicyRequest,
    default_config,
)
from core_operator.audit import RAW_STREAM_PATTERN, contains_secret

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = PROJECT_ROOT / "web" / "readonly-shell"
STATUS_PATH = WEB_ROOT / "data" / "status.json"
MAX_BODY_BYTES = 64 * 1024
LAB_PROFILE_NAME = "cibermedida-control-center-lab"


def load_mock_status() -> dict[str, Any]:
    """Load only the repository-controlled, non-live status document."""

    with STATUS_PATH.open("r", encoding="utf-8") as handle:
        status = json.load(handle)
    if not isinstance(status, dict):
        raise ValueError("status data must be a JSON object")
    data_source = status.get("dataSource")
    if not isinstance(data_source, dict) or data_source.get("liveData") is not False:
        raise ValueError("live data is not permitted for the read-only API")
    return status


def build_core_health() -> dict[str, Any]:
    """Expose the internal health contract without operational probes."""

    try:
        config = default_config()
        result = CoreHealthChecker(
            config=config,
            policy=PolicyEngine(),
            audit=InMemoryAuditStore(),
            logger=InMemoryStructuredLogger(),
        ).check()
    except (OSError, ValueError):
        return {
            "status": "degraded",
            "checks": {"core_operator_wiring": False},
            "network_checks": False,
            "real_execution": False,
        }
    return {
        "status": result.status,
        "checks": result.checks,
        "network_checks": False,
        "real_execution": False,
    }


def build_api_status(application: ControlCenterApplication | None = None) -> dict[str, Any]:
    status = copy.deepcopy(load_mock_status())
    if application is not None:
        status["capabilities"] = jsonable(application.capabilities.statuses)
    execution_enabled = bool(application and application.execution.enabled and application.execution.provider)
    execution_live = bool(
        execution_enabled and getattr(application.execution.provider, "live_data", False)
    )
    testing_enabled = bool(application and application.tests.provider_enabled and application.tests.provider)
    builds_enabled = bool(application and application.builds.provider_enabled and application.builds.provider)
    codex_enabled = bool(application and application.codex.provider_enabled and application.codex.provider)
    monitoring_enabled = bool(
        application and application.monitoring.provider_enabled and application.monitoring.provider
    )
    monitoring_live = bool(
        monitoring_enabled and getattr(application.monitoring.provider, "live_data", False)
    )
    inventory_enabled = bool(application and application.inventory.provider_enabled and application.inventory.provider)
    inventory_live = bool(
        inventory_enabled and getattr(application.inventory.provider, "live_data", False)
    )
    projects_enabled = bool(application and application.projects.provider_enabled and application.projects.provider)
    projects_live = bool(
        projects_enabled and getattr(application.projects.provider, "live_data", False)
    )
    status["runtime"] = {
        "transport": "local-readonly-api",
        "liveData": monitoring_live or inventory_live or projects_live,
        "execution": "provider_enabled" if execution_enabled else "blocked_by_default",
        "monitoring": "provider_enabled" if monitoring_enabled else "snapshot_only",
        "inventory": "provider_enabled" if inventory_enabled else "blocked_by_default",
        "projects": "provider_enabled" if projects_enabled else "mock_catalog",
        "testing": "provider_enabled" if testing_enabled else "contract_only",
        "builds": "provider_enabled" if builds_enabled else "contract_only",
        "codex": "provider_enabled" if codex_enabled else "contract_only",
        "application": "in-memory-workflows",
    }
    status["product"]["executionStatus"] = (
        "Ejecución READ_SAFE live habilitada"
        if execution_live
        else "Ejecución READ_SAFE sintética de laboratorio"
        if execution_enabled
        else "Ejecución real bloqueada"
    )
    live_read_safe = monitoring_live or inventory_live or projects_live
    status["dataSource"] = {
        "mode": "API local solo lectura con proveedor READ_SAFE" if live_read_safe else "API local solo lectura con datos simulados",
        "path": "/api/status -> web/readonly-shell/data/status.json",
        "liveData": live_read_safe,
        "backend": True,
    }
    return status


def build_inventory_summary(application: ControlCenterApplication | None = None) -> dict[str, Any]:
    if application is None:
        return {
            "mode": "mock",
            "liveData": False,
            "persisted": False,
            "status": "not_collected",
            "provider": None,
            "message": "No se ha ejecutado inventario real desde esta aplicación.",
        }
    return application.inventory.summary()


def build_server_status() -> dict[str, Any]:
    return {
        "server": "cibermedida-vps-mock",
        "environment": "production-protected",
        "liveData": False,
        "status": "not_connected",
        "message": "El servidor real no se consulta desde esta aplicación local.",
        "checks": {"network": False, "services": False, "storage": False},
    }


def build_projects() -> list[dict[str, Any]]:
    return [
        {
            "id": "control-center",
            "name": "Cibermedida VPS Control Center",
            "repository": "repository-mock",
            "branch": "main-mock",
            "status": "not_connected",
            "liveData": False,
        }
    ]


def build_services() -> list[dict[str, Any]]:
    return [
        {
            "id": "web-shell",
            "name": "Web Control Center",
            "technology": "static-html-python-api",
            "status": "mock",
            "liveData": False,
        },
        {
            "id": "core-operator",
            "name": "Core Operator",
            "technology": "python-in-memory",
            "status": "blocked_by_default",
            "liveData": False,
        },
    ]


def jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [jsonable(item) for item in value]
    return value


def parse_bootstrap_user(value: str) -> tuple[str, Role]:
    """Parse an explicit ``username[:ROLE]`` bootstrap declaration."""

    if not isinstance(value, str):
        raise ValueError("bootstrap user must be text")
    username, separator, role_text = value.strip().partition(":")
    if not username or any(character.isspace() for character in username):
        raise ValueError("bootstrap username is invalid")
    role = Role(role_text.upper()) if separator and role_text else Role.VIEWER
    return username, role


def parse_build_profile(value: str) -> tuple[str, tuple[str, ...]]:
    """Parse one startup-only ``target=argv`` build declaration."""

    if not isinstance(value, str):
        raise ValueError("build profile must be text")
    target, separator, command = value.partition("=")
    if not separator or not target.strip() or not command.strip():
        raise ValueError("build profile must use TARGET=EXECUTABLE [ARG ...]")
    try:
        argv = tuple(shlex.split(command, posix=True))
    except ValueError as exc:
        raise ValueError("build profile quoting is invalid") from exc
    if not argv:
        raise ValueError("build profile command is empty")
    return target.strip(), argv


def parse_codex_project(value: str) -> tuple[str, Path]:
    """Parse one startup-only ``name=/absolute/project`` declaration."""

    if not isinstance(value, str):
        raise ValueError("Codex project must be text")
    name, separator, raw_path = value.partition("=")
    path = Path(raw_path.strip()) if separator else Path()
    if not name.strip() or not separator or not path.is_absolute():
        raise ValueError("Codex project must use NAME=/absolute/path")
    return name.strip(), path


class ControlCenterHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[SimpleHTTPRequestHandler],
        application: ControlCenterApplication,
        *,
        secure_cookies: bool = False,
        activation_manifest: ActivationManifest | None = None,
        activation_manifest_path: str | Path | None = None,
        https_terminated: bool = False,
    ) -> None:
        self.application = application
        self.secure_cookies = secure_cookies
        self.activation_manifest = activation_manifest
        self.activation_manifest_path = Path(activation_manifest_path) if activation_manifest_path is not None else None
        self.https_terminated = https_terminated
        super().__init__(address, handler)


class ReadOnlyHandler(SimpleHTTPRequestHandler):
    """Serve the Spanish shell and local, policy-gated application endpoints."""

    server_version = "CibermedidaControlCenter/1.0"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    @property
    def application(self) -> ControlCenterApplication:
        return self.server.application  # type: ignore[attr-defined]

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; connect-src 'self'; script-src 'self'; "
            "style-src 'self'; img-src 'self'; frame-ancestors 'none'",
        )
        super().end_headers()

    def do_GET(self) -> None:
        path = urlsplit(self.path).path.rstrip("/") or "/"
        if not path.startswith("/api"):
            super().do_GET()
            return
        try:
            if path == "/api/health":
                self._send_json(build_core_health())
            elif path == "/api/status":
                self._send_json(build_api_status(self.application))
            elif path == "/api/policy":
                status = build_api_status(self.application)
                self._send_json(
                    {
                        "policyMatrix": status["policyMatrix"],
                        "executionStatus": status["product"]["executionStatus"],
                        "default": "deny_or_approval_required",
                    }
                )
            elif path == "/api/audit-preview":
                status = build_api_status(self.application)
                self._send_json(
                    {
                        "auditPreview": status["auditPreview"],
                        "storage": "in-memory mock",
                        "rawOutput": False,
                    }
                )
            elif path == "/api/inventory/summary":
                self._require_live_provider(
                    self.application.inventory.provider,
                    "phase1-read-safe-inventory",
                )
                self._send_json(build_inventory_summary(self.application))
            elif path == "/api/inventory":
                self._require(Permission.VIEW_INVENTORY_METADATA)
                self._require_live_provider(
                    self.application.inventory.provider,
                    "phase1-read-safe-inventory",
                    required_permission=Permission.VIEW_INVENTORY_METADATA,
                )
                latest = self.application.inventory.latest
                self._send_json(
                    {
                        "summary": build_inventory_summary(self.application),
                        "collection": jsonable(latest) if latest is not None else None,
                    }
                )
            elif path == "/api/server/status":
                self._send_json(build_server_status())
            elif path == "/api/projects":
                provider = self.application.projects.provider
                if self.application.projects.provider_enabled and provider is not None:
                    self._require(Permission.VIEW_PROJECTS)
                    self._require_live_provider(
                        provider,
                        "phase1-read-safe-projects" if getattr(provider, "live_data", False) else None,
                        required_permission=Permission.VIEW_PROJECTS,
                    )
                    self._send_json(
                        {
                            "projects": jsonable(self.application.projects.records),
                            "liveData": bool(getattr(provider, "live_data", False)),
                            "provider": getattr(provider, "name", None),
                        }
                    )
                else:
                    self._send_json({"projects": build_projects(), "liveData": False})
            elif path.startswith("/api/projects/") and path.endswith("/status"):
                project_id = path.removeprefix("/api/projects/").removesuffix("/status").strip("/")
                provider = self.application.projects.provider
                if self.application.projects.provider_enabled and provider is not None:
                    self._require(Permission.VIEW_PROJECTS)
                    self._require_live_provider(
                        provider,
                        "phase1-read-safe-projects" if getattr(provider, "live_data", False) else None,
                        required_permission=Permission.VIEW_PROJECTS,
                    )
                    project = next(
                        (item for item in self.application.projects.records if item.project_id == project_id),
                        None,
                    )
                    if project is None:
                        self._send_json({"error": "not_found"}, status=HTTPStatus.NOT_FOUND)
                    else:
                        self._send_json(
                            {
                                "project": jsonable(project),
                                "status": project.state.value,
                                "liveData": project.live_data,
                            }
                        )
                else:
                    project = next((item for item in build_projects() if item["id"] == project_id), None)
                    if project is None:
                        self._send_json({"error": "not_found"}, status=HTTPStatus.NOT_FOUND)
                    else:
                        self._send_json({"project": project, "status": "not_connected", "liveData": False})
            elif path == "/api/services":
                self._send_json({"services": build_services(), "liveData": False})
            elif path.startswith("/api/services/") and path.endswith("/logs"):
                self._require(Permission.VIEW_LOGS)
                self._send_json(
                    {
                        "error": "raw_logs_disabled",
                        "message": "La lectura de logs reales está bloqueada por diseño.",
                        "liveData": False,
                    },
                    status=HTTPStatus.FORBIDDEN,
                )
            elif path == "/api/views":
                self._send_json({"views": build_api_status(self.application)["views"]})
            elif path == "/api/capabilities":
                self._send_json({"capabilities": jsonable(self.application.capabilities.statuses)})
            elif path == "/api/readiness":
                self._require(Permission.VIEW_CORE_OPERATOR)
                report = evaluate_production_readiness(
                    self.application,
                    secure_cookies=self.server.secure_cookies,  # type: ignore[attr-defined]
                    https_terminated=self.server.https_terminated,  # type: ignore[attr-defined]
                    activation_manifest=self._runtime_activation_manifest(),
                )
                self._send_json(report.as_dict())
            elif path in {"/api/auth/me", "/api/auth/csrf"}:
                user, session = self._authenticated_session()
                self._send_json(self._user_payload(user, session))
            elif path == "/api/audit":
                self._require(Permission.VIEW_AUDIT_METADATA)
                self._send_json({"records": jsonable(self.application.audit.records)})
            elif path == "/api/approvals":
                self._require(Permission.VIEW_AUDIT_METADATA)
                self._send_json({"requests": jsonable(self.application.approvals.requests)})
            elif path == "/api/operations":
                self._require(Permission.VIEW_CORE_OPERATOR)
                self._send_json({"plans": jsonable(self.application.operations.plans)})
            elif path == "/api/execution":
                self._require(Permission.VIEW_CORE_OPERATOR)
                self._require_live_provider(
                    self.application.execution.provider,
                    "phase1-read-safe-execution",
                    required_permission=Permission.VIEW_CORE_OPERATOR,
                )
                self._send_json(
                    {
                        "enabled": self.application.execution.enabled,
                        "provider": getattr(self.application.execution.provider, "name", None),
                        "records": jsonable(self.application.execution.records),
                        "execution": "provider_enabled" if self.application.execution.enabled else "blocked_by_default",
                    }
                )
            elif path == "/api/backups":
                self._require(Permission.VIEW_BACKUPS)
                self._require_live_provider(
                    self.application.backups.provider,
                    "declared-filesystem-backup",
                    required_permission=Permission.VIEW_BACKUPS,
                )
                self._send_json({"records": jsonable(self.application.backups.records)})
            elif path == "/api/deployments":
                self._require(Permission.VIEW_PROJECTS)
                self._require_live_provider(
                    self.application.deployments.provider,
                    "declared-filesystem-release",
                    required_permission=Permission.VIEW_PROJECTS,
                )
                self._send_json({"plans": jsonable(self.application.deployments.plans)})
            elif path == "/api/rollbacks":
                self._require(Permission.VIEW_PROJECTS)
                self._require_live_provider(
                    self.application.rollbacks.provider,
                    "declared-filesystem-release",
                    required_permission=Permission.VIEW_PROJECTS,
                )
                self._send_json({"plans": jsonable(self.application.rollbacks.plans)})
            elif path == "/api/incidents":
                self._require(Permission.VIEW_INCIDENTS)
                self._send_json({"incidents": jsonable(self.application.incidents.incidents)})
            elif path == "/api/monitoring":
                self._require(Permission.VIEW_MONITORING)
                self._require_live_provider(
                    self.application.monitoring.provider,
                    "phase1-read-safe-monitoring",
                    required_permission=Permission.VIEW_MONITORING,
                )
                latest = self.application.monitoring.latest()
                self._send_json(
                    {
                        "latest": jsonable(latest),
                        "history": jsonable(self.application.monitoring.snapshots),
                        "anomalies": list(self.application.monitoring.anomalies()),
                        "liveData": bool(
                            self.application.monitoring.provider_enabled
                            and self.application.monitoring.provider
                            and getattr(self.application.monitoring.provider, "live_data", False)
                        ),
                    }
                )
            elif path == "/api/chat/messages":
                self._require(Permission.VIEW_DASHBOARD)
                self._send_json({"messages": jsonable(self.application.conversation.messages)})
            elif path == "/api/validation":
                self._require(Permission.VIEW_CORE_OPERATOR)
                self._send_json({"reports": jsonable(self.application.validator.reports)})
            elif path == "/api/tests/runs":
                self._require(Permission.VIEW_CORE_OPERATOR)
                self._require_live_provider(
                    self.application.tests.provider,
                    "repository-tests"
                    if self.application.tests.provider is not None
                    and getattr(self.application.tests.provider, "live_data", False)
                    else None,
                    required_permission=Permission.VIEW_CORE_OPERATOR,
                )
                self._send_json({"runs": jsonable(self.application.tests.runs)})
            elif path == "/api/builds/runs":
                self._require(Permission.VIEW_CORE_OPERATOR)
                self._require_live_provider(
                    self.application.builds.provider,
                    "declared-build"
                    if self.application.builds.provider is not None
                    and getattr(self.application.builds.provider, "live_data", False)
                    else None,
                    required_permission=Permission.VIEW_CORE_OPERATOR,
                )
                self._send_json({"runs": jsonable(self.application.builds.runs)})
            elif path == "/api/codex/runs":
                self._require(Permission.VIEW_PROJECTS)
                self._require_live_provider(
                    self.application.codex.provider,
                    "codex-provider"
                    if self.application.codex.provider is not None
                    and getattr(self.application.codex.provider, "live_data", False)
                    else None,
                    required_permission=Permission.VIEW_PROJECTS,
                )
                self._send_json({"runs": jsonable(self.application.codex.runs)})
            elif path == "/api/knowledge":
                self._require(Permission.VIEW_PROJECTS)
                self._send_json({"records": jsonable(self.application.knowledge.records)})
            elif path == "/api/impact":
                self._require(Permission.VIEW_PROJECTS)
                self._send_json({"reports": jsonable(self.application.impact.reports)})
            elif path == "/api/drift":
                self._require(Permission.VIEW_PROJECTS)
                self._send_json({"reports": jsonable(self.application.drift.reports)})
            elif path == "/api/agents":
                self._require(Permission.VIEW_CORE_OPERATOR)
                self._send_json(
                    {
                        "agents": jsonable(self.application.agents.agents),
                        "tasks": jsonable(self.application.agents.tasks),
                    }
                )
            elif path == "/api/changes":
                self._require(Permission.VIEW_AUDIT_METADATA)
                self._send_json({"changes": jsonable(self.application.changes.changes)})
            elif path == "/api/digital-twin":
                self._require(Permission.VIEW_PROJECTS)
                self._send_json({"twins": jsonable(self.application.v3.twins)})
            elif path == "/api/history/correlation":
                self._require(Permission.VIEW_MONITORING)
                self._send_json({"correlations": jsonable(self.application.v3.correlations)})
            elif path == "/api/predictive":
                self._require(Permission.VIEW_MONITORING)
                self._send_json({"reports": jsonable(self.application.v3.predictions)})
            elif path == "/api/autonomy":
                self._require(Permission.VIEW_CORE_OPERATOR)
                self._send_json({"profiles": jsonable(self.application.v3.autonomy_profiles)})
            elif path == "/api/servers":
                self._require(Permission.VIEW_PROJECTS)
                self._send_json({"servers": jsonable(self.application.v3.servers)})
            elif path == "/api/recovery":
                self._require(Permission.VIEW_INCIDENTS)
                self._send_json({"plans": jsonable(self.application.v3.recovery_plans)})
            else:
                self._send_json({"error": "not_found"}, status=HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self._send_exception(exc)

    def do_POST(self) -> None:
        path = urlsplit(self.path).path.rstrip("/") or "/"
        try:
            body = self._read_json_body()
        except Exception as exc:
            self._send_exception(exc)
            return
        try:
            if path == "/api/auth/login":
                self._login(body)
                return
            if path == "/api/auth/logout":
                session_id = self._session_id()
                self.application.auth.require_csrf(session_id, self._csrf_token(body))
                self.application.auth.logout(session_id)
                self._send_json(
                    {"authenticated": False},
                    headers={"Set-Cookie": self._expired_cookie()},
                )
                return
            if path == "/api/chat":
                self._require_csrf(body)
                self._require_live_provider(
                    self.application.conversation.provider,
                    "openai-compatible-chat",
                    required_permission=Permission.VIEW_DASHBOARD,
                )
                result = self.application.conversation.handle(
                    session_id=self._session_id(), message=self._required_string(body, "message")
                )
                self._send_json(jsonable(result), status=HTTPStatus.CREATED)
                return
            if path == "/api/diagnostics":
                self._require_csrf(body)
                user = self._require(Permission.RUN_DIAGNOSTICS)
                target = self._required_string(body, "target")
                scope = body.get("scope", [])
                if not isinstance(scope, list) or not all(isinstance(item, str) and item.strip() for item in scope):
                    raise ValueError("scope must be a list of strings")
                if any(_unsafe_request_text(item) for item in scope):
                    raise ValueError("scope contains unsafe metadata")
                self.application.audit.append(
                    user_id=user.user_id,
                    actor=user.username,
                    role=user.role.value,
                    project=target,
                    action="diagnostic_planned",
                    risk="LOW",
                    authorization="permission:RUN_DIAGNOSTICS",
                    result="blocked_by_default",
                    metadata={"scope_count": len(scope), "executed": False},
                )
                self._send_json(
                    {
                        "diagnostic_id": f"diagnostic-{uuid4()}",
                        "target": target,
                        "state": "blocked_by_default",
                        "executed": False,
                        "scope": tuple(scope),
                        "message": "No se han consultado logs, procesos ni servicios reales.",
                    },
                    status=HTTPStatus.CREATED,
                )
                return
            if path == "/api/monitoring/snapshot":
                self._require_csrf(body)
                user = self._require(Permission.RUN_DIAGNOSTICS)
                snapshot = MetricSnapshot(
                    timestamp=self._optional_string(body, "timestamp") or datetime.now(timezone.utc).isoformat(),
                    cpu_percent=self._number(body, "cpu_percent"),
                    memory_percent=self._number(body, "memory_percent"),
                    disk_percent=self._number(body, "disk_percent"),
                    load_1m=self._number(body, "load_1m"),
                    http_error_rate=self._number(body, "http_error_rate", default=0.0),
                    service_restarts=self._integer(body, "service_restarts", default=0),
                )
                recorded = self.application.monitoring.record(snapshot)
                anomalies = self.application.monitoring.anomalies(recorded)
                self.application.audit.append(
                    user_id=user.user_id,
                    actor=user.username,
                    role=user.role.value,
                    action="monitoring_snapshot_recorded",
                    risk="LOW",
                    authorization="permission:RUN_DIAGNOSTICS",
                    result="metadata_only",
                    metadata={"anomaly_count": len(anomalies), "live_data": False},
                )
                self._send_json(
                    {"latest": recorded, "anomalies": list(anomalies), "liveData": False, "executed": False},
                    status=HTTPStatus.CREATED,
                )
                return
            if path == "/api/inventory/collect":
                self._require_csrf(body)
                self._require_live_provider(
                    self.application.inventory.provider,
                    "phase1-read-safe-inventory",
                    required_permission=Permission.RUN_READ_SAFE,
                )
                result = self.application.inventory.collect(session_id=self._session_id())
                self._send_json(jsonable(result), status=HTTPStatus.CREATED)
                return
            if path == "/api/projects/collect":
                self._require_csrf(body)
                provider = self.application.projects.provider
                self._require_live_provider(
                    provider,
                    "phase1-read-safe-projects" if provider is not None and getattr(provider, "live_data", False) else None,
                    required_permission=Permission.RUN_READ_SAFE,
                )
                result = self.application.projects.collect(session_id=self._session_id())
                self._send_json(jsonable(result), status=HTTPStatus.CREATED)
                return
            if path == "/api/monitoring/collect":
                self._require_csrf(body)
                user = self._require(Permission.RUN_DIAGNOSTICS)
                self._require_live_provider(
                    self.application.monitoring.provider,
                    "phase1-read-safe-monitoring",
                    required_permission=Permission.RUN_DIAGNOSTICS,
                )
                result = self.application.monitoring.collect()
                incident = None
                if result.state == "collected" and result.anomalies:
                    severity = IncidentSeverity.HIGH if "disk_high" not in result.anomalies else IncidentSeverity.CRITICAL
                    incident = self.application.incidents.create(
                        session_id=self._session_id(),
                        project="control-center",
                        service="read-safe-monitoring",
                        severity=severity,
                        symptom=f"Anomalías metadata-only: {', '.join(result.anomalies)}",
                        detected_by="read-safe-monitoring",
                    )
                self.application.audit.append(
                    user_id=user.user_id,
                    actor=user.username,
                    role=user.role.value,
                    action="monitoring_collection_requested",
                    risk="LOW",
                    authorization="permission:RUN_DIAGNOSTICS",
                    result=result.state,
                    metadata={
                        "provider": result.provider,
                        "live_data": result.state == "collected",
                        "incident_created": incident is not None,
                    },
                )
                payload = jsonable(result)
                if incident is not None:
                    payload["incident"] = jsonable(incident)
                self._send_json(payload, status=HTTPStatus.CREATED)
                return
            if path == "/api/execution/evaluate":
                self._require_csrf(body)
                self._require_live_provider(
                    self.application.execution.provider,
                    "phase1-read-safe-execution",
                    required_permission=Permission.VIEW_CORE_OPERATOR,
                )
                result = self.application.execution_pipeline.run(
                    session_id=self._session_id(),
                    action=self._required_string(body, "action"),
                    command_id=self._required_string(body, "command_id"),
                    approval_id=self._required_string(body, "approval_id"),
                )
                self._send_json(jsonable(result), status=HTTPStatus.CREATED)
                return
            if path == "/api/tests/run":
                self._require_csrf(body)
                self._require_live_provider(
                    self.application.tests.provider,
                    "repository-tests"
                    if self.application.tests.provider is not None
                    and getattr(self.application.tests.provider, "live_data", False)
                    else None,
                    required_permission=Permission.RUN_TESTS,
                )
                run = self.application.tests.run(
                    session_id=self._session_id(),
                    target=self._required_string(body, "target"),
                )
                self._send_json(jsonable(run), status=HTTPStatus.CREATED)
                return
            if path == "/api/builds/run":
                self._require_csrf(body)
                self._require_live_provider(
                    self.application.builds.provider,
                    "declared-build"
                    if self.application.builds.provider is not None
                    and getattr(self.application.builds.provider, "live_data", False)
                    else None,
                    required_permission=Permission.RUN_BUILDS,
                )
                run = self.application.builds.run(
                    session_id=self._session_id(),
                    target=self._required_string(body, "target"),
                )
                self._send_json(jsonable(run), status=HTTPStatus.CREATED)
                return
            if path == "/api/codex/analyze":
                self._require_csrf(body)
                self._require_live_provider(
                    self.application.codex.provider,
                    "codex-provider"
                    if self.application.codex.provider is not None
                    and getattr(self.application.codex.provider, "live_data", False)
                    else None,
                    required_permission=Permission.VIEW_PROJECTS,
                )
                run = self.application.codex.analyze(
                    session_id=self._session_id(),
                    project=self._required_string(body, "project"),
                    request_kind=self._required_string(body, "request_kind"),
                )
                self._send_json(jsonable(run), status=HTTPStatus.CREATED)
                return
            if path == "/api/tests":
                self._require_csrf(body)
                checks = body.get("checks", {})
                if not isinstance(checks, dict):
                    raise ValueError("checks must be an object")
                report = self.application.validator.evaluate(
                    session_id=self._session_id(),
                    target=self._required_string(body, "target"),
                    checks=checks,
                )
                self._send_json(jsonable(report), status=HTTPStatus.CREATED)
                return
            if path == "/api/operations/plan":
                self._require_csrf(body)
                downtime_possible = body.get("downtime_possible", False)
                if not isinstance(downtime_possible, bool):
                    raise ValueError("downtime_possible must be a boolean")
                plan = self.application.operations.plan(
                    session_id=self._session_id(),
                    project=self._required_string(body, "project"),
                    action=self._required_string(body, "action"),
                    resource=str(body.get("resource", "project")),
                    command_id=self._optional_string(body, "command_id"),
                    server=self._optional_string(body, "server") or "local-lab",
                    environment=self._optional_string(body, "environment") or "laboratory",
                    branch=self._optional_string(body, "branch"),
                    commit=self._optional_string(body, "commit"),
                    files=self._string_list(body, "files"),
                    services_affected=self._string_list(body, "services_affected"),
                    dependencies=self._string_list(body, "dependencies"),
                    tests_required=self._string_list(body, "tests_required"),
                    downtime_possible=downtime_possible,
                    data_risk=self._optional_string(body, "data_risk") or "none",
                )
                self._send_json(jsonable(plan), status=HTTPStatus.CREATED)
                return
            if path == "/api/approvals/request":
                self._require_csrf(body)
                user = self._require(Permission.REQUEST_APPROVAL)
                action = self._required_string(body, "action")
                command_id = self._optional_string(body, "command_id")
                if command_id is None:
                    raise ValueError("command_id is required")
                resource = self._optional_string(body, "resource") or f"command:{command_id}"
                effective_permissions = tuple(sorted(permission.value for permission in user.permissions))
                policy_decision = self.application.policy.evaluate(
                    PolicyRequest(actor=user.username, action=action, command_id=command_id)
                )
                if policy_decision.decision is Decision.ALLOW:
                    request = self.application.approvals.create_pending(
                        actor=user.username,
                        action=action,
                        risk_level=policy_decision.risk_level,
                        reason="explicit approval required for controlled execution",
                        command_id=command_id,
                        actor_role=user.role.value,
                        policy_version=self.application.policy_version,
                        effective_permissions=effective_permissions,
                        resource=resource,
                    )
                else:
                    request = self.application.approvals.apply_policy_decision(
                        actor=user.username,
                        action=action,
                        policy_decision=policy_decision,
                        command_id=command_id,
                        actor_role=user.role.value,
                        policy_version=self.application.policy_version,
                        effective_permissions=effective_permissions,
                        resource=resource,
                    )
                if request is None:
                    raise ValueError("policy does not require an approval request")
                self.application.audit.append(
                    user_id=user.user_id,
                    actor=user.username,
                    role=user.role.value,
                    action="approval_request_created",
                    risk=policy_decision.risk_level.value,
                    command=command_id,
                    authorization=policy_decision.decision.value,
                    result=request.status.value,
                    metadata={
                        "approval_id": request.id,
                        "plan_id": request.plan_id,
                        "policy_version": request.policy_version,
                        "effective_permissions": request.effective_permissions,
                        "resource": request.resource,
                    },
                )
                self._send_json(jsonable(request), status=HTTPStatus.CREATED)
                return
            if path == "/api/approvals/approve":
                self._require_csrf(body)
                approver = self._require(Permission.APPROVE_OPERATION)
                request_id = self._required_string(body, "request_id")
                request = self.application.approvals.get(request_id)
                if request.actor == approver.username:
                    raise PermissionError("requester and approver must be different users")
                decision = self.application.approvals.approve(
                    request_id,
                    decided_by=approver.username,
                    decided_by_role=approver.role.value,
                    reason=str(body.get("reason", "approved")),
                )
                self.application.audit.append(
                    user_id=approver.user_id,
                    actor=approver.username,
                    role=approver.role.value,
                    action="approval_request_approved",
                    risk=decision.risk_level.value,
                    command=decision.command_id,
                    authorization="permission:APPROVE_OPERATION",
                    result=decision.status.value,
                    metadata={
                        "approval_id": decision.id,
                        "plan_id": decision.plan_id,
                        "policy_version": decision.policy_version,
                        "effective_permissions": decision.effective_permissions,
                        "resource": decision.resource,
                        "decided_by_role": decision.decided_by_role,
                    },
                )
                self._send_json(jsonable(decision))
                return
            if path == "/api/approvals/deny":
                self._require_csrf(body)
                approver = self._require(Permission.APPROVE_OPERATION)
                request_id = self._required_string(body, "request_id")
                request = self.application.approvals.get(request_id)
                if request.actor == approver.username:
                    raise PermissionError("requester and approver must be different users")
                decision = self.application.approvals.deny(
                    request_id,
                    decided_by=approver.username,
                    decided_by_role=approver.role.value,
                    reason=str(body.get("reason", "denied")),
                )
                self.application.audit.append(
                    user_id=approver.user_id,
                    actor=approver.username,
                    role=approver.role.value,
                    action="approval_request_denied",
                    risk=decision.risk_level.value,
                    command=decision.command_id,
                    authorization="permission:APPROVE_OPERATION",
                    result=decision.status.value,
                    metadata={
                        "approval_id": decision.id,
                        "plan_id": decision.plan_id,
                        "policy_version": decision.policy_version,
                        "effective_permissions": decision.effective_permissions,
                        "resource": decision.resource,
                        "decided_by_role": decision.decided_by_role,
                    },
                )
                self._send_json(jsonable(decision))
                return
            if path == "/api/operations/approve":
                self._require_csrf(body)
                plan = self.application.operations.approve(
                    session_id=self._session_id(),
                    plan_id=self._required_string(body, "plan_id"),
                    reason=str(body.get("reason", "approved")),
                )
                self._send_json(jsonable(plan))
                return
            if path == "/api/operations/attach-backup":
                self._require_csrf(body)
                plan = self.application.operations.attach_verified_backup(
                    session_id=self._session_id(),
                    plan_id=self._required_string(body, "plan_id"),
                    backup_id=self._required_string(body, "backup_id"),
                )
                self._send_json(jsonable(plan))
                return
            if path == "/api/operations/execute":
                self._require_csrf(body)
                plan = self.application.operations.execute(
                    session_id=self._session_id(), plan_id=self._required_string(body, "plan_id")
                )
                self._send_json(jsonable(plan))
                return
            if path == "/api/backups/prepare":
                self._require_csrf(body)
                self._require_live_provider(
                    self.application.backups.provider,
                    "declared-filesystem-backup",
                    required_permission=Permission.CREATE_BACKUP,
                )
                backup = self.application.backups.prepare(
                    session_id=self._session_id(),
                    project=self._required_string(body, "project"),
                    backup_type=BackupType(self._required_string(body, "backup_type")),
                    source_label=self._required_string(body, "source_label"),
                    destination_label=self._required_string(body, "destination_label"),
                    retention=str(body.get("retention", "manual")),
                    server=self._optional_string(body, "server") or "local-lab",
                    environment=self._optional_string(body, "environment") or "laboratory",
                    path=self._optional_string(body, "path"),
                    size_bytes=self._optional_non_negative_integer(body, "size_bytes"),
                    retention_until=self._optional_string(body, "retention_until"),
                    related_operation=self._optional_string(body, "related_operation"),
                    related_deployment=self._optional_string(body, "related_deployment"),
                )
                self._send_json(jsonable(backup), status=HTTPStatus.CREATED)
                return
            if path == "/api/backups/verify":
                self._require_csrf(body)
                self._require_live_provider(
                    self.application.backups.provider,
                    "declared-filesystem-backup",
                    required_permission=Permission.CREATE_BACKUP,
                )
                backup = self.application.backups.verify(
                    session_id=self._session_id(), backup_id=self._required_string(body, "backup_id")
                )
                self._send_json(jsonable(backup))
                return
            if path == "/api/backups/restore-test":
                self._require_csrf(body)
                self._require_live_provider(
                    self.application.backups.provider,
                    "declared-filesystem-backup",
                    required_permission=Permission.CREATE_BACKUP,
                )
                backup = self.application.backups.restore_test(
                    session_id=self._session_id(), backup_id=self._required_string(body, "backup_id")
                )
                self._send_json(jsonable(backup))
                return
            if path == "/api/deployments/prepare":
                self._require_csrf(body)
                self._require_live_provider(
                    self.application.deployments.provider,
                    "declared-filesystem-release",
                    required_permission=Permission.DEPLOY,
                )
                checks = body.get("checks", {})
                if not isinstance(checks, dict):
                    raise ValueError("checks must be an object")
                deployment = self.application.deployments.prepare(
                    session_id=self._session_id(),
                    project=self._required_string(body, "project"),
                    commit=self._required_string(body, "commit"),
                    checks=checks,
                    backup_id=self._optional_string(body, "backup_id"),
                    branch=self._optional_string(body, "branch") or "main",
                    server=self._optional_string(body, "server") or "local-lab",
                    environment=self._optional_string(body, "environment") or "laboratory",
                    approval_id=self._optional_string(body, "approval_id"),
                    operation_id=self._optional_string(body, "operation_id"),
                    operation_hash=self._optional_string(body, "operation_hash"),
                )
                self._send_json(jsonable(deployment), status=HTTPStatus.CREATED)
                return
            if path == "/api/deployments/approve":
                self._require_csrf(body)
                self._require_live_provider(
                    self.application.deployments.provider,
                    "declared-filesystem-release",
                    required_permission=Permission.APPROVE_OPERATION,
                )
                deployment = self.application.deployments.approve(
                    session_id=self._session_id(),
                    deployment_id=self._required_string(body, "deployment_id"),
                )
                self._send_json(jsonable(deployment))
                return
            if path == "/api/deployments/execute":
                self._require_csrf(body)
                self._require_live_provider(
                    self.application.deployments.provider,
                    "declared-filesystem-release",
                    required_permission=Permission.DEPLOY,
                )
                deployment = self.application.deployments.execute(
                    session_id=self._session_id(),
                    deployment_id=self._required_string(body, "deployment_id"),
                )
                self._send_json(jsonable(deployment))
                return
            if path == "/api/rollbacks/prepare":
                self._require_csrf(body)
                self._require_live_provider(
                    self.application.rollbacks.provider,
                    "declared-filesystem-release",
                    required_permission=Permission.ROLLBACK,
                )
                rollback = self.application.rollbacks.prepare(
                    session_id=self._session_id(),
                    project=self._required_string(body, "project"),
                    rollback_type=self._required_string(body, "rollback_type"),
                    target=self._required_string(body, "target"),
                )
                self._send_json(jsonable(rollback), status=HTTPStatus.CREATED)
                return
            if path == "/api/rollbacks/approve":
                self._require_csrf(body)
                self._require_live_provider(
                    self.application.rollbacks.provider,
                    "declared-filesystem-release",
                    required_permission=Permission.APPROVE_OPERATION,
                )
                rollback = self.application.rollbacks.approve(
                    session_id=self._session_id(),
                    rollback_id=self._required_string(body, "rollback_id"),
                )
                self._send_json(jsonable(rollback))
                return
            if path == "/api/rollbacks/execute":
                self._require_csrf(body)
                self._require_live_provider(
                    self.application.rollbacks.provider,
                    "declared-filesystem-release",
                    required_permission=Permission.ROLLBACK,
                )
                rollback = self.application.rollbacks.execute(
                    session_id=self._session_id(),
                    rollback_id=self._required_string(body, "rollback_id"),
                )
                self._send_json(jsonable(rollback))
                return
            if path == "/api/incidents/create":
                self._require_csrf(body)
                incident = self.application.incidents.create(
                    session_id=self._session_id(),
                    project=self._required_string(body, "project"),
                    service=self._required_string(body, "service"),
                    severity=IncidentSeverity(self._required_string(body, "severity")),
                    symptom=self._required_string(body, "symptom"),
                    detected_by=str(body.get("detected_by", "operator")),
                    related_logs=self._string_list(body, "related_logs"),
                    related_metrics=self._string_list(body, "related_metrics"),
                    related_deployments=self._string_list(body, "related_deployments"),
                    related_changes=self._string_list(body, "related_changes"),
                    related_backups=self._string_list(body, "related_backups"),
                    related_conversations=self._string_list(body, "related_conversations"),
                    related_operations=self._string_list(body, "related_operations"),
                )
                self._send_json(jsonable(incident), status=HTTPStatus.CREATED)
                return
            if path == "/api/incidents/transition":
                self._require_csrf(body)
                incident = self.application.incidents.transition(
                    session_id=self._session_id(),
                    incident_id=self._required_string(body, "incident_id"),
                    status=IncidentStatus(self._required_string(body, "status")),
                    note=self._optional_string(body, "note"),
                    resolution=self._optional_string(body, "resolution"),
                    rollback=self._optional_string(body, "rollback"),
                )
                self._send_json(jsonable(incident))
                return
            if path.startswith("/api/incidents/") and path.endswith("/analyze"):
                self._require_csrf(body)
                evidence = body.get("evidence_labels", [])
                if not isinstance(evidence, list) or not all(isinstance(item, str) for item in evidence):
                    raise ValueError("evidence_labels must be a list of strings")
                incident = self.application.incidents.analyze(
                    session_id=self._session_id(),
                    incident_id=path.removeprefix("/api/incidents/").removesuffix("/analyze").strip("/"),
                    hypothesis=self._required_string(body, "hypothesis"),
                    evidence_labels=tuple(evidence),
                )
                self._send_json(jsonable(incident))
                return
            if path == "/api/validation/evaluate":
                self._require_csrf(body)
                checks = body.get("checks", {})
                if not isinstance(checks, dict):
                    raise ValueError("checks must be an object")
                report = self.application.validator.evaluate(
                    session_id=self._session_id(),
                    target=self._required_string(body, "target"),
                    checks=checks,
                )
                self._send_json(jsonable(report), status=HTTPStatus.CREATED)
                return
            if path == "/api/knowledge/register":
                self._require_csrf(body)
                services = body.get("services", [])
                if not isinstance(services, list) or not all(isinstance(item, str) for item in services):
                    raise ValueError("services must be a list of strings")
                record = self.application.knowledge.register(
                    session_id=self._session_id(),
                    project=self._required_string(body, "project"),
                    repository_label=self._required_string(body, "repository_label"),
                    branch_label=self._required_string(body, "branch_label"),
                    deployment_label=self._required_string(body, "deployment_label"),
                    services=tuple(services),
                    server=self._optional_string(body, "server") or "local-lab",
                    environment=self._optional_string(body, "environment") or "laboratory",
                    domains=self._string_list(body, "domains"),
                    databases=self._string_list(body, "databases"),
                    containers=self._string_list(body, "containers"),
                    ports=self._string_list(body, "ports"),
                    certificates=self._string_list(body, "certificates"),
                    dependencies=self._string_list(body, "dependencies"),
                    endpoints=self._string_list(body, "endpoints"),
                    health_checks=self._string_list(body, "health_checks"),
                    processes=self._string_list(body, "processes"),
                    related_backups=self._string_list(body, "related_backups"),
                    related_deployments=self._string_list(body, "related_deployments"),
                    related_incidents=self._string_list(body, "related_incidents"),
                    source=self._optional_string(body, "source") or "caller_metadata",
                    confidence=float(body.get("confidence", 0.5)),
                    last_verified=self._optional_string(body, "last_verified"),
                )
                self._send_json(jsonable(record), status=HTTPStatus.CREATED)
                return
            if path == "/api/impact/analyze":
                self._require_csrf(body)
                components = body.get("affected_components", [])
                if not isinstance(components, list) or not all(isinstance(item, str) for item in components):
                    raise ValueError("affected_components must be a list of strings")
                report = self.application.impact.analyze(
                    session_id=self._session_id(),
                    project=self._required_string(body, "project"),
                    action=self._required_string(body, "action"),
                    risk=self._required_string(body, "risk"),
                    affected_components=tuple(components),
                )
                self._send_json(jsonable(report), status=HTTPStatus.CREATED)
                return
            if path == "/api/drift/compare":
                self._require_csrf(body)
                desired = body.get("desired", {})
                observed = body.get("observed", {})
                if not isinstance(desired, dict) or not isinstance(observed, dict):
                    raise ValueError("desired and observed must be objects")
                report = self.application.drift.compare(
                    session_id=self._session_id(),
                    project=self._required_string(body, "project"),
                    desired=desired,
                    observed=observed,
                )
                self._send_json(jsonable(report), status=HTTPStatus.CREATED)
                return
            if path == "/api/agents/plan":
                self._require_csrf(body)
                task = self.application.agents.plan(
                    session_id=self._session_id(),
                    agent_id=self._required_string(body, "agent_id"),
                    task=self._required_string(body, "task"),
                )
                self._send_json(jsonable(task), status=HTTPStatus.CREATED)
                return
            if path == "/api/changes/propose":
                self._require_csrf(body)
                change = self.application.changes.propose(
                    session_id=self._session_id(),
                    project=self._required_string(body, "project"),
                    action=self._required_string(body, "action"),
                    risk=self._required_string(body, "risk"),
                )
                self._send_json(jsonable(change), status=HTTPStatus.CREATED)
                return
            if path == "/api/digital-twin/register":
                self._require_csrf(body)
                nodes = body.get("nodes", [])
                relations = body.get("relations", [])
                if (
                    not isinstance(nodes, list)
                    or not all(isinstance(item, dict) for item in nodes)
                    or not isinstance(relations, list)
                    or not all(isinstance(item, dict) for item in relations)
                ):
                    raise ValueError("nodes and relations must be lists of objects")
                record = self.application.v3.register_digital_twin(
                    session_id=self._session_id(),
                    project=self._required_string(body, "project"),
                    nodes=nodes,
                    relations=relations,
                )
                self._send_json(jsonable(record), status=HTTPStatus.CREATED)
                return
            if path == "/api/history/correlate":
                self._require_csrf(body)
                current_labels = body.get("current_labels", [])
                historical_events = body.get("historical_events", [])
                if (
                    not isinstance(current_labels, list)
                    or not all(isinstance(item, str) for item in current_labels)
                    or not isinstance(historical_events, list)
                    or not all(isinstance(item, dict) for item in historical_events)
                ):
                    raise ValueError("current_labels and historical_events are invalid")
                result = self.application.v3.correlate_history(
                    session_id=self._session_id(),
                    subject=self._required_string(body, "subject"),
                    current_labels=current_labels,
                    historical_events=historical_events,
                )
                self._send_json(jsonable(result), status=HTTPStatus.CREATED)
                return
            if path == "/api/predictive/analyze":
                self._require_csrf(body)
                raw_snapshots = body.get("snapshots", [])
                if not isinstance(raw_snapshots, list) or not all(isinstance(item, dict) for item in raw_snapshots):
                    raise ValueError("snapshots must be a list of objects")
                snapshots = tuple(self._metric_snapshot(item) for item in raw_snapshots)
                report = self.application.v3.analyze_predictive(
                    session_id=self._session_id(),
                    project=self._required_string(body, "project"),
                    snapshots=snapshots,
                    horizon_hours=self._integer(body, "horizon_hours"),
                )
                self._send_json(jsonable(report), status=HTTPStatus.CREATED)
                return
            if path == "/api/autonomy/profile":
                self._require_csrf(body)
                profile = self.application.v3.set_autonomy_profile(
                    session_id=self._session_id(),
                    project=self._required_string(body, "project"),
                    level=self._integer(body, "level"),
                )
                self._send_json(jsonable(profile), status=HTTPStatus.CREATED)
                return
            if path == "/api/servers/register":
                self._require_csrf(body)
                record = self.application.v3.register_server(
                    session_id=self._session_id(),
                    server_id=self._required_string(body, "server_id"),
                    label=self._required_string(body, "label"),
                    environment=self._required_string(body, "environment"),
                )
                self._send_json(jsonable(record), status=HTTPStatus.CREATED)
                return
            if path == "/api/recovery/plan":
                self._require_csrf(body)
                plan = self.application.v3.plan_recovery(
                    session_id=self._session_id(),
                    incident_id=self._required_string(body, "incident_id"),
                    project=self._required_string(body, "project"),
                    target=self._required_string(body, "target"),
                    strategy=self._required_string(body, "strategy"),
                    backup_id=self._optional_string(body, "backup_id"),
                )
                self._send_json(jsonable(plan), status=HTTPStatus.CREATED)
                return
            self._send_json({"error": "read_only_or_not_found"}, status=HTTPStatus.METHOD_NOT_ALLOWED)
        except Exception as exc:
            self._send_exception(exc)

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def _login(self, body: dict[str, Any]) -> None:
        username = self._required_string(body, "username")
        password = self._required_string(body, "password")
        otp = self._optional_string(body, "otp")
        session = self.application.auth.login(username=username, password=password, otp=otp)
        user = self.application.auth.user_for_session(session.session_id)
        self._send_json(
            self._user_payload(user, session),
            headers={
                "Set-Cookie": self.application.auth.cookie_header(
                    session,
                    secure=bool(getattr(self.server, "secure_cookies", False)),
                )
            },
        )

    def _expired_cookie(self) -> str:
        suffix = "; Secure" if bool(getattr(self.server, "secure_cookies", False)) else ""
        return f"cc_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{suffix}"

    def _authenticated_session(self):
        session_id = self._session_id()
        session = self.application.auth.session_for(session_id)
        user = self.application.auth.user_for_session(session_id)
        return user, session

    def _user_payload(self, user: Any, session: Any) -> dict[str, Any]:
        return {
            "authenticated": True,
            "user": {
                "id": user.user_id,
                "username": user.username,
                "role": user.role.value,
                "permissions": sorted(permission.value for permission in user.permissions),
            },
            "csrfToken": session.csrf_token,
            "sessionExpiresAt": session.expires_at,
        }

    def _require(self, permission: Permission) -> Any:
        return self.application.auth.require(self._session_id(), permission)

    def _require_live_provider(
        self,
        provider: Any | None,
        provider_id: str | None = None,
        *,
        required_permission: Permission | None = None,
    ) -> None:
        """Require an active, explicitly scoped manifest for live providers."""

        if provider is None or getattr(provider, "live_data", False) is not True:
            return
        manifest = self._runtime_activation_manifest()
        if manifest is None or not manifest.is_active():
            raise AuthorizationError("live provider requires an active activation manifest")
        actual_id = getattr(provider, "name", None)
        if not isinstance(actual_id, str) or not actual_id.strip():
            raise AuthorizationError("live provider has no stable identity")
        if provider_id is not None and actual_id != provider_id:
            raise AuthorizationError("live provider identity does not match its route")
        if actual_id not in set(manifest.provider_ids):
            raise AuthorizationError("live provider is outside activation scope")
        if required_permission is not None and required_permission.value not in set(manifest.effective_permissions):
            raise AuthorizationError("activation manifest does not authorize this permission")

    def _runtime_activation_manifest(self) -> ActivationManifest | None:
        """Reload a configured manifest so removal or replacement fails closed."""

        manifest_path = getattr(self.server, "activation_manifest_path", None)
        if manifest_path is None:
            return self.server.activation_manifest  # type: ignore[attr-defined]
        try:
            return load_activation_manifest(manifest_path)
        except ActivationManifestError:
            return None

    def _require_csrf(self, body: dict[str, Any]) -> Any:
        session_id = self._session_id()
        return self.application.auth.require_csrf(session_id, self._csrf_token(body))

    def _session_id(self) -> str:
        cookies = self.headers.get("Cookie", "")
        for item in cookies.split(";"):
            name, separator, value = item.strip().partition("=")
            if separator and name == "cc_session" and value:
                return value
        raise AuthenticationError("authentication required")

    def _csrf_token(self, body: Mapping[str, Any]) -> str | None:
        header = self.headers.get("X-CSRF-Token")
        if header:
            return header
        token = body.get("csrfToken")
        return token if isinstance(token, str) else None

    def _read_json_body(self) -> dict[str, Any]:
        length_text = self.headers.get("Content-Length", "0")
        try:
            length = int(length_text)
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError("request body is too large")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("request body must be JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("request body must be an object")
        return payload

    @staticmethod
    def _required_string(body: Mapping[str, Any], key: str) -> str:
        value = body.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} is required")
        return value.strip()

    @staticmethod
    def _optional_string(body: Mapping[str, Any], key: str) -> str | None:
        value = body.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError(f"{key} must be a string")
        return value.strip() or None

    @staticmethod
    def _string_list(body: Mapping[str, Any], key: str) -> tuple[str, ...]:
        value = body.get(key, [])
        if not isinstance(value, list) or len(value) > 128 or any(not isinstance(item, str) or not item.strip() for item in value):
            raise ValueError(f"{key} must be a bounded list of strings")
        return tuple(item.strip() for item in value)

    @staticmethod
    def _number(body: Mapping[str, Any], key: str, *, default: float | None = None) -> float:
        value = body.get(key, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
            raise ValueError(f"{key} must be a finite number")
        number = float(value)
        if number < 0:
            raise ValueError(f"{key} cannot be negative")
        if key in {"cpu_percent", "memory_percent", "disk_percent"} and number > 100:
            raise ValueError(f"{key} must be between 0 and 100")
        if key == "http_error_rate" and number > 1:
            raise ValueError("http_error_rate must be between 0 and 1")
        return number

    @staticmethod
    def _integer(body: Mapping[str, Any], key: str, *, default: int | None = None) -> int:
        value = body.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{key} must be a non-negative integer")
        return value

    @staticmethod
    def _optional_non_negative_integer(body: Mapping[str, Any], key: str) -> int | None:
        value = body.get(key)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{key} must be a non-negative integer")
        return value

    @classmethod
    def _metric_snapshot(cls, body: Mapping[str, Any]) -> MetricSnapshot:
        timestamp = cls._required_string(body, "timestamp")
        return MetricSnapshot(
            timestamp=timestamp,
            cpu_percent=cls._number(body, "cpu_percent"),
            memory_percent=cls._number(body, "memory_percent"),
            disk_percent=cls._number(body, "disk_percent"),
            load_1m=cls._number(body, "load_1m"),
            http_error_rate=cls._number(body, "http_error_rate", default=0.0),
            service_restarts=cls._integer(body, "service_restarts", default=0),
            http_latency_ms=cls._number(body, "http_latency_ms", default=0.0),
            http_requests_per_minute=cls._integer(body, "http_requests_per_minute", default=0),
            process_count=cls._integer(body, "process_count", default=0),
            container_count=cls._integer(body, "container_count", default=0),
            deployment_ids=cls._string_list(body, "deployment_ids"),
            incident_ids=cls._string_list(body, "incident_ids"),
        )

    def _method_not_allowed(self) -> None:
        self._send_json({"error": "read_only"}, status=HTTPStatus.METHOD_NOT_ALLOWED)

    def _send_exception(self, exc: Exception) -> None:
        if isinstance(exc, (AuthenticationError, RateLimitError)):
            self._send_json({"error": "authentication_required"}, status=HTTPStatus.UNAUTHORIZED)
        elif isinstance(exc, (AuthorizationError, CSRFError, PermissionError)):
            self._send_json({"error": "not_authorized"}, status=HTTPStatus.FORBIDDEN)
        elif isinstance(exc, (ValueError, KeyError)):
            self._send_json({"error": "invalid_request"}, status=HTTPStatus.BAD_REQUEST)
        else:
            self._send_json({"error": "request_failed"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _send_json(
        self,
        payload: Any,
        *,
        status: HTTPStatus = HTTPStatus.OK,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        body = json.dumps(jsonable(payload), ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        # Do not write request data to a persistent or operational log.
        return


def create_server(
    host: str = "127.0.0.1",
    port: int = 8766,
    *,
    application: ControlCenterApplication | None = None,
    secure_cookies: bool = False,
    activation_manifest: ActivationManifest | None = None,
    activation_manifest_path: str | Path | None = None,
    https_terminated: bool = False,
) -> ControlCenterHTTPServer:
    """Create, but do not start, the local server."""

    return ControlCenterHTTPServer(
        (host, port),
        ReadOnlyHandler,
        application or ControlCenterApplication(),
        secure_cookies=secure_cookies,
        activation_manifest=activation_manifest,
        activation_manifest_path=activation_manifest_path,
        https_terminated=https_terminated,
    )


def _unsafe_request_text(value: str) -> bool:
    return contains_secret(value) or RAW_STREAM_PATTERN.search(value) is not None or len(value) > 256


def validate_state_root(path: Path) -> Path:
    """Validate an explicit external root for metadata-only workflow state."""

    if not path.is_absolute() or path.is_symlink() or not path.exists() or not path.is_dir():
        raise ValueError("state root must be an existing absolute directory")
    resolved = path.resolve()
    project = PROJECT_ROOT.resolve()
    if resolved == project or project in resolved.parents:
        raise ValueError("state root must be outside the project directory")
    if ".git" in resolved.parts or any(part.startswith(".env") for part in resolved.parts):
        raise ValueError("state root cannot be inside protected paths")
    if any(part.casefold() in {"logs", "backups"} for part in resolved.parts):
        raise ValueError("state root cannot be inside logs or backups")
    return resolved


def validate_activation_scope(
    activation_manifest: ActivationManifest | None,
    provider_ids: tuple[str, ...],
) -> None:
    """Require explicit, active authorization for every non-lab provider."""

    if not provider_ids:
        return
    if activation_manifest is None or not activation_manifest.is_active():
        raise ValueError("live providers require an active activation manifest")
    declared = set(activation_manifest.provider_ids)
    missing = sorted(set(provider_ids) - declared)
    if missing:
        raise ValueError("activation manifest does not declare all requested providers")


def prepare_lab_environment(root: Path) -> dict[str, Path]:
    """Create an isolated, explicit filesystem profile for local testing.

    The profile is deliberately outside the repository and contains only
    harmless fixture data. It is never used unless ``--lab-mode`` is passed.
    No production path, service, log, database, secret or existing backup is
    discovered or read.
    """

    lab_root = _validate_lab_root(root)
    _ensure_lab_directory(lab_root)
    paths = {
        "root": lab_root,
        "state_root": lab_root / "state",
        "backup_source_root": lab_root / "backup-source",
        "backup_destination_root": lab_root / "backups",
        "release_artifact_root": lab_root / "artifacts",
        "release_root": lab_root / "releases",
    }
    for path in paths.values():
        if path != lab_root:
            _ensure_lab_directory(path)

    _ensure_lab_file(
        paths["backup_source_root"] / "README.txt",
        "Fixture de laboratorio; no contiene datos operativos.\n",
    )
    _ensure_lab_file(
        paths["release_artifact_root"] / "lab-commit" / "README.txt",
        "Release fixture de laboratorio; no inicia servicios.\n",
    )
    return paths


def _validate_lab_root(root: Path) -> Path:
    if not isinstance(root, Path) or not root.is_absolute():
        raise ValueError("lab root must be an absolute path")
    if root.exists() and root.is_symlink():
        raise ValueError("lab root cannot be a symlink")
    resolved = root.resolve(strict=False)
    if resolved == PROJECT_ROOT or PROJECT_ROOT in resolved.parents or resolved in PROJECT_ROOT.parents:
        raise ValueError("lab root must be unrelated to the project directory")
    return resolved


def _ensure_lab_directory(path: Path) -> None:
    if path.exists() and (path.is_symlink() or not path.is_dir()):
        raise ValueError("lab path must be a non-symlink directory")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)


def _ensure_lab_file(path: Path, content: str) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise ValueError("lab fixture must be a regular file")
        return
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


def main() -> None:
    parser = argparse.ArgumentParser(description="Cibermedida local Control Center")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument(
        "--secure-cookies",
        action="store_true",
        help="Marca la cookie de sesión como Secure; usar solo detrás de HTTPS",
    )
    parser.add_argument(
        "--https-terminated",
        action="store_true",
        help="Declara que un proxy externo revisado termina HTTPS; no configura TLS por sí mismo",
    )
    parser.add_argument(
        "--activation-manifest",
        type=Path,
        help="JSON metadata-only de autorización humana; solo alimenta readiness y nunca activa providers",
    )
    parser.add_argument("--bootstrap-username")
    parser.add_argument("--bootstrap-role", choices=[role.value for role in Role], default=Role.ADMIN.value)
    parser.add_argument(
        "--bootstrap-user",
        action="append",
        default=[],
        metavar="USUARIO[:ROL]",
        help="Usuario adicional a provisionar; puede repetirse y nunca incluye la contraseña",
    )
    parser.add_argument(
        "--bootstrap-2fa-user",
        action="append",
        default=[],
        metavar="USUARIO[:ROL]",
        help="Usuario adicional con TOTP; solicita contraseña y semilla sin mostrar ni persistir la semilla",
    )
    parser.add_argument("--auth-state", type=Path, help="Ruta JSON explícita para identidades con hashes")
    parser.add_argument("--audit-path", type=Path, help="Ruta JSONL explícita para auditoría metadata-only")
    parser.add_argument(
        "--audit-max-bytes",
        type=int,
        default=16 * 1024 * 1024,
        help="Límite por segmento de auditoría JSONL antes de rotar",
    )
    parser.add_argument(
        "--audit-retention-files",
        type=int,
        default=3,
        help="Número de segmentos JSONL rotados que se conservan además del actual",
    )
    parser.add_argument("--approval-state", type=Path, help="Ruta JSON explícita para aprobaciones metadata-only")
    parser.add_argument(
        "--state-root",
        type=Path,
        help="Directorio absoluto externo para estados JSON metadata-only de identidad y workflows",
    )
    parser.add_argument(
        "--backup-source-root",
        type=Path,
        help="Raíz absoluta declarada para backups de archivos UTF-8; requiere destino explícito",
    )
    parser.add_argument(
        "--backup-destination-root",
        type=Path,
        help="Raíz absoluta separada para archivos .tar.gz; requiere origen explícito",
    )
    parser.add_argument(
        "--release-artifact-root",
        type=Path,
        help="Raíz absoluta de artefactos versionados para releases declaradas",
    )
    parser.add_argument(
        "--release-root",
        type=Path,
        help="Raíz absoluta separada para releases declaradas y puntero CURRENT",
    )
    parser.add_argument(
        "--chat-endpoint",
        help="Endpoint HTTPS compatible con chat completions; requiere prompt de clave",
    )
    parser.add_argument(
        "--chat-model",
        default="control-center-planner",
        help="Nombre de modelo enviado al proveedor de chat",
    )
    parser.add_argument(
        "--chat-api-key-prompt",
        action="store_true",
        help="Solicita la clave de chat por terminal sin mostrarla",
    )
    parser.add_argument(
        "--read-safe-monitoring",
        action="store_true",
        help="Habilita colección explícita de métricas READ_SAFE, sin logs ni servicios",
    )
    parser.add_argument(
        "--read-safe-execution",
        action="store_true",
        help="Habilita únicamente ejecución aprobada de comandos READ_SAFE",
    )
    parser.add_argument(
        "--read-safe-inventory",
        action="store_true",
        help="Habilita colección explícita READ_SAFE de inventario sin persistir INVENTORY.json",
    )
    parser.add_argument(
        "--read-safe-projects",
        action="store_true",
        help="Habilita colección explícita READ_SAFE de rama, estado y HEAD Git",
    )
    parser.add_argument(
        "--run-repository-tests",
        action="store_true",
        help="Habilita la ejecución acotada del conjunto unittest del repositorio",
    )
    parser.add_argument(
        "--build-root",
        type=Path,
        help="Raíz absoluta declarada para perfiles de build; requiere --build-profile",
    )
    parser.add_argument(
        "--build-profile",
        action="append",
        default=[],
        metavar="TARGET=EXECUTABLE [ARG ...]",
        help="Perfil argv de build declarado al arrancar; puede repetirse",
    )
    parser.add_argument(
        "--codex-project",
        action="append",
        default=[],
        metavar="NOMBRE=/RUTA",
        help="Proyecto Codex read-only declarado al arrancar; puede repetirse",
    )
    parser.add_argument(
        "--codex-executable",
        default="codex",
        help="Nombre del ejecutable Codex; no acepta rutas ni argumentos",
    )
    parser.add_argument(
        "--inventory-state",
        type=Path,
        help="Ruta JSON explícita para el último inventario validado; nunca usa INVENTORY.json",
    )
    parser.add_argument(
        "--lab-mode",
        action="store_true",
        help="Activa un perfil aislado de laboratorio; requiere --lab-root y un usuario de bootstrap",
    )
    parser.add_argument(
        "--lab-root",
        type=Path,
        help="Raíz absoluta externa al proyecto para el perfil --lab-mode",
    )
    args = parser.parse_args()

    try:
        bootstrap_users: list[tuple[str, Role]] = []
        if args.bootstrap_username:
            bootstrap_users.append((args.bootstrap_username, Role(args.bootstrap_role)))
        bootstrap_users.extend(parse_bootstrap_user(value) for value in args.bootstrap_user)
        bootstrap_2fa_users = [parse_bootstrap_user(value) for value in args.bootstrap_2fa_user]
        all_bootstrap_users = bootstrap_users + bootstrap_2fa_users
        if len({username for username, _role in all_bootstrap_users}) != len(all_bootstrap_users):
            parser.error("los usuarios de bootstrap no pueden repetirse")
    except ValueError as exc:
        parser.error(str(exc))

    try:
        build_profiles = dict(parse_build_profile(value) for value in args.build_profile)
        codex_projects = dict(parse_codex_project(value) for value in args.codex_project)
        if len(build_profiles) != len(args.build_profile) or len(codex_projects) != len(args.codex_project):
            raise ValueError("build profiles and Codex projects cannot repeat names")
    except ValueError as exc:
        parser.error(str(exc))

    if bool(args.build_root) != bool(build_profiles):
        parser.error("--build-root y --build-profile deben indicarse juntos")
    if (
        not isinstance(args.codex_executable, str)
        or not args.codex_executable.strip()
        or "/" in args.codex_executable
        or "\\" in args.codex_executable
        or args.codex_executable != args.codex_executable.strip()
    ):
        parser.error("--codex-executable es inválido")
    if args.codex_executable != "codex" and not args.codex_project:
        parser.error("--codex-executable requiere al menos un --codex-project")

    if args.lab_mode and (
        args.lab_root is None
        or not (args.bootstrap_username or args.bootstrap_user or args.bootstrap_2fa_user)
    ):
        parser.error("--lab-mode requiere --lab-root y al menos un usuario de bootstrap")
    if args.lab_root is not None and not args.lab_mode:
        parser.error("--lab-root solo se puede usar con --lab-mode")
    if args.lab_mode and (
        any(
            value is not None
            for value in (
                args.auth_state,
                args.audit_path,
                args.approval_state,
                args.backup_source_root,
                args.backup_destination_root,
                args.release_artifact_root,
                args.release_root,
                args.inventory_state,
                args.activation_manifest,
                args.state_root,
                args.build_root,
            )
        )
        or args.https_terminated
        or args.build_profile
        or args.codex_project
        or args.codex_executable != "codex"
    ):
        parser.error("--lab-mode crea sus propias rutas aisladas; no se combina con rutas explícitas")

    try:
        lab_paths = prepare_lab_environment(args.lab_root) if args.lab_mode else None
    except ValueError as exc:
        parser.error(str(exc))
    try:
        state_root = validate_state_root(args.state_root) if args.state_root is not None else None
    except ValueError as exc:
        parser.error(str(exc))
    try:
        activation_manifest = (
            load_activation_manifest(args.activation_manifest)
            if args.activation_manifest is not None
            else None
        )
    except ActivationManifestError as exc:
        parser.error(f"manifiesto de activación inválido: {exc}")
    requested_provider_ids: list[str] = []
    if args.read_safe_monitoring:
        requested_provider_ids.append("phase1-read-safe-monitoring")
    if args.read_safe_execution:
        requested_provider_ids.append("phase1-read-safe-execution")
    if args.read_safe_inventory:
        requested_provider_ids.append("phase1-read-safe-inventory")
    if args.read_safe_projects:
        requested_provider_ids.append("phase1-read-safe-projects")
    if args.run_repository_tests:
        requested_provider_ids.append("repository-tests")
    if args.build_root or args.build_profile:
        requested_provider_ids.append("declared-build")
    if args.codex_project:
        requested_provider_ids.append("codex-provider")
    if args.chat_endpoint:
        requested_provider_ids.append("openai-compatible-chat")
    if args.backup_source_root and args.backup_destination_root:
        requested_provider_ids.append("declared-filesystem-backup")
    if args.release_artifact_root and args.release_root:
        requested_provider_ids.append("declared-filesystem-release")
    if not args.lab_mode:
        try:
            validate_activation_scope(activation_manifest, tuple(requested_provider_ids))
        except ValueError as exc:
            parser.error(str(exc))
    args_auth_state = args.auth_state
    args_audit_path = args.audit_path
    args_approval_state = args.approval_state
    backup_source_root = args.backup_source_root
    backup_destination_root = args.backup_destination_root
    release_artifact_root = args.release_artifact_root
    release_root = args.release_root
    if lab_paths is not None:
        args_auth_state = lab_paths["state_root"] / "users.json"
        args_audit_path = lab_paths["state_root"] / "audit.jsonl"
        args_approval_state = lab_paths["state_root"] / "approvals.json"
        backup_source_root = lab_paths["backup_source_root"]
        backup_destination_root = lab_paths["backup_destination_root"]
        release_artifact_root = lab_paths["release_artifact_root"]
        release_root = lab_paths["release_root"]

    if state_root is not None:
        args_auth_state = args_auth_state or state_root / "users.json"
        args_audit_path = args_audit_path or state_root / "audit.jsonl"
        args_approval_state = args_approval_state or state_root / "approvals.json"

    auth_state = args_auth_state if lab_paths is not None else args.auth_state
    audit_path = args_audit_path if lab_paths is not None else args.audit_path
    approval_state = args_approval_state if lab_paths is not None else args.approval_state
    user_store = JsonUserStore(auth_state) if auth_state else None
    audit_sink = (
        JsonlAuditSink(
            audit_path,
            max_bytes=args.audit_max_bytes,
            retention_files=args.audit_retention_files,
        )
        if audit_path
        else None
    )
    approval_store = JsonApprovalStore(approval_state) if approval_state else None
    workflow_state_root = lab_paths["state_root"] if lab_paths is not None else state_root
    backup_state_store = (
        JsonMetadataStore(workflow_state_root / "backups-workflow.json")
        if workflow_state_root is not None
        else None
    )
    deployment_state_store = (
        JsonMetadataStore(workflow_state_root / "deployments-workflow.json")
        if workflow_state_root is not None
        else None
    )
    rollback_state_store = (
        JsonMetadataStore(workflow_state_root / "rollbacks-workflow.json")
        if workflow_state_root is not None
        else None
    )
    monitoring_state_store = (
        JsonMetadataStore(workflow_state_root / "monitoring.json")
        if workflow_state_root is not None
        else None
    )
    operation_state_store = (
        JsonMetadataStore(workflow_state_root / "operations-workflow.json")
        if workflow_state_root is not None
        else None
    )
    conversation_state_store = (
        JsonMetadataStore(workflow_state_root / "conversation.json")
        if workflow_state_root is not None
        else None
    )
    inventory_state_store = (
        JsonMetadataStore(workflow_state_root / "inventory-workflow.json")
        if workflow_state_root is not None
        else (JsonMetadataStore(args.inventory_state) if args.inventory_state else None)
    )
    projects_state_store = (
        JsonMetadataStore(workflow_state_root / "projects.json")
        if workflow_state_root is not None
        else None
    )
    tests_state_store = (
        JsonMetadataStore(workflow_state_root / "tests.json")
        if workflow_state_root is not None
        else None
    )
    builds_state_store = (
        JsonMetadataStore(workflow_state_root / "builds.json")
        if workflow_state_root is not None
        else None
    )
    codex_state_store = (
        JsonMetadataStore(workflow_state_root / "codex.json")
        if workflow_state_root is not None
        else None
    )
    execution_state_store = (
        JsonMetadataStore(workflow_state_root / "execution-workflow.json")
        if workflow_state_root is not None
        else None
    )
    incident_state_store = (
        JsonMetadataStore(workflow_state_root / "incidents.json")
        if workflow_state_root is not None
        else None
    )
    v3_state_store = (
        JsonMetadataStore(workflow_state_root / "v3-insights.json")
        if workflow_state_root is not None
        else None
    )
    validation_state_store = (
        JsonMetadataStore(workflow_state_root / "validation.json")
        if workflow_state_root is not None
        else None
    )
    totp_verifier = TotpVerifier({}) if bootstrap_2fa_users else None
    monitoring_provider = (
        SyntheticReadSafeMonitoringProvider()
        if args.lab_mode
        else ReadSafeMonitoringProvider()
        if args.read_safe_monitoring
        else None
    )
    execution_provider = (
        SyntheticReadSafeExecutionProvider()
        if args.lab_mode
        else ReadSafeExecutionProvider()
        if args.read_safe_execution
        else None
    )
    inventory_provider = None
    if args.read_safe_inventory:
        inventory_provider = ReadSafeInventoryProvider(PROJECT_ROOT / "schemas" / "inventory.schema.json")
    elif args.lab_mode:
        inventory_provider = SyntheticInventoryProvider(PROJECT_ROOT / "schemas" / "inventory.schema.json")
    project_provider = None
    if args.read_safe_projects:
        project_provider = ReadSafeProjectProvider(executor=RestrictedExecutor())
    elif args.lab_mode:
        project_provider = SyntheticProjectProvider()
    test_provider = None
    if args.run_repository_tests and not args.lab_mode:
        test_provider = InProcessTestProvider(
            project_root=PROJECT_ROOT,
            tests_root=PROJECT_ROOT / "tests",
        )
    elif args.lab_mode:
        test_provider = SyntheticTestProvider()
    build_provider = None
    if args.lab_mode:
        build_provider = SyntheticBuildProvider()
    elif args.build_root and build_profiles:
        build_provider = DeclaredCommandBuildProvider(
            project_root=args.build_root,
            commands=build_profiles,
        )
    codex_provider = None
    if args.lab_mode:
        codex_provider = SyntheticCodexProvider()
    elif codex_projects:
        codex_provider = CodexCliProvider(
            projects=codex_projects,
            executable=args.codex_executable,
        )
    if bool(backup_source_root) != bool(backup_destination_root):
        parser.error("--backup-source-root y --backup-destination-root deben indicarse juntos")
    if bool(release_artifact_root) != bool(release_root):
        parser.error("--release-artifact-root y --release-root deben indicarse juntos")
    if bool(args.chat_endpoint) != args.chat_api_key_prompt:
        parser.error("--chat-endpoint y --chat-api-key-prompt deben indicarse juntos")
    backup_provider = (
        FilesystemBackupProvider(
            source_root=backup_source_root,
            destination_root=backup_destination_root,
            live_data=not args.lab_mode,
        )
        if backup_source_root and backup_destination_root
        else None
    )
    release_provider = (
        FilesystemReleaseProvider(
            artifact_root=release_artifact_root,
            release_root=release_root,
            live_data=not args.lab_mode,
        )
        if release_artifact_root and release_root
        else None
    )
    chat_provider = None
    if args.chat_endpoint:
        chat_provider = OpenAICompatibleChatProvider(
            endpoint=args.chat_endpoint,
            api_key=getpass("Clave API del proveedor de chat (no se mostrará): "),
            model=args.chat_model,
        )
    application = ControlCenterApplication(
        user_store=user_store,
        otp_verifier=totp_verifier,
        audit_sink=audit_sink,
        approval_store=approval_store,
        operation_state_store=operation_state_store,
        monitoring_provider=monitoring_provider,
        execution_provider=execution_provider,
        execution_state_store=execution_state_store,
        inventory_provider=inventory_provider,
        inventory_enabled=inventory_provider is not None,
        inventory_schema_path=PROJECT_ROOT / "schemas" / "inventory.schema.json",
        inventory_state_store=inventory_state_store,
        project_provider=project_provider,
        projects_enabled=project_provider is not None,
        projects_state_store=projects_state_store,
        test_provider=test_provider,
        tests_enabled=test_provider is not None,
        tests_state_store=tests_state_store,
        build_provider=build_provider,
        builds_enabled=build_provider is not None,
        builds_state_store=builds_state_store,
        codex_provider=codex_provider,
        codex_enabled=codex_provider is not None,
        codex_state_store=codex_state_store,
        backup_provider=backup_provider,
        backup_state_store=backup_state_store,
        deployment_provider=release_provider,
        deployment_validator=release_provider,
        deployment_state_store=deployment_state_store,
        rollback_provider=release_provider,
        rollback_state_store=rollback_state_store,
        chat_provider=chat_provider,
        chat_enabled=chat_provider is not None,
        conversation_state_store=conversation_state_store,
        monitoring_state_store=monitoring_state_store,
        incident_state_store=incident_state_store,
        validation_state_store=validation_state_store,
        v3_state_store=v3_state_store,
        providers_enabled=any(
            provider is not None
            for provider in (
                monitoring_provider,
                execution_provider,
                backup_provider,
                release_provider,
                chat_provider,
                project_provider,
                test_provider,
                build_provider,
                codex_provider,
            )
        ),
    )
    for username, role in bootstrap_users:
        if application.auth.has_username(username):
            print(f"Usuario {username!r} ya provisionado; se conserva su identidad existente.")
        else:
            password = getpass(f"Contraseña para {username} (no se mostrará): ")
            application.register_user(
                user_id=f"bootstrap-{uuid4()}",
                username=username,
                password=password,
                role=role,
            )
            storage_mode = "almacenado en la ruta opt-in" if user_store is not None else "solo en memoria para este proceso"
            print(f"Usuario {username!r} provisionado: {storage_mode}.")
    for username, role in bootstrap_2fa_users:
        existing_user = application.auth.user_for_username(username)
        if existing_user is not None and not existing_user.requires_2fa:
            parser.error(
                f"el usuario {username!r} ya existe sin 2FA; no se cambia su requisito durante el arranque"
            )
        user_id = existing_user.user_id if existing_user is not None else f"bootstrap-{uuid4()}"
        password = None
        if existing_user is None:
            password = getpass(f"Contraseña para {username} (no se mostrará): ")
        seed = getpass(f"Semilla TOTP para {username} (no se mostrará ni se guardará): ")
        try:
            # Validate before creating a new persistent identity, then retain
            # only the decoded seed in the verifier's process memory.
            TotpVerifier({user_id: seed})
            if totp_verifier is None:
                parser.error("la provisión 2FA no está inicializada")
            if existing_user is None:
                application.register_user(
                    user_id=user_id,
                    username=username,
                    password=password or "",
                    role=role,
                    requires_2fa=True,
                )
            totp_verifier.register_secret(user_id, seed)
        except ValueError as exc:
            parser.error(f"semilla TOTP inválida para {username!r}: {exc}")
        storage_mode = "almacenado en la ruta opt-in" if user_store is not None else "solo en memoria para este proceso"
        if existing_user is None:
            print(f"Usuario 2FA {username!r} provisionado: {storage_mode}.")
        else:
            print(f"Usuario 2FA {username!r} reactivado para esta sesión: la semilla permanece en memoria.")
    server = create_server(
        args.host,
        args.port,
        application=application,
        secure_cookies=args.secure_cookies,
        activation_manifest=activation_manifest,
        activation_manifest_path=args.activation_manifest,
        https_terminated=args.https_terminated,
    )
    print(f"Control Center local: http://{args.host}:{args.port}/")
    if monitoring_provider is not None:
        if args.lab_mode:
            print("Monitorización READ_SAFE sintética habilitada: sin consulta al host ni logs.")
        else:
            print("Monitorización READ_SAFE habilitada: solo memoria, disco y carga; sin logs ni cambios.")
    if execution_provider is not None:
        if args.lab_mode:
            print("Ejecución READ_SAFE sintética habilitada: no invoca el executor.")
        else:
            print("Ejecución READ_SAFE habilitada: requiere aprobación independiente y no admite modificaciones.")
    if inventory_provider is not None:
        if args.lab_mode:
            print("Inventario READ_SAFE sintético habilitado: no ejecuta comandos ni crea INVENTORY.json.")
        else:
            print(
                "Inventario READ_SAFE habilitado: resultado validado; estado opt-in seguro; no se crea INVENTORY.json."
            )
    if project_provider is not None:
        if args.lab_mode:
            print("Proyectos/Git READ_SAFE sintéticos habilitados: no consulta el host ni muta repositorios.")
        else:
            print("Proyectos/Git READ_SAFE habilitados: solo rama, estado y HEAD; sin push, merge ni stdout crudo.")
    if test_provider is not None:
        if args.lab_mode:
            print("Testing sintético habilitado: no ejecuta el conjunto real del repositorio.")
        else:
            print("Testing del repositorio habilitado: solo target repository y sin exponer salida de tests.")
    if build_provider is not None:
        print(
            "Build sintético habilitado: no ejecuta comandos."
            if args.lab_mode
            else "Build declarado habilitado: solo perfiles argv configurados y sin exponer salida."
        )
    if codex_provider is not None:
        print(
            "Codex sintético habilitado: análisis metadata-only; no lanza CLI ni modifica repositorios."
            if args.lab_mode
            else "Codex CLI read-only habilitado: sandbox de solo lectura y resultados metadata-only."
        )
    if backup_provider is not None:
        print("Backup de filesystem habilitado: solo raíces declaradas y archivos UTF-8 acotados.")
    if release_provider is not None:
        print(
            "Releases de laboratorio habilitados: solo artefactos declarados y puntero CURRENT."
            if args.lab_mode
            else "Releases declaradas habilitadas: solo artefactos declarados y puntero CURRENT."
        )
    if lab_paths is not None:
        print(f"Perfil de laboratorio {LAB_PROFILE_NAME}: {lab_paths['root']}")
        print("No se conectan servicios, logs, bases de datos ni rutas de producción.")
    if chat_provider is not None:
        print("Chat IA habilitado: las respuestas se validan como planes no ejecutables.")
    else:
        print("Sin adapter de chat externo: se mantiene el planificador local y metadata-only.")
    if activation_manifest is not None:
        print(
            "Manifiesto de activación cargado para readiness y gate por petición; "
            "no selecciona providers ni concede permisos."
        )
    if state_root is not None:
        print(f"Estado metadata-only persistente: {state_root}")
    if args.https_terminated:
        print("HTTPS externo declarado para readiness; TLS no se configura desde este proceso.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
