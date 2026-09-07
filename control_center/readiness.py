"""Production-readiness checks with no operational side effects.

The report is deliberately conservative. It describes whether the application
graph has the required boundaries and persistence to be reviewed for
production; it never enables a provider, reads the host, or changes services.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING

from core_operator.approvals import JsonApprovalStore

from .activation import ActivationManifest

if TYPE_CHECKING:
    from .application import ControlCenterApplication


class ReadinessState(str, Enum):
    GO = "GO"
    NO_GO = "NO_GO"


@dataclass(frozen=True)
class ReadinessCheck:
    check_id: str
    label: str
    passed: bool
    evidence: str


@dataclass(frozen=True)
class ProductionReadinessReport:
    state: ReadinessState
    checks: tuple[ReadinessCheck, ...]
    generated_at: str

    @property
    def blocking_checks(self) -> tuple[ReadinessCheck, ...]:
        return tuple(check for check in self.checks if not check.passed)

    def as_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "ready": self.state is ReadinessState.GO,
            "generated_at": self.generated_at,
            "blocking_checks": [check.check_id for check in self.blocking_checks],
            "checks": [
                {
                    "check_id": check.check_id,
                    "label": check.label,
                    "passed": check.passed,
                    "evidence": check.evidence,
                }
                for check in self.checks
            ],
        }


def evaluate_production_readiness(
    application: "ControlCenterApplication",
    *,
    secure_cookies: bool,
    https_terminated: bool = False,
    activation_manifest: ActivationManifest | None = None,
) -> ProductionReadinessReport:
    """Evaluate the documented production prerequisites without enabling them."""

    auth = application.auth
    users = auth.users
    identity_persistent = auth.user_store is not None and bool(users)
    two_factor = bool(users) and auth.otp_verifier is not None and all(user.requires_2fa for user in users)
    approval_persistent = isinstance(application.approvals, JsonApprovalStore)
    state_stores = (
        application.operations.state_store,
        application.backups.state_store,
        application.deployments.state_store,
        application.rollbacks.state_store,
        application.monitoring.state_store,
        application.execution.state_store,
        application.conversation.state_store,
        application.incidents.state_store,
        application.inventory.state_store,
        application.tests.state_store,
        application.builds.state_store,
        application.codex.state_store,
        application.validator.state_store,
        application.v3.state_store,
    )
    activation_is_active = bool(activation_manifest and activation_manifest.is_active())
    activation_evidence = (
        activation_manifest.evidence()
        if activation_manifest is not None
        else "requiere manifiesto de activación explícito fuera del código"
    )
    inventory_provider = application.inventory.provider
    backup_provider = application.backups.provider
    deployment_provider = application.deployments.provider
    rollback_provider = application.rollbacks.provider
    monitoring_provider = application.monitoring.provider
    execution_provider = application.execution.provider
    test_provider = application.tests.provider
    build_provider = application.builds.provider
    codex_provider = application.codex.provider
    chat_provider = application.conversation.provider
    backup_ready = bool(
        application.backups.provider_enabled
        and backup_provider
        and getattr(backup_provider, "live_data", False)
    )
    deployment_ready = bool(
        application.deployments.provider_enabled
        and deployment_provider
        and getattr(deployment_provider, "live_data", False)
    )
    rollback_ready = bool(
        application.rollbacks.provider_enabled
        and rollback_provider
        and getattr(rollback_provider, "live_data", False)
    )
    monitoring_ready = bool(
        application.monitoring.provider_enabled
        and monitoring_provider
        and getattr(monitoring_provider, "live_data", False)
    )
    execution_ready = bool(
        application.execution.enabled
        and execution_provider
        and getattr(execution_provider, "live_data", False)
    )
    testing_ready = bool(
        application.tests.provider_enabled
        and test_provider
        and getattr(test_provider, "live_data", False)
    )
    build_ready = bool(
        application.builds.provider_enabled
        and build_provider
        and getattr(build_provider, "live_data", False)
    )
    codex_ready = bool(
        application.codex.provider_enabled
        and codex_provider
        and getattr(codex_provider, "live_data", False)
    )
    chat_ready = bool(
        application.conversation.ai_enabled
        and chat_provider
        and getattr(chat_provider, "live_data", False)
    )
    required_provider_ids, required_permissions = _activation_requirements(application)
    declared_provider_ids = set(activation_manifest.provider_ids) if activation_manifest else set()
    declared_permissions = set(activation_manifest.effective_permissions) if activation_manifest else set()
    missing_provider_ids = sorted(required_provider_ids - declared_provider_ids)
    missing_permissions = sorted(required_permissions - declared_permissions)
    activation_scope_ready = activation_is_active and not missing_provider_ids and not missing_permissions
    checks = (
        ReadinessCheck(
            "identity_persistent",
            "Identidad persistente",
            identity_persistent,
            "JsonUserStore con al menos una identidad provisionada" if identity_persistent else "falta almacén de identidad o usuario provisionado",
        ),
        ReadinessCheck(
            "two_factor",
            "Segundo factor",
            two_factor,
            "TOTP inyectado y exigido para todas las identidades" if two_factor else "no todas las identidades requieren TOTP",
        ),
        ReadinessCheck(
            "authorization_policy",
            "Autorización y Policy Engine",
            application.policy is not None and bool(users),
            "roles, permisos y policy engine presentes" if application.policy is not None and users else "falta policy engine o identidad",
        ),
        ReadinessCheck(
            "audit_persistent",
            "Auditoría persistente",
            application.audit.sink is not None,
            "sink metadata-only configurado" if application.audit.sink is not None else "auditoría solo en memoria",
        ),
        ReadinessCheck(
            "approval_persistent",
            "Aprobaciones persistentes",
            approval_persistent,
            "store de aprobaciones explícito" if approval_persistent else "aprobaciones en memoria",
        ),
        ReadinessCheck(
            "workflow_state_persistent",
            "Estado de workflows persistente",
            all(store is not None for store in state_stores),
            "todos los workflows tienen store opt-in" if all(store is not None for store in state_stores) else "falta persistencia en uno o más workflows",
        ),
        ReadinessCheck(
            "backup_and_restore",
            "Backup, checksum y restore-test",
            backup_ready,
            "provider de backup live habilitado" if backup_ready else "provider de backup live no habilitado",
        ),
        ReadinessCheck(
            "validation",
            "Validación pre/post",
            application.validator is not None and application.validator.state_store is not None,
            "servicio de validación y estado persistente configurados"
            if application.validator is not None and application.validator.state_store is not None
            else "falta persistencia del informe de validación",
        ),
        ReadinessCheck(
            "testing_provider",
            "Testing Agent",
            testing_ready,
            "provider de tests del repositorio live declarado"
            if testing_ready
            else "provider de tests live no habilitado",
        ),
        ReadinessCheck(
            "build_provider",
            "Build provider",
            build_ready,
            "provider de build live declarado" if build_ready else "provider de build live no habilitado",
        ),
        ReadinessCheck(
            "codex_provider",
            "Provider de Codex",
            codex_ready,
            "provider Codex live declarado"
            if codex_ready
            else "provider Codex live no habilitado",
        ),
        ReadinessCheck(
            "deployment_provider",
            "Provider de deployment revisado",
            deployment_ready,
            "provider de deployment live declarado" if deployment_ready else "deployment permanece bloqueado",
        ),
        ReadinessCheck(
            "rollback_provider",
            "Provider de rollback revisado",
            rollback_ready,
            "provider de rollback live declarado" if rollback_ready else "rollback permanece bloqueado",
        ),
        ReadinessCheck(
            "monitoring_provider",
            "Monitorización READ_SAFE",
            monitoring_ready,
            "provider de monitorización live declarado" if monitoring_ready else "monitorización live no habilitada",
        ),
        ReadinessCheck(
            "inventory_provider",
            "Inventario READ_SAFE explícito",
            bool(inventory_provider and application.inventory.provider_enabled and getattr(inventory_provider, "live_data", False)),
            "provider READ_SAFE live habilitado" if inventory_provider and application.inventory.provider_enabled and getattr(inventory_provider, "live_data", False) else "inventario live no habilitado",
        ),
        ReadinessCheck(
            "controlled_execution",
            "Ejecución controlada",
            execution_ready,
            "provider live explícito detrás del gate" if execution_ready else "blocked_by_default",
        ),
        ReadinessCheck(
            "chat_provider",
            "Provider de chat IA",
            chat_ready,
            "provider IA live configurado" if chat_ready else "solo planificador local",
        ),
        ReadinessCheck(
            "transport_security",
            "HTTPS y cookies seguras",
            secure_cookies and https_terminated,
            "HTTPS terminado y cookie Secure declarada" if secure_cookies and https_terminated else "HTTPS/cookie Secure no demostrados",
        ),
        ReadinessCheck(
            "human_authorization",
            "Autorización humana de activación",
            activation_is_active,
            activation_evidence,
        ),
        ReadinessCheck(
            "activation_scope",
            "Scope y permisos del manifiesto",
            activation_scope_ready,
            "providers y permisos efectivos declarados"
            if activation_scope_ready
            else "faltan providers o permisos efectivos en el manifiesto de activación",
        ),
    )
    state = ReadinessState.GO if all(check.passed for check in checks) else ReadinessState.NO_GO
    return ProductionReadinessReport(
        state=state,
        checks=checks,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def _activation_requirements(application: "ControlCenterApplication") -> tuple[set[str], set[str]]:
    """Return the provider identities and permissions needed by live adapters."""

    provider_ids: set[str] = set()
    permissions: set[str] = set()

    def require(provider: object | None, enabled: bool, values: tuple[str, ...]) -> None:
        if not enabled or provider is None or getattr(provider, "live_data", False) is not True:
            return
        provider_id = getattr(provider, "name", None)
        if isinstance(provider_id, str) and provider_id.strip():
            provider_ids.add(provider_id)
        permissions.update(values)

    require(
        application.conversation.provider,
        application.conversation.ai_enabled,
        ("VIEW_DASHBOARD",),
    )
    require(
        application.backups.provider,
        application.backups.provider_enabled,
        ("VIEW_BACKUPS", "CREATE_BACKUP"),
    )
    require(
        application.deployments.provider,
        application.deployments.provider_enabled,
        ("VIEW_PROJECTS", "DEPLOY", "APPROVE_OPERATION"),
    )
    require(
        application.rollbacks.provider,
        application.rollbacks.provider_enabled,
        ("VIEW_PROJECTS", "ROLLBACK", "APPROVE_OPERATION"),
    )
    require(
        application.monitoring.provider,
        application.monitoring.provider_enabled,
        ("VIEW_MONITORING", "RUN_DIAGNOSTICS"),
    )
    require(
        application.execution.provider,
        application.execution.enabled,
        ("VIEW_CORE_OPERATOR", "RUN_READ_SAFE"),
    )
    require(
        application.inventory.provider,
        application.inventory.provider_enabled,
        ("VIEW_INVENTORY_METADATA", "RUN_READ_SAFE"),
    )
    require(
        application.published_projects.provider,
        application.published_projects.provider_enabled,
        ("VIEW_PROJECTS",),
    )
    require(
        application.tests.provider,
        application.tests.provider_enabled,
        ("VIEW_CORE_OPERATOR", "RUN_TESTS"),
    )
    require(
        application.builds.provider,
        application.builds.provider_enabled,
        ("VIEW_CORE_OPERATOR", "RUN_BUILDS"),
    )
    require(
        application.codex.provider,
        application.codex.provider_enabled,
        ("VIEW_PROJECTS",),
    )
    return provider_ids, permissions
