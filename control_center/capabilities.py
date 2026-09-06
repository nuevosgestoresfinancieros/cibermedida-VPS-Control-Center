"""Capability registry for honest UI and API status reporting."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CapabilityStatus:
    capability_id: str
    label: str
    phase: str
    state: str
    live_data: bool
    provider: str | None
    description: str


class CapabilityRegistry:
    """Describe which contracts are usable and which need reviewed adapters."""

    def __init__(
        self,
        *,
        auth_persistent: bool,
        audit_persistent: bool,
        approval_persistent: bool = False,
        chat_provider: Any = None,
        chat_enabled: bool = False,
        backup_provider: Any = None,
        deployment_provider: Any = None,
        rollback_provider: Any = None,
        execution_provider: Any = None,
        monitoring_provider: Any = None,
        inventory_provider: Any = None,
        inventory_enabled: bool = False,
        project_provider: Any = None,
        projects_enabled: bool = False,
        test_provider: Any = None,
        tests_enabled: bool = False,
        build_provider: Any = None,
        builds_enabled: bool = False,
        codex_provider: Any = None,
        codex_enabled: bool = False,
        providers_enabled: bool = False,
    ) -> None:
        provider_state = lambda provider: getattr(provider, "name", None) if providers_enabled and provider else None
        provider_live = lambda provider: bool(
            provider_state(provider) and getattr(provider, "live_data", False)
        )
        inventory_state = (
            getattr(inventory_provider, "name", None)
            if inventory_enabled and inventory_provider is not None
            else None
        )
        project_state = (
            getattr(project_provider, "name", None)
            if projects_enabled and project_provider is not None
            else None
        )
        test_state = (
            getattr(test_provider, "name", None)
            if tests_enabled and test_provider is not None
            else None
        )
        build_state = (
            getattr(build_provider, "name", None)
            if builds_enabled and build_provider is not None
            else None
        )
        codex_state = (
            getattr(codex_provider, "name", None)
            if codex_enabled and codex_provider is not None
            else None
        )
        self._statuses = (
            CapabilityStatus(
                "authentication",
                "Autenticación y roles",
                "Fase 3",
                "persistent" if auth_persistent else "provision_required",
                False,
                "JsonUserStore" if auth_persistent else None,
                "Sesiones, CSRF, roles y TOTP inyectable están disponibles; una cuenta debe provisionarse explícitamente.",
            ),
            CapabilityStatus(
                "chat",
                "Chat y planificación",
                "Fase 4",
                "provider_ready" if chat_provider and chat_enabled else "local_planner",
                provider_live(chat_provider) if chat_enabled else False,
                getattr(chat_provider, "name", None) if chat_provider and chat_enabled else None,
                "El planificador local funciona; un proveedor IA externo requiere inyección y revisión.",
            ),
            CapabilityStatus(
                "audit",
                "Auditoría metadata-only",
                "Fase 2/3",
                "persistent" if audit_persistent else "in_memory",
                False,
                "JsonlAuditSink" if audit_persistent else None,
                "Nunca registra secretos, stdout ni stderr crudos.",
            ),
            CapabilityStatus(
                "approval_workflow",
                "Aprobaciones independientes",
                "Fase 2/3",
                "persistent" if approval_persistent else "in_memory",
                False,
                "JsonApprovalStore" if approval_persistent else None,
                "Solicitante y aprobador se separan; la persistencia JSON es opt-in y metadata-only.",
            ),
            CapabilityStatus(
                "backups",
                "Backups y restore test",
                "Fase 6",
                "provider_enabled" if provider_state(backup_provider) else "contract_only",
                provider_live(backup_provider),
                provider_state(backup_provider),
                "Provider de filesystem declarado con checksum y restore test de laboratorio."
                if provider_state(backup_provider)
                else "El ciclo prepare/verify/restore-test permanece en memoria sin un adaptador explícito.",
            ),
            CapabilityStatus(
                "deployments",
                "Despliegues",
                "Fase 7",
                "provider_enabled" if provider_state(deployment_provider) else "blocked_by_default",
                provider_live(deployment_provider),
                provider_state(deployment_provider),
                "Release de filesystem declarada; no inicia servicios. Requiere preflight, backup verificado y aprobación independiente."
                if provider_state(deployment_provider)
                else "Requiere preflight, backup verificado, aprobación independiente y proveedor revisado.",
            ),
            CapabilityStatus(
                "rollback",
                "Rollback",
                "Fase 8",
                "provider_enabled" if provider_state(rollback_provider) else "blocked_by_default",
                provider_live(rollback_provider),
                provider_state(rollback_provider),
                "Rollback de release declarada mediante CURRENT; no modifica servicios."
                if provider_state(rollback_provider)
                else "Requiere aprobación independiente y un proveedor que demuestre validación posterior.",
            ),
            CapabilityStatus(
                "monitoring",
                "Monitorización y anomalías",
                "Fase 9/14",
                "provider_enabled" if provider_state(monitoring_provider) else "snapshot_only",
                bool(
                    provider_live(monitoring_provider)
                ),
                provider_state(monitoring_provider),
                "Provider READ_SAFE limitado a memoria, disco y carga; sin logs ni cambios."
                if provider_state(monitoring_provider)
                else "Los snapshots aportados se pueden evaluar; la recolección real requiere un adaptador revisado.",
            ),
            CapabilityStatus(
                "controlled_execution",
                "Ejecución controlada",
                "Fase 2/15",
                "provider_enabled" if provider_state(execution_provider) else "blocked_by_default",
                provider_live(execution_provider),
                provider_state(execution_provider),
                "La aplicación puede evaluar la cadena aprobada; el proveedor explícito READ_SAFE es opcional y las acciones modificadoras permanecen bloqueadas.",
            ),
            CapabilityStatus(
                "inventory",
                "Inventario READ_SAFE",
                "Fase 1/3",
                "provider_enabled" if inventory_state else "blocked_by_default",
                bool(inventory_state and getattr(inventory_provider, "live_data", False)),
                inventory_state,
                "Colección explícita y validada en memoria; no crea INVENTORY.json ni consulta datos sensibles."
                if inventory_state
                else "La colección READ_SAFE requiere una habilitación explícita y permanece bloqueada por defecto.",
            ),
            CapabilityStatus(
                "projects",
                "Proyectos y Git READ_SAFE",
                "Fase 3/5",
                "provider_enabled" if project_state else "mock_catalog",
                bool(project_state and getattr(project_provider, "live_data", False)),
                project_state,
                "Lee únicamente rama, estado sucio y HEAD mediante la allowlist Git; nunca modifica el repositorio."
                if project_state
                else "Catálogo mock; la colección Git requiere un provider explícito.",
            ),
            CapabilityStatus(
                "testing",
                "Testing Agent",
                "Fase 5",
                "provider_enabled" if test_state else "contract_only",
                bool(test_state and getattr(test_provider, "live_data", False)),
                test_state,
                "Ejecuta únicamente el target repository mediante un provider explícito y conserva métricas sin salida."
                if test_state
                else "Evalúa checks declarados; la ejecución de tests requiere un provider explícito.",
            ),
            CapabilityStatus(
                "builds",
                "Builds declarados",
                "Fase 5/7",
                "provider_enabled" if build_state else "contract_only",
                bool(build_state and getattr(build_provider, "live_data", False)),
                build_state,
                "Ejecuta únicamente perfiles argv declarados y conserva métricas sin salida cruda."
                if build_state
                else "La validación de build requiere un provider explícito y no acepta comandos de la petición.",
            ),
            CapabilityStatus(
                "codex",
                "Integración Codex",
                "Fase 5",
                "provider_enabled" if codex_state else "contract_only",
                bool(codex_state and getattr(codex_provider, "live_data", False)),
                codex_state,
                "Analiza solicitudes mediante un provider explícito y conserva solo hallazgos metadata-only; el adapter CLI usa sandbox read-only y no modifica repositorios."
                if codex_state
                else "El contrato Codex está definido; el provider externo requiere revisión y habilitación explícitas.",
            ),
            CapabilityStatus(
                "knowledge_engine",
                "Knowledge Engine y gemelo digital",
                "Fase 11",
                "metadata_only",
                False,
                "V3InsightsService",
                "Registra relaciones declaradas y no descubre automáticamente el VPS.",
            ),
            CapabilityStatus(
                "impact_analysis",
                "Análisis de impacto e histórico",
                "Fase 12",
                "metadata_only",
                False,
                "V3InsightsService",
                "Calcula correlaciones y requisitos sobre evidencia aportada por el usuario.",
            ),
            CapabilityStatus(
                "predictive_analysis",
                "Análisis predictivo prudente",
                "Fase 14",
                "metadata_only",
                False,
                "V3InsightsService",
                "Calcula tendencias acotadas; no genera decisiones ni alertas operativas automáticas.",
            ),
            CapabilityStatus(
                "project_autonomy",
                "Autonomía por proyecto",
                "Fase 15",
                "blocked_by_default",
                False,
                "V3InsightsService",
                "Registra el nivel solicitado, pero mantiene toda ejecución bloqueada por defecto.",
            ),
            CapabilityStatus(
                "multi_server",
                "Catálogo multi-servidor",
                "V3",
                "metadata_only",
                False,
                "V3InsightsService",
                "Registra servidores declarados sin abrir conexiones ni consultar hosts.",
            ),
            CapabilityStatus(
                "controlled_recovery",
                "Recuperación controlada",
                "V3",
                "blocked_by_default",
                False,
                "V3InsightsService",
                "Prepara planes vinculados a incidentes; requiere aprobación y provider revisado.",
            ),
        )

    @property
    def statuses(self) -> tuple[CapabilityStatus, ...]:
        return self._statuses
