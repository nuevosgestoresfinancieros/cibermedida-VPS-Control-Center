"""Composition root for the local Control Center application.

All services share the same in-memory authentication, policy, approval and
metadata-audit boundaries. A deployment adapter must be supplied explicitly
before any production integration is considered.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from core_operator.approvals import ApprovalStore, InMemoryApprovalStore
from core_operator.policy import PolicyEngine

from .agents import AgentManager
from .analysis import ChangeManager, ConfigurationDriftService, ImpactAnalysisService, KnowledgeService
from .audit import AuditSink, MetadataAuditLog
from .auth import AuthService, Role, User, UserStore
from .backups import BackupManager, BackupProvider
from .builds import BuildProvider, BuildService
from .capabilities import CapabilityRegistry
from .conversation import ChatProvider, ConversationService
from .codex import CodexProvider, CodexService
from .deployments import DeploymentManager, DeploymentProvider, DeploymentValidator
from .execution import ControlledExecutionService, ExecutionProvider
from .incidents import IncidentManager
from .inventory import InventoryProvider, InventoryService
from .monitoring import MonitoringProvider, MonitoringService
from .operations import OperationService
from .pipeline import ExecutionPipelineService
from .projects import ProjectProvider, ProjectService
from .published_projects import PublishedProjectCatalogService, PublishedProjectProvider
from .rollbacks import RollbackManager, RollbackProvider
from .service_activation import ServiceActivationProvider
from .state import JsonMetadataStore
from .testing import TestProvider, TestService
from .validation import ValidatorService
from .v3 import V3InsightsService


class ControlCenterApplication:
    """Application graph with no default identity or live adapters.

    Identity and audit persistence, plus every external provider, are opt-in
    constructor dependencies; the default graph remains local and blocked.
    """

    def __init__(
        self,
        *,
        user_store: UserStore | None = None,
        otp_verifier: Callable[[User, str], bool] | None = None,
        audit_sink: AuditSink | None = None,
        approval_store: ApprovalStore | None = None,
        operation_state_store: JsonMetadataStore | None = None,
        chat_provider: ChatProvider | None = None,
        chat_enabled: bool = False,
        conversation_state_store: JsonMetadataStore | None = None,
        backup_provider: BackupProvider | None = None,
        backup_state_store: JsonMetadataStore | None = None,
        deployment_provider: DeploymentProvider | None = None,
        deployment_validator: DeploymentValidator | None = None,
        deployment_state_store: JsonMetadataStore | None = None,
        service_activation: ServiceActivationProvider | None = None,
        rollback_provider: RollbackProvider | None = None,
        rollback_state_store: JsonMetadataStore | None = None,
        execution_provider: ExecutionProvider | None = None,
        execution_state_store: JsonMetadataStore | None = None,
        monitoring_provider: MonitoringProvider | None = None,
        monitoring_state_store: JsonMetadataStore | None = None,
        inventory_provider: InventoryProvider | None = None,
        inventory_enabled: bool = False,
        inventory_schema_path: str | Path | None = None,
        inventory_state_store: JsonMetadataStore | None = None,
        project_provider: ProjectProvider | None = None,
        projects_enabled: bool = False,
        projects_state_store: JsonMetadataStore | None = None,
        published_projects_provider: PublishedProjectProvider | None = None,
        published_projects_enabled: bool = False,
        test_provider: TestProvider | None = None,
        tests_enabled: bool = False,
        tests_state_store: JsonMetadataStore | None = None,
        build_provider: BuildProvider | None = None,
        builds_enabled: bool = False,
        builds_state_store: JsonMetadataStore | None = None,
        codex_provider: CodexProvider | None = None,
        codex_enabled: bool = False,
        codex_state_store: JsonMetadataStore | None = None,
        incident_state_store: JsonMetadataStore | None = None,
        validation_state_store: JsonMetadataStore | None = None,
        v3_state_store: JsonMetadataStore | None = None,
        policy_version: str = "phase-3.6",
        providers_enabled: bool = False,
    ) -> None:
        self.auth = AuthService(user_store=user_store, otp_verifier=otp_verifier)
        self.audit = MetadataAuditLog(sink=audit_sink)
        self.policy = PolicyEngine()
        self.policy_version = policy_version
        self.approvals = approval_store or InMemoryApprovalStore()
        self.service_activation = service_activation
        self.monitoring = MonitoringService(
            provider=monitoring_provider,
            provider_enabled=providers_enabled and monitoring_provider is not None,
            state_store=monitoring_state_store,
        )
        self.inventory = InventoryService(
            auth=self.auth,
            audit=self.audit,
            provider=inventory_provider,
            provider_enabled=inventory_enabled,
            schema_path=inventory_schema_path,
            state_store=inventory_state_store,
        )
        self.projects = ProjectService(
            auth=self.auth,
            audit=self.audit,
            provider=project_provider,
            provider_enabled=projects_enabled,
            state_store=projects_state_store,
        )
        self.published_projects = PublishedProjectCatalogService(
            auth=self.auth,
            audit=self.audit,
            provider=published_projects_provider,
            provider_enabled=published_projects_enabled,
        )
        self.tests = TestService(
            auth=self.auth,
            audit=self.audit,
            provider=test_provider,
            provider_enabled=tests_enabled,
            state_store=tests_state_store,
        )
        self.builds = BuildService(
            auth=self.auth,
            audit=self.audit,
            provider=build_provider,
            provider_enabled=builds_enabled,
            state_store=builds_state_store,
        )
        self.codex = CodexService(
            auth=self.auth,
            audit=self.audit,
            provider=codex_provider,
            provider_enabled=codex_enabled,
            state_store=codex_state_store,
        )
        self.backups = BackupManager(
            auth=self.auth,
            audit=self.audit,
            provider=backup_provider,
            provider_enabled=providers_enabled and backup_provider is not None,
            state_store=backup_state_store,
        )
        self.operations = OperationService(
            auth=self.auth,
            policy=self.policy,
            approvals=self.approvals,
            audit=self.audit,
            backups=self.backups,
            policy_version=self.policy_version,
            state_store=operation_state_store,
        )
        self.deployments = DeploymentManager(
            auth=self.auth,
            audit=self.audit,
            backups=self.backups,
            provider=deployment_provider,
            provider_enabled=providers_enabled and deployment_provider is not None,
            post_validator=deployment_validator,
            state_store=deployment_state_store,
            service_activation=service_activation,
        )
        self.execution = ControlledExecutionService(
            auth=self.auth,
            audit=self.audit,
            provider=execution_provider,
            enabled=providers_enabled and execution_provider is not None,
            state_store=execution_state_store,
        )
        self.execution_pipeline = ExecutionPipelineService(
            auth=self.auth,
            policy=self.policy,
            approvals=self.approvals,
            audit=self.audit,
            controlled_execution=self.execution,
            policy_version=self.policy_version,
        )
        self.rollbacks = RollbackManager(
            auth=self.auth,
            audit=self.audit,
            provider=rollback_provider,
            provider_enabled=providers_enabled and rollback_provider is not None,
            state_store=rollback_state_store,
            service_activation=service_activation,
        )
        self.conversation = ConversationService(
            auth=self.auth,
            audit=self.audit,
            provider=chat_provider,
            ai_enabled=chat_enabled,
            state_store=conversation_state_store,
        )
        self.incidents = IncidentManager(
            auth=self.auth,
            audit=self.audit,
            state_store=incident_state_store,
        )
        self.validator = ValidatorService(auth=self.auth, audit=self.audit, state_store=validation_state_store)
        self.knowledge = KnowledgeService(auth=self.auth, audit=self.audit)
        self.impact = ImpactAnalysisService(auth=self.auth, audit=self.audit)
        self.drift = ConfigurationDriftService(auth=self.auth, audit=self.audit)
        self.agents = AgentManager(auth=self.auth, audit=self.audit)
        self.changes = ChangeManager(auth=self.auth, audit=self.audit)
        self.v3 = V3InsightsService(auth=self.auth, audit=self.audit, state_store=v3_state_store)
        self.capabilities = CapabilityRegistry(
            auth_persistent=user_store is not None,
            audit_persistent=audit_sink is not None,
            approval_persistent=approval_store is not None,
            chat_provider=chat_provider,
            chat_enabled=chat_enabled,
            backup_provider=backup_provider,
            deployment_provider=deployment_provider,
            rollback_provider=rollback_provider,
            execution_provider=execution_provider,
            monitoring_provider=monitoring_provider,
            inventory_provider=inventory_provider,
            inventory_enabled=inventory_enabled,
            project_provider=project_provider,
            projects_enabled=projects_enabled,
            published_projects_provider=published_projects_provider,
            published_projects_enabled=published_projects_enabled,
            test_provider=test_provider,
            tests_enabled=tests_enabled,
            build_provider=build_provider,
            builds_enabled=builds_enabled,
            codex_provider=codex_provider,
            codex_enabled=codex_enabled,
            providers_enabled=providers_enabled,
        )

    def register_user(
        self,
        *,
        user_id: str,
        username: str,
        password: str,
        role: Role,
        requires_2fa: bool = False,
    ) -> User:
        """Register an explicitly provisioned local user.

        This method is intentionally not called during application startup;
        operators must provision an identity through a separate trusted step.
        """

        return self.auth.register_user(
            user_id=user_id,
            username=username,
            password=password,
            role=role,
            requires_2fa=requires_2fa,
        )
