"""Application services for the Cibermedida Control Center.

The package contains dependency-free, in-memory services. Production adapters
must be added only behind the existing policy and authorization contracts.
"""

from .audit import AuditRecord, AuditSink, JsonlAuditSink, MetadataAuditLog
from .activation import ActivationManifest, ActivationManifestError, load_activation_manifest
from .application import ControlCenterApplication
from .agents import AgentDescriptor, AgentManager, AgentState, AgentTask
from .analysis import (
    ChangeManager,
    ChangeRecord,
    ConfigurationDriftService,
    ContractState,
    DriftReport,
    ImpactAnalysisService,
    ImpactReport,
    KnowledgeRecord,
    KnowledgeService,
)
from .auth import AuthService, JsonUserStore, Permission, Role, TotpVerifier, User, UserStore
from .backups import BackupManager, BackupProvider, BackupProviderEvidence, BackupRecord, BackupState, BackupType
from .builds import BuildEvidence, BuildExecutionState, BuildProvider, BuildRun, BuildService, DeclaredCommandBuildProvider, SyntheticBuildProvider
from .filesystem_backup import FilesystemBackupProvider
from .filesystem_release import FilesystemReleaseProvider
from .capabilities import CapabilityRegistry, CapabilityStatus
from .conversation import ChatMessage, ChatProvider, ConversationResult, ConversationService, ProviderChatResult
from .codex import CodexAnalysisState, CodexEvidence, CodexProvider, CodexRun, CodexService, SyntheticCodexProvider
from .codex_cli import CodexCliProvider
from .chat_provider import OpenAICompatibleChatProvider
from .deployments import (
    DeploymentManager,
    DeploymentPlan,
    DeploymentProvider,
    DeploymentProviderEvidence,
    DeploymentState,
    DeploymentValidationEvidence,
    DeploymentValidator,
)
from .execution import (
    ControlledExecutionRecord,
    ControlledExecutionService,
    ControlledExecutionState,
    ExecutionProvider,
    ProviderEvidence,
)
from .incidents import Incident, IncidentManager, IncidentSeverity, IncidentStatus
from .inventory import (
    InventoryCollectionResult,
    InventoryCollectionState,
    InventoryProvider,
    InventoryService,
    ReadSafeInventoryProvider,
    SyntheticInventoryProvider,
)
from .readiness import ProductionReadinessReport, ReadinessCheck, ReadinessState, evaluate_production_readiness
from .monitoring import (
    MetricSnapshot,
    MonitoringCollectionResult,
    MonitoringCollectionState,
    MonitoringProvider,
    MonitoringService,
)
from .read_safe_monitoring import ReadSafeMonitoringProvider, SyntheticReadSafeMonitoringProvider
from .read_safe_execution import ReadSafeExecutionProvider, SyntheticReadSafeExecutionProvider
from .operations import OperationPlan, OperationService, OperationState
from .operation_manifest import OperationManifest, OperationStatus, hashes_match, manifest_from_dict, risk_level_for
from .pipeline import ApplicationCoreAuditBridge, ExecutionPipelineResult, ExecutionPipelineService
from .projects import (
    ProjectCollectionState,
    ProjectEvidence,
    ProjectProvider,
    ProjectRecord,
    ProjectService,
    ReadSafeProjectProvider,
    SyntheticProjectProvider,
)
from .rollbacks import RollbackManager, RollbackPlan, RollbackProvider, RollbackProviderEvidence, RollbackState
from .state import JsonMetadataStore
from .testing import InProcessTestProvider, SyntheticTestProvider, TestEvidence, TestExecutionState, TestProvider, TestRun, TestService
from .validation import ValidationReport, ValidationState, ValidatorService
from .v3 import (
    DigitalTwinNode,
    DigitalTwinRecord,
    DigitalTwinRelation,
    HistoricalCorrelation,
    PredictiveReport,
    ProjectAutonomyProfile,
    RecoveryPlan,
    ServerRecord,
    V3InsightsService,
    V3State,
)

__all__ = [
    "AuditRecord",
    "AuditSink",
    "ActivationManifest",
    "ActivationManifestError",
    "AgentDescriptor",
    "AgentManager",
    "AgentState",
    "AgentTask",
    "ChangeManager",
    "ChangeRecord",
    "ConfigurationDriftService",
    "ContractState",
    "ControlCenterApplication",
    "AuthService",
    "JsonUserStore",
    "JsonlAuditSink",
    "load_activation_manifest",
    "BackupManager",
    "BackupProvider",
    "BackupProviderEvidence",
    "BackupRecord",
    "BackupState",
    "BackupType",
    "BuildEvidence",
    "BuildExecutionState",
    "BuildProvider",
    "BuildRun",
    "BuildService",
    "DeclaredCommandBuildProvider",
    "SyntheticBuildProvider",
    "FilesystemBackupProvider",
    "FilesystemReleaseProvider",
    "CapabilityRegistry",
    "CapabilityStatus",
    "ChatMessage",
    "ChatProvider",
    "OpenAICompatibleChatProvider",
    "ConversationResult",
    "ConversationService",
    "ProviderChatResult",
    "CodexAnalysisState",
    "CodexEvidence",
    "CodexProvider",
    "CodexRun",
    "CodexService",
    "SyntheticCodexProvider",
    "CodexCliProvider",
    "DeploymentManager",
    "DeploymentPlan",
    "DeploymentProvider",
    "DeploymentProviderEvidence",
    "DeploymentState",
    "DeploymentValidationEvidence",
    "DeploymentValidator",
    "ControlledExecutionRecord",
    "ControlledExecutionService",
    "ControlledExecutionState",
    "ExecutionProvider",
    "DriftReport",
    "Incident",
    "IncidentManager",
    "IncidentSeverity",
    "IncidentStatus",
    "InventoryCollectionResult",
    "InventoryCollectionState",
    "InventoryProvider",
    "InventoryService",
    "ReadSafeInventoryProvider",
    "SyntheticInventoryProvider",
    "ProductionReadinessReport",
    "ReadinessCheck",
    "ReadinessState",
    "evaluate_production_readiness",
    "ImpactAnalysisService",
    "ImpactReport",
    "KnowledgeRecord",
    "KnowledgeService",
    "MetadataAuditLog",
    "MetricSnapshot",
    "MonitoringCollectionResult",
    "MonitoringCollectionState",
    "MonitoringProvider",
    "MonitoringService",
    "ReadSafeMonitoringProvider",
    "SyntheticReadSafeMonitoringProvider",
    "ReadSafeExecutionProvider",
    "SyntheticReadSafeExecutionProvider",
    "OperationPlan",
    "OperationService",
    "OperationState",
    "OperationManifest",
    "OperationStatus",
    "hashes_match",
    "manifest_from_dict",
    "risk_level_for",
    "ApplicationCoreAuditBridge",
    "ExecutionPipelineResult",
    "ExecutionPipelineService",
    "Permission",
    "ProviderEvidence",
    "ProjectCollectionState",
    "ProjectEvidence",
    "ProjectProvider",
    "ProjectRecord",
    "ProjectService",
    "ReadSafeProjectProvider",
    "SyntheticProjectProvider",
    "InProcessTestProvider",
    "SyntheticTestProvider",
    "TestEvidence",
    "TestExecutionState",
    "TestProvider",
    "TestRun",
    "TestService",
    "Role",
    "TotpVerifier",
    "RollbackManager",
    "RollbackPlan",
    "RollbackProvider",
    "RollbackProviderEvidence",
    "RollbackState",
    "JsonMetadataStore",
    "User",
    "UserStore",
    "ValidationReport",
    "ValidationState",
    "ValidatorService",
    "DigitalTwinNode",
    "DigitalTwinRecord",
    "DigitalTwinRelation",
    "HistoricalCorrelation",
    "PredictiveReport",
    "ProjectAutonomyProfile",
    "RecoveryPlan",
    "ServerRecord",
    "V3InsightsService",
    "V3State",
]
