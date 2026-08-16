"""Safe Core Operator primitives for Phase 2."""

from .audit import AuditEvent, AuditStore, InMemoryAuditStore, JsonlAuditStore, UnsafeAuditEventError
from .approved_plan_dry_runner import ApprovedPlanDryRunner, DryRunExecutionResult, DryRunExecutionState
from .approved_execution import ApprovedExecutionPlan, ApprovedExecutionPlanner, ExecutionPlanState
from .approvals import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStateError,
    ApprovalStatus,
    ApprovalStore,
    InMemoryApprovalStore,
)
from .config import OperatorConfig, default_config
from .execution_gate import ExecutionGate, ExecutionGateDecision, ExecutionGateState
from .executor_adapter import ReadSafeExecutorAdapter
from .health import CoreHealthChecker, HealthCheckResult
from .policy import Decision, PolicyEngine, PolicyRequest, RiskLevel
from .safe_logging import InMemoryStructuredLogger, LogRecord

__all__ = [
    "AuditEvent",
    "AuditStore",
    "ApprovedExecutionPlan",
    "ApprovedExecutionPlanner",
    "ApprovedPlanDryRunner",
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalStateError",
    "ApprovalStatus",
    "ApprovalStore",
    "CoreHealthChecker",
    "Decision",
    "DryRunExecutionResult",
    "DryRunExecutionState",
    "ExecutionPlanState",
    "ExecutionGate",
    "ExecutionGateDecision",
    "ExecutionGateState",
    "HealthCheckResult",
    "InMemoryAuditStore",
    "InMemoryApprovalStore",
    "JsonlAuditStore",
    "InMemoryStructuredLogger",
    "LogRecord",
    "OperatorConfig",
    "PolicyEngine",
    "PolicyRequest",
    "ReadSafeExecutorAdapter",
    "RiskLevel",
    "UnsafeAuditEventError",
    "default_config",
]
