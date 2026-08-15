"""Policy-gated adapter for the existing READ_SAFE executor."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from phase1_inventory.executor import CommandResult, RestrictedExecutor

from .audit import AuditStore
from .approvals import ApprovalRequest, ApprovalStore, InMemoryApprovalStore
from .policy import Decision, PolicyEngine, PolicyRequest
from .safe_logging import InMemoryStructuredLogger


class ReadSafeExecutor(Protocol):
    def execute(self, command_id: str) -> CommandResult:
        ...


@dataclass(frozen=True)
class ExecutionEnvelope:
    decision: Decision
    result: CommandResult | None
    reason: str
    approval_request: ApprovalRequest | None = None


class PolicyDeniedError(PermissionError):
    pass


class ReadSafeExecutorAdapter:
    def __init__(
        self,
        *,
        policy: PolicyEngine,
        audit: AuditStore,
        logger: InMemoryStructuredLogger,
        executor: ReadSafeExecutor | None = None,
        approvals: ApprovalStore | None = None,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.logger = logger
        self.executor = executor or RestrictedExecutor()
        self.approvals = approvals or InMemoryApprovalStore(audit=audit)

    def execute(self, *, actor: str, command_id: str) -> ExecutionEnvelope:
        policy_decision = self.policy.evaluate(PolicyRequest(actor=actor, action="execute_read_safe", command_id=command_id))
        if policy_decision.decision is not Decision.ALLOW:
            approval_request = self.approvals.apply_policy_decision(
                actor=actor,
                action="execute_read_safe",
                policy_decision=policy_decision,
                command_id=command_id,
            )
            self.audit.append(
                actor=actor,
                action="execute_read_safe",
                risk_level=policy_decision.risk_level,
                command_id=command_id,
                result=policy_decision.decision.value,
                authorization_required=policy_decision.authorization_required,
            )
            self.logger.log("warning", "executor request blocked", command_id=command_id, decision=policy_decision.decision.value)
            return ExecutionEnvelope(policy_decision.decision, None, policy_decision.reason, approval_request)

        result = self.executor.execute(command_id)
        audit_result = "success" if result.returncode == 0 and not result.error_code else "failed"
        self.audit.append(
            actor=actor,
            action="execute_read_safe",
            risk_level=policy_decision.risk_level,
            command_id=command_id,
            result=audit_result,
            authorization_required=False,
        )
        self.logger.log(
            "info",
            "executor request completed",
            command_id=command_id,
            returncode=result.returncode,
            error_code=result.error_code,
            timed_out=result.timed_out,
        )
        return ExecutionEnvelope(policy_decision.decision, result, policy_decision.reason)
