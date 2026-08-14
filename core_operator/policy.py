"""Initial policy engine for safe Core Operator decisions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from phase1_inventory.commands import CommandClass, CommandSpec, get_command


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


@dataclass(frozen=True)
class PolicyRequest:
    actor: str
    action: str
    command_id: str | None = None
    command_class: CommandClass | None = None
    modifies_production: bool = False
    writes_to_disk: bool = False
    requires_privileged_access: bool = False


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    risk_level: RiskLevel
    authorization_required: bool
    reason: str


MODIFYING_ACTIONS = frozenset(
    {
        "create_backup",
        "delete",
        "deploy",
        "install_dependency",
        "merge",
        "modify_apache",
        "modify_code",
        "modify_docker",
        "modify_pm2",
        "modify_systemd",
        "restart_service",
        "rollback",
        "write_file",
    }
)


class PolicyEngine:
    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        if request.modifies_production or request.writes_to_disk or request.action in MODIFYING_ACTIONS:
            return PolicyDecision(Decision.DENY, RiskLevel.HIGH, True, "modifying actions are denied by default")

        command_class, requires_privileged_access = self._resolve_command_metadata(request)
        if request.requires_privileged_access or requires_privileged_access:
            return PolicyDecision(Decision.APPROVAL_REQUIRED, RiskLevel.HIGH, True, "privileged access requires authorization")

        if command_class is CommandClass.READ_SAFE:
            return PolicyDecision(Decision.ALLOW, RiskLevel.LOW, False, "READ_SAFE is allowed")
        if command_class is CommandClass.READ_SENSITIVE:
            return PolicyDecision(Decision.APPROVAL_REQUIRED, RiskLevel.MEDIUM, True, "READ_SENSITIVE requires authorization")
        if command_class is CommandClass.READ_PRIVILEGED:
            return PolicyDecision(Decision.APPROVAL_REQUIRED, RiskLevel.HIGH, True, "READ_PRIVILEGED requires authorization")
        if command_class is CommandClass.FORBIDDEN:
            return PolicyDecision(Decision.DENY, RiskLevel.CRITICAL, True, "FORBIDDEN actions are denied")

        return PolicyDecision(Decision.DENY, RiskLevel.MEDIUM, True, "unknown command class is denied")

    @staticmethod
    def _resolve_command_metadata(request: PolicyRequest) -> tuple[CommandClass | None, bool]:
        if request.command_id:
            spec: CommandSpec = get_command(request.command_id)
            return spec.command_class, False
        return request.command_class, False
