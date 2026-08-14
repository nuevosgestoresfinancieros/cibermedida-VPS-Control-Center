"""Internal health checks for Core Operator wiring."""

from __future__ import annotations

from dataclasses import dataclass

from .audit import InMemoryAuditStore
from .config import OperatorConfig
from .policy import PolicyEngine
from .safe_logging import InMemoryStructuredLogger


@dataclass(frozen=True)
class HealthCheckResult:
    status: str
    checks: dict[str, bool]

    @property
    def healthy(self) -> bool:
        return self.status == "ok"


class CoreHealthChecker:
    def __init__(
        self,
        *,
        config: OperatorConfig,
        policy: PolicyEngine,
        audit: InMemoryAuditStore,
        logger: InMemoryStructuredLogger,
    ) -> None:
        self.config = config
        self.policy = policy
        self.audit = audit
        self.logger = logger

    def check(self) -> HealthCheckResult:
        checks = {
            "config_initialized": self.config is not None,
            "policy_initialized": self.policy is not None,
            "audit_initialized": self.audit is not None,
            "logger_initialized": self.logger is not None,
            "persistence_disabled": not self.config.persistence_enabled,
            "disk_logging_disabled": not self.config.log_to_disk and not self.config.audit_to_disk,
            "network_health_checks_disabled": not self.config.allow_network_health_checks,
        }
        return HealthCheckResult(status="ok" if all(checks.values()) else "degraded", checks=checks)
