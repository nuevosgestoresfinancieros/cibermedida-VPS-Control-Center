"""Configuration defaults for the Phase 2 Core Operator."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

AUTHORIZED_PROJECT_ROOT = Path("/var/www/cibermedida-vps-control-center")


@dataclass(frozen=True)
class OperatorConfig:
    project_root: Path = AUTHORIZED_PROJECT_ROOT
    persistence_enabled: bool = False
    log_to_disk: bool = False
    audit_to_disk: bool = False
    load_environment_files: bool = False
    allow_network_health_checks: bool = False

    def validate(self) -> None:
        if self.project_root != AUTHORIZED_PROJECT_ROOT:
            raise ValueError("Core Operator project_root must be the authorized project path")
        if self.persistence_enabled:
            raise ValueError("Persistence is disabled by default for the Phase 2 base")
        if self.log_to_disk or self.audit_to_disk:
            raise ValueError("Disk logging/audit storage is not authorized in the Phase 2 base")
        if self.load_environment_files:
            raise ValueError("Environment file loading is not authorized")
        if self.allow_network_health_checks:
            raise ValueError("Network health checks are not authorized in the Phase 2 base")


def default_config() -> OperatorConfig:
    config = OperatorConfig()
    config.validate()
    return config
