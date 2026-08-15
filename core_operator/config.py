"""Configuration defaults for the Phase 2 Core Operator."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

AUTHORIZED_PROJECT_ROOT = Path("/var/www/cibermedida-vps-control-center")
CRITICAL_FILENAMES = frozenset(
    {
        ".env",
        "AGENTS.md",
        "Cibermedida VPS Control Center.md",
        "INVENTORY.json",
        "pyproject.toml",
    }
)


@dataclass(frozen=True)
class OperatorConfig:
    project_root: Path = AUTHORIZED_PROJECT_ROOT
    persistence_enabled: bool = False
    log_to_disk: bool = False
    audit_to_disk: bool = False
    audit_path: Path | None = None
    load_environment_files: bool = False
    allow_network_health_checks: bool = False

    def validate(self) -> None:
        project_root = self.project_root.resolve()
        if project_root != AUTHORIZED_PROJECT_ROOT:
            raise ValueError("Core Operator project_root must be the authorized project path")
        if self.log_to_disk:
            raise ValueError("Disk logging is not authorized in the Phase 2 base")
        if self.audit_to_disk and not self.persistence_enabled:
            raise ValueError("Audit disk storage requires explicit persistence_enabled=True")
        if self.persistence_enabled and not self.audit_to_disk:
            raise ValueError("Persistence requires an explicit storage target")
        if self.audit_to_disk:
            self.resolve_audit_path()
        if self.load_environment_files:
            raise ValueError("Environment file loading is not authorized")
        if self.allow_network_health_checks:
            raise ValueError("Network health checks are not authorized in the Phase 2 base")

    def resolve_audit_path(self) -> Path:
        if self.audit_path is None:
            raise ValueError("audit_path is required when audit_to_disk=True")

        project_root = self.project_root.resolve()
        candidate = self.audit_path if self.audit_path.is_absolute() else project_root / self.audit_path
        resolved = candidate.resolve(strict=False)

        if not resolved.is_relative_to(project_root):
            raise ValueError("audit_path must stay inside the authorized project root")
        if ".git" in resolved.relative_to(project_root).parts:
            raise ValueError("audit_path must not target repository metadata")
        if resolved.name in CRITICAL_FILENAMES:
            raise ValueError("audit_path must not target a critical project file")
        if resolved.suffix != ".jsonl":
            raise ValueError("audit_path must use a .jsonl file")
        if not resolved.parent.exists():
            raise ValueError("audit_path parent directory must already exist")
        if not resolved.parent.resolve().is_relative_to(project_root):
            raise ValueError("audit_path parent directory must stay inside the project root")
        if resolved.exists() and not resolved.is_file():
            raise ValueError("audit_path must target a regular file")
        return resolved


def default_config() -> OperatorConfig:
    config = OperatorConfig()
    config.validate()
    return config
