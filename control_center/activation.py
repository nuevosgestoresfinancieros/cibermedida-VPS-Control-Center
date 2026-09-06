"""Validated, metadata-only activation authorization manifests.

An activation manifest is evidence for a readiness review, not a feature flag.
Loading one never enables a provider, grants a permission, or executes an
operation. The document is deliberately short-lived and records the policy
snapshot used by the human approval decision.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret


MAX_MANIFEST_BYTES = 64 * 1024
MAX_MANIFEST_LIFETIME = timedelta(hours=24)
_PROTECTED_NAMES = frozenset({".env", "AGENTS.md", "INVENTORY.json"})
_REQUIRED_FIELDS = frozenset(
    {
        "version",
        "manifest_id",
        "decision",
        "requester",
        "requester_role",
        "approver",
        "approver_role",
        "policy_version",
        "effective_permissions",
        "scope",
        "provider_ids",
        "approved_at",
        "expires_at",
    }
)


class ActivationManifestError(ValueError):
    """Raised when an activation manifest is unsafe or malformed."""


@dataclass(frozen=True)
class ActivationManifest:
    """Immutable authorization evidence used only by readiness checks."""

    manifest_id: str
    decision: str
    requester: str
    requester_role: str
    approver: str
    approver_role: str
    policy_version: str
    effective_permissions: tuple[str, ...]
    scope: tuple[str, ...]
    provider_ids: tuple[str, ...]
    approved_at: str
    expires_at: str

    def status(self, *, now: datetime | None = None) -> str:
        current = _as_utc(now or datetime.now(timezone.utc))
        approved_at = _parse_timestamp(self.approved_at)
        expires_at = _parse_timestamp(self.expires_at)
        if current < approved_at:
            return "not_yet_active"
        if current >= expires_at:
            return "expired"
        return "active"

    def is_active(self, *, now: datetime | None = None) -> bool:
        return self.status(now=now) == "active"

    def evidence(self, *, now: datetime | None = None) -> str:
        state = self.status(now=now)
        if state == "active":
            return f"manifiesto {self.manifest_id} activo; alcance y snapshot de permisos declarados"
        if state == "expired":
            return f"manifiesto {self.manifest_id} caducado"
        return f"manifiesto {self.manifest_id} todavía no está vigente"


def load_activation_manifest(path: str | Path) -> ActivationManifest:
    """Load one explicit JSON manifest without discovering any other files."""

    manifest_path = _validate_manifest_path(Path(path))
    try:
        if not manifest_path.exists() or not manifest_path.is_file() or manifest_path.is_symlink():
            raise ActivationManifestError("activation manifest must be a regular file")
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ActivationManifestError("activation manifest is too large")
        raw = manifest_path.read_text(encoding="utf-8")
        if contains_secret(raw) or RAW_STREAM_PATTERN.search(raw) is not None:
            raise ActivationManifestError("activation manifest contains unsafe metadata")
        payload = json.loads(raw)
    except ActivationManifestError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActivationManifestError("activation manifest cannot be read") from exc
    return _decode_manifest(payload)


def _decode_manifest(payload: object) -> ActivationManifest:
    if not isinstance(payload, Mapping):
        raise ActivationManifestError("activation manifest must be a JSON object")
    if set(payload) != _REQUIRED_FIELDS:
        raise ActivationManifestError("activation manifest fields are invalid")
    if payload.get("version") != 1:
        raise ActivationManifestError("activation manifest version is unsupported")
    if payload.get("decision") != "approved":
        raise ActivationManifestError("activation manifest decision must be approved")

    scalar_fields = (
        "manifest_id",
        "requester",
        "requester_role",
        "approver",
        "approver_role",
        "policy_version",
        "approved_at",
        "expires_at",
    )
    values: dict[str, str] = {}
    for field_name in scalar_fields:
        value = payload.get(field_name)
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise ActivationManifestError(f"activation manifest field {field_name!r} is invalid")
        if any(character in value for character in "\r\n\x00"):
            raise ActivationManifestError(f"activation manifest field {field_name!r} is invalid")
        values[field_name] = value.strip()

    if values["requester"] == values["approver"]:
        raise ActivationManifestError("requester and approver must be different identities")
    approved_at = _parse_timestamp(values["approved_at"])
    expires_at = _parse_timestamp(values["expires_at"])
    if expires_at <= approved_at or expires_at - approved_at > MAX_MANIFEST_LIFETIME:
        raise ActivationManifestError("activation manifest validity window is invalid")

    list_values: dict[str, tuple[str, ...]] = {}
    for field_name in ("effective_permissions", "scope", "provider_ids"):
        value = payload.get(field_name)
        if not isinstance(value, list) or not value or len(value) > 64:
            raise ActivationManifestError(f"activation manifest field {field_name!r} is invalid")
        normalized: list[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip() or len(item) > 128:
                raise ActivationManifestError(f"activation manifest field {field_name!r} is invalid")
            if any(character in item for character in "\r\n\x00"):
                raise ActivationManifestError(f"activation manifest field {field_name!r} is invalid")
            normalized.append(item.strip())
        if len(set(normalized)) != len(normalized):
            raise ActivationManifestError(f"activation manifest field {field_name!r} contains duplicates")
        list_values[field_name] = tuple(normalized)

    decoded = ActivationManifest(
        manifest_id=values["manifest_id"],
        decision="approved",
        requester=values["requester"],
        requester_role=values["requester_role"],
        approver=values["approver"],
        approver_role=values["approver_role"],
        policy_version=values["policy_version"],
        effective_permissions=list_values["effective_permissions"],
        scope=list_values["scope"],
        provider_ids=list_values["provider_ids"],
        approved_at=approved_at.isoformat(),
        expires_at=expires_at.isoformat(),
    )
    serialized = json.dumps(_manifest_metadata(decoded), ensure_ascii=False, sort_keys=True)
    if contains_secret(serialized) or RAW_STREAM_PATTERN.search(serialized) is not None:
        raise ActivationManifestError("activation manifest contains unsafe metadata")
    return decoded


def _manifest_metadata(manifest: ActivationManifest) -> dict[str, Any]:
    return {
        "version": 1,
        "manifest_id": manifest.manifest_id,
        "decision": manifest.decision,
        "requester": manifest.requester,
        "requester_role": manifest.requester_role,
        "approver": manifest.approver,
        "approver_role": manifest.approver_role,
        "policy_version": manifest.policy_version,
        "effective_permissions": list(manifest.effective_permissions),
        "scope": list(manifest.scope),
        "provider_ids": list(manifest.provider_ids),
        "approved_at": manifest.approved_at,
        "expires_at": manifest.expires_at,
    }


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ActivationManifestError("activation manifest timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ActivationManifestError("activation manifest timestamp must include timezone")
    return _as_utc(parsed)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ActivationManifestError("activation manifest time must include timezone")
    return value.astimezone(timezone.utc)


def _validate_manifest_path(path: Path) -> Path:
    if (
        not path.is_absolute()
        or path.suffix != ".json"
        or path.name in _PROTECTED_NAMES
        or path.is_symlink()
    ):
        raise ActivationManifestError("unsafe activation manifest path")
    if ".git" in path.parts or any(part.startswith(".env") for part in path.parts):
        raise ActivationManifestError("unsafe activation manifest path")
    if any(part.casefold() in {"logs", "backups"} for part in path.parts):
        raise ActivationManifestError("activation manifest cannot live in logs or backups")
    if not path.parent.exists() or not path.parent.is_dir():
        raise ActivationManifestError("activation manifest parent directory must exist")
    return path
