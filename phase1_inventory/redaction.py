"""Centralized redaction and secret scanning for inventory data."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

REDACTION_TOKEN = "[REDACTED]"

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "password_assignment": re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*[^\s,;]+"),
    "token_assignment": re.compile(r"(?i)(token|api[_-]?key|secret)\s*[:=]\s*[^\s,;]+"),
    "authorization_header": re.compile(r"(?i)authorization\s*:\s*[^\n\r]+"),
    "bearer_token": re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]{12,}"),
    "private_key_marker": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "url_credentials": re.compile(r"([a-z][a-z0-9+.-]*://)([^/@\s:]+):([^/@\s]+)@", re.IGNORECASE),
    "connection_string": re.compile(r"(?i)\b(postgres|postgresql|mysql|mongodb|redis)://[^\s]+"),
}


@dataclass(frozen=True)
class RedactionResult:
    value: Any
    rules: tuple[str, ...]
    fields_redacted: tuple[str, ...]


class SecretDetectedError(ValueError):
    pass


def redact_text(value: str) -> tuple[str, tuple[str, ...]]:
    redacted = value
    rules: list[str] = []
    for name, pattern in SECRET_PATTERNS.items():
        if pattern.search(redacted):
            rules.append(name)
            if name == "url_credentials":
                redacted = pattern.sub(r"\1[REDACTED]@", redacted)
            else:
                redacted = pattern.sub(REDACTION_TOKEN, redacted)
    return redacted, tuple(rules)


def redact(value: Any, path: str = "$") -> RedactionResult:
    rules: list[str] = []
    fields: list[str] = []

    def walk(item: Any, item_path: str) -> Any:
        if isinstance(item, str):
            redacted, item_rules = redact_text(item)
            if item_rules:
                rules.extend(item_rules)
                fields.append(item_path)
            return redacted
        if isinstance(item, list):
            return [walk(child, f"{item_path}[{index}]") for index, child in enumerate(item)]
        if isinstance(item, dict):
            return {key: walk(child, f"{item_path}.{key}") for key, child in item.items()}
        return item

    return RedactionResult(walk(value, path), tuple(sorted(set(rules))), tuple(fields))


def scan_for_secrets(value: Any) -> None:
    serialized = json.dumps(value, sort_keys=True, ensure_ascii=False)
    hits = [name for name, pattern in SECRET_PATTERNS.items() if pattern.search(serialized)]
    if hits:
        raise SecretDetectedError("Possible secret detected: " + ", ".join(sorted(hits)))


def merge_rules(*groups: Iterable[str]) -> list[str]:
    merged: set[str] = set()
    for group in groups:
        merged.update(group)
    return sorted(merged)
