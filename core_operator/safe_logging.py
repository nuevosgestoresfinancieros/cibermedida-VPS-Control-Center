"""Structured in-memory logging with conservative redaction."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s,;]+"),
    re.compile(r"(?i)(password|passwd|pwd|token|api[_-]?key|secret)\s*[:=]\s*[^,\s;]+"),
    re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^:/\s]+:)[^@\s]+(@)"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
)

REDACTION = "[REDACTED]"


@dataclass(frozen=True)
class LogRecord:
    timestamp: str
    level: str
    message: str
    fields: Mapping[str, Any] = field(default_factory=dict)


def redact_text(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        if pattern.pattern.startswith("([a-zA-Z]"):
            redacted = pattern.sub(r"\1" + REDACTION + r"\2", redacted)
        elif pattern.pattern.startswith("(?i)(authorization"):
            redacted = pattern.sub(r"\1" + REDACTION, redacted)
        elif "PRIVATE KEY" in pattern.pattern:
            redacted = pattern.sub(REDACTION, redacted)
        else:
            redacted = pattern.sub(lambda match: match.group(1) + "=" + REDACTION, redacted)
    return redacted


def sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {str(key): sanitize(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return tuple(sanitize(child) for child in value)
    if isinstance(value, list):
        return [sanitize(child) for child in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_text(repr(value))


class InMemoryStructuredLogger:
    def __init__(self) -> None:
        self._records: list[LogRecord] = []

    @property
    def records(self) -> tuple[LogRecord, ...]:
        return tuple(self._records)

    def log(self, level: str, message: str, **fields: Any) -> LogRecord:
        record = LogRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=level.upper(),
            message=redact_text(message),
            fields=sanitize(fields),
        )
        self._records.append(record)
        return record
