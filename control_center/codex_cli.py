"""Read-only Codex CLI provider with a declared project boundary.

The provider is opt-in and uses Codex's read-only sandbox.  It accepts only a
named project from an explicit mapping, asks for bounded JSON metadata, and
never exposes CLI output through the API or audit log.  A failed or ambiguous
CLI response is rejected closed.
"""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret

from .codex import CodexEvidence


MAX_CLI_OUTPUT_BYTES = 1_048_576
MAX_FINDINGS = 64
REQUEST_KINDS = frozenset({"repository", "diagnosis", "impact"})
CodexRunner = Callable[[Sequence[str], Path, float], tuple[int, bytes, bytes]]


class CodexCliProvider:
    """Use an explicitly installed Codex CLI in a read-only sandbox."""

    name = "codex-provider"
    live_data = True

    def __init__(
        self,
        *,
        projects: Mapping[str, str | Path],
        executable: str = "codex",
        timeout_seconds: float = 300.0,
        runner: CodexRunner | None = None,
    ) -> None:
        if not projects or len(projects) > 32:
            raise ValueError("at least one and at most thirty-two Codex projects are required")
        if not isinstance(executable, str) or not executable.strip() or "/" in executable or "\\" in executable:
            raise ValueError("Codex executable must be a command name")
        if timeout_seconds <= 0 or timeout_seconds > 1800:
            raise ValueError("Codex timeout is invalid")
        normalized: dict[str, Path] = {}
        for project, root in projects.items():
            key = _safe_text(project, "project")
            path = Path(root).resolve()
            if not path.is_absolute() or not path.is_dir() or path.is_symlink():
                raise ValueError("Codex project root must be an existing regular directory")
            normalized[key] = path
        self.projects = normalized
        self.executable = executable.strip()
        self.timeout_seconds = timeout_seconds
        self._runner = runner or _subprocess_runner

    def analyze(self, *, project: str, request_kind: str) -> CodexEvidence:
        project = _safe_text(project, "project")
        request_kind = _safe_text(request_kind, "request_kind")
        if request_kind not in REQUEST_KINDS:
            raise ValueError("unsupported Codex request kind")
        try:
            root = self.projects[project]
        except KeyError as exc:
            raise ValueError("Codex project is not declared") from exc
        prompt = (
            "Analiza el repositorio en modo estrictamente solo lectura. "
            "No edites archivos, no crees ramas, no ejecutes comandos operativos y no incluyas contenido de archivos. "
            "Devuelve un unico objeto JSON con las claves summary, findings, files_examined, changed_files y duration_ms. "
            f"Tipo de análisis: {request_kind}. findings debe ser una lista breve de etiquetas metadata-only."
        )
        argv = (
            self.executable,
            "exec",
            "--sandbox",
            "read-only",
            "--ask-for-approval",
            "never",
            "--json",
            prompt,
        )
        started = time.monotonic()
        return_code, raw_stdout, raw_stderr = self._runner(argv, root, self.timeout_seconds)
        duration_ms = min(1_800_000, max(0, int((time.monotonic() - started) * 1000)))
        if return_code != 0 or not isinstance(raw_stdout, bytes) or not isinstance(raw_stderr, bytes):
            raise ValueError("Codex CLI failed")
        if len(raw_stdout) > MAX_CLI_OUTPUT_BYTES or len(raw_stderr) > MAX_CLI_OUTPUT_BYTES:
            raise ValueError("Codex CLI output is too large")
        stdout_text = raw_stdout.decode("utf-8", errors="replace")
        stderr_text = raw_stderr.decode("utf-8", errors="replace")
        if contains_secret(stdout_text) or contains_secret(stderr_text):
            raise ValueError("Codex CLI output contains secret-like data")
        payload = _find_metadata_payload(stdout_text)
        if payload is None:
            raise ValueError("Codex CLI did not return bounded metadata")
        summary = _safe_text(payload.get("summary"), "summary")
        findings = payload.get("findings")
        if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
            raise ValueError("Codex findings are invalid")
        normalized_findings = tuple(_safe_text(item, "finding") for item in findings)
        files_examined = _bounded_integer(payload.get("files_examined"), 100_000)
        changed_files = _bounded_integer(payload.get("changed_files"), 0)
        reported_duration = _bounded_integer(payload.get("duration_ms"), 1_800_000)
        return CodexEvidence(
            provider=self.name,
            project=project,
            request_kind=request_kind,
            summary=summary,
            findings=normalized_findings,
            files_examined=files_examined,
            changed_files=changed_files,
            duration_ms=max(duration_ms, reported_duration),
        )


def _subprocess_runner(argv: Sequence[str], cwd: Path, timeout: float) -> tuple[int, bytes, bytes]:
    try:
        completed = subprocess.run(
            tuple(argv),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Codex CLI could not be invoked") from exc
    return completed.returncode, completed.stdout, completed.stderr


def _find_metadata_payload(text: str) -> dict[str, object] | None:
    if not isinstance(text, str) or not text.strip():
        return None
    candidates = [text.strip()]
    candidates.extend(line.strip() for line in text.splitlines() if line.strip())
    for candidate in reversed(candidates):
        try:
            value = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            continue
        payload = _find_metadata_value(value, depth=0)
        if payload is not None:
            return payload
    return None


_METADATA_KEYS = frozenset({"summary", "findings", "files_examined", "changed_files", "duration_ms"})


def _find_metadata_value(value: object, *, depth: int) -> dict[str, object] | None:
    """Extract only the bounded final metadata object from JSON or JSONL output."""

    if depth > 6:
        return None
    if isinstance(value, dict):
        if _METADATA_KEYS <= set(value):
            return value
        for child in value.values():
            found = _find_metadata_value(child, depth=depth + 1)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in reversed(value):
            found = _find_metadata_value(child, depth=depth + 1)
            if found is not None:
                return found
    elif isinstance(value, str) and len(value) <= MAX_CLI_OUTPUT_BYTES:
        stripped = value.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                return _find_metadata_value(json.loads(stripped), depth=depth + 1)
            except (json.JSONDecodeError, TypeError):
                return None
    return None


def _bounded_integer(value: object, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > maximum:
        raise ValueError("Codex numeric metadata is invalid")
    return value


def _safe_text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 512
        or contains_secret(value)
        or RAW_STREAM_PATTERN.search(value)
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"Codex {label} is unsafe")
    return value.strip()
