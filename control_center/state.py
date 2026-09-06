"""Small, metadata-only JSON state store for explicitly enabled workflows."""

from __future__ import annotations

import json
import fcntl
import os
import tempfile
import threading
from contextlib import contextmanager
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Iterator

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret


MAX_STATE_BYTES = 16 * 1024 * 1024
_PROTECTED_NAMES = frozenset({".env", "AGENTS.md", "INVENTORY.json"})
_PROTECTED_KEYS = frozenset({
    "password",
    "password_hash",
    "password_salt",
    "secret",
    "token",
    "api_key",
    "credential",
    "stdout",
    "stderr",
})


class JsonMetadataStore:
    """Persist only JSON records that have passed metadata safety checks.

    This store is opt-in and intended for the single-process laboratory
    profile. It does not provide a database transaction or multi-process
    coordination; writes are atomic and serialized within this process.
    """

    def __init__(self, path: str | Path, *, max_bytes: int = MAX_STATE_BYTES) -> None:
        self.path = _validate_state_path(Path(path))
        if max_bytes < 4096 or max_bytes > MAX_STATE_BYTES:
            raise ValueError("state size limit is invalid")
        self.max_bytes = max_bytes
        self._lock = threading.Lock()

    def load(self) -> tuple[dict[str, Any], ...]:
        if not self.path.exists():
            return ()
        if self.path.stat().st_size > self.max_bytes:
            raise ValueError("state store is too large")
        try:
            with _state_path_lock(self.path, exclusive=False):
                with self.path.open("r", encoding="utf-8") as handle:
                    payload = json.load(handle)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("state store cannot be loaded") from exc
        records = _decode_payload(payload)
        return tuple(records)

    def save(self, records: Sequence[Mapping[str, Any]]) -> None:
        normalized = [dict(record) for record in records]
        payload = {"version": 1, "records": normalized}
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        encoded = (serialized + "\n").encode("utf-8")
        if len(encoded) > self.max_bytes or _unsafe_payload(payload):
            raise ValueError("state store rejected unsafe or oversized metadata")
        if not self.path.parent.exists() or not self.path.parent.is_dir():
            raise ValueError("state store parent directory must exist")
        temporary_path: str | None = None
        with self._lock:
            with _state_path_lock(self.path, exclusive=True):
                try:
                    with tempfile.NamedTemporaryFile(
                        mode="w",
                        encoding="utf-8",
                        dir=self.path.parent,
                        prefix=f".{self.path.name}.",
                        suffix=".tmp",
                        delete=False,
                    ) as handle:
                        temporary_path = handle.name
                        os.chmod(handle.name, 0o600)
                        handle.write(serialized)
                        handle.write("\n")
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(temporary_path, self.path)
                    temporary_path = None
                    os.chmod(self.path, 0o600)
                except OSError as exc:
                    raise ValueError("state store cannot be written") from exc
                finally:
                    if temporary_path is not None:
                        try:
                            os.unlink(temporary_path)
                        except FileNotFoundError:
                            pass


def _decode_payload(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or value.get("version") != 1 or not isinstance(value.get("records"), list):
        raise ValueError("state store format is invalid")
    if _unsafe_payload(value):
        raise ValueError("state store contains unsafe metadata")
    records: list[dict[str, Any]] = []
    for record in value["records"]:
        if not isinstance(record, dict):
            raise ValueError("state record must be an object")
        records.append(dict(record))
    return records


def _unsafe_payload(value: object, *, key: str | None = None) -> bool:
    if key is not None and key.casefold() in _PROTECTED_KEYS:
        return True
    if isinstance(value, Mapping):
        return any(
            _unsafe_payload(item, key=str(item_key))
            for item_key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_unsafe_payload(item) for item in value)
    if isinstance(value, str):
        return contains_secret(value) or RAW_STREAM_PATTERN.search(value) is not None
    return False


def _validate_state_path(path: Path) -> Path:
    if (
        not path.is_absolute()
        or path.suffix != ".json"
        or path.name in _PROTECTED_NAMES
        or path.is_symlink()
    ):
        raise ValueError("unsafe metadata state path")
    if ".git" in path.parts or any(part.startswith(".env") for part in path.parts):
        raise ValueError("unsafe metadata state path")
    if not path.parent.exists() or not path.parent.is_dir():
        raise ValueError("state path parent directory must exist")
    return path


@contextmanager
def _state_path_lock(path: Path, *, exclusive: bool) -> Iterator[None]:
    """Coordinate atomic state replacement across application processes."""

    lock_path = path.with_name(f".{path.name}.lock")
    try:
        with lock_path.open("a+", encoding="utf-8") as lock_handle:
            os.chmod(lock_path, 0o600)
            operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            fcntl.flock(lock_handle.fileno(), operation)
            try:
                yield
            finally:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
    except OSError as exc:
        raise ValueError("state store lock cannot be acquired") from exc
