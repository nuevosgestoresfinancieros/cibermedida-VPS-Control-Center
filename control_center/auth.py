"""In-memory authentication, sessions, roles, permissions and CSRF tokens."""

from __future__ import annotations

import hashlib
import hmac
import base64
import fcntl
import json
import os
import re
import secrets
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterator, Mapping, Protocol


class AuthenticationError(ValueError):
    pass


class AuthorizationError(PermissionError):
    pass


class RateLimitError(AuthenticationError):
    pass


class CSRFError(PermissionError):
    pass


class Role(str, Enum):
    ADMIN = "ADMIN"
    OPERATOR = "OPERATOR"
    DEVELOPER = "DEVELOPER"
    VIEWER = "VIEWER"


class Permission(str, Enum):
    VIEW_DASHBOARD = "VIEW_DASHBOARD"
    VIEW_CORE_OPERATOR = "VIEW_CORE_OPERATOR"
    VIEW_POLICY = "VIEW_POLICY"
    VIEW_AUDIT_METADATA = "VIEW_AUDIT_METADATA"
    VIEW_INVENTORY_METADATA = "VIEW_INVENTORY_METADATA"
    VIEW_SERVER = "VIEW_SERVER"
    VIEW_PROJECTS = "VIEW_PROJECTS"
    VIEW_SERVICES = "VIEW_SERVICES"
    VIEW_LOGS = "VIEW_LOGS"
    VIEW_BACKUPS = "VIEW_BACKUPS"
    VIEW_INCIDENTS = "VIEW_INCIDENTS"
    VIEW_MONITORING = "VIEW_MONITORING"
    REQUEST_APPROVAL = "REQUEST_APPROVAL"
    APPROVE_OPERATION = "APPROVE_OPERATION"
    RUN_READ_SAFE = "RUN_READ_SAFE"
    RUN_READ_SENSITIVE = "RUN_READ_SENSITIVE"
    RUN_PRIVILEGED = "RUN_PRIVILEGED"
    RUN_DIAGNOSTICS = "RUN_DIAGNOSTICS"
    RUN_TESTS = "RUN_TESTS"
    RUN_BUILDS = "RUN_BUILDS"
    CREATE_BRANCH = "CREATE_BRANCH"
    MODIFY_CODE = "MODIFY_CODE"
    CREATE_BACKUP = "CREATE_BACKUP"
    DEPLOY = "DEPLOY"
    ROLLBACK = "ROLLBACK"
    MANAGE_SECURITY = "MANAGE_SECURITY"
    MANAGE_USERS = "MANAGE_USERS"
    MANAGE_POLICIES = "MANAGE_POLICIES"


VIEW_PERMISSIONS = frozenset(
    {
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_CORE_OPERATOR,
        Permission.VIEW_POLICY,
        Permission.VIEW_AUDIT_METADATA,
        Permission.VIEW_INVENTORY_METADATA,
        Permission.VIEW_SERVER,
        Permission.VIEW_PROJECTS,
        Permission.VIEW_SERVICES,
        Permission.VIEW_BACKUPS,
        Permission.VIEW_INCIDENTS,
        Permission.VIEW_MONITORING,
    }
)

ROLE_PERMISSIONS = {
    Role.VIEWER: VIEW_PERMISSIONS,
    Role.DEVELOPER: VIEW_PERMISSIONS
    | frozenset(
        {
            Permission.REQUEST_APPROVAL,
            Permission.RUN_READ_SAFE,
            Permission.RUN_TESTS,
            Permission.RUN_BUILDS,
            Permission.CREATE_BRANCH,
            Permission.VIEW_LOGS,
        }
    ),
    Role.OPERATOR: VIEW_PERMISSIONS
    | frozenset(
        {
            Permission.REQUEST_APPROVAL,
            Permission.APPROVE_OPERATION,
            Permission.RUN_READ_SAFE,
            Permission.RUN_READ_SENSITIVE,
            Permission.RUN_PRIVILEGED,
            Permission.RUN_DIAGNOSTICS,
            Permission.RUN_TESTS,
            Permission.RUN_BUILDS,
            Permission.CREATE_BACKUP,
            Permission.DEPLOY,
            Permission.ROLLBACK,
            Permission.VIEW_LOGS,
        }
    ),
    Role.ADMIN: frozenset(Permission),
}

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
PBKDF2_ROUNDS = 310_000


@dataclass(frozen=True)
class User:
    user_id: str
    username: str
    role: Role
    password_salt: bytes
    password_hash: bytes
    enabled: bool = True
    requires_2fa: bool = False

    @property
    def permissions(self) -> frozenset[Permission]:
        return ROLE_PERMISSIONS[self.role]


class UserStore(Protocol):
    """Persistence boundary for password hashes, never plaintext passwords."""

    def load(self) -> Mapping[str, User]:
        ...

    def save(self, users: Mapping[str, User]) -> None:
        ...


class TotpVerifier:
    """Validate RFC 6238-style TOTP codes from explicitly injected secrets.

    Secrets remain in process memory only. The verifier does not discover,
    read, or persist seed material; provisioning belongs to a separate
    trusted identity workflow.
    """

    def __init__(
        self,
        secrets_by_user: Mapping[str, str],
        *,
        clock: Callable[[], float] | None = None,
        period_seconds: int = 30,
        digits: int = 6,
        allowed_steps: int = 1,
    ) -> None:
        if period_seconds <= 0 or digits not in {6, 8} or allowed_steps < 0 or allowed_steps > 2:
            raise ValueError("invalid TOTP parameters")
        self._secrets = {
            str(user_id): _decode_totp_secret(secret)
            for user_id, secret in secrets_by_user.items()
        }
        self.clock = clock or time.time
        self.period_seconds = period_seconds
        self.digits = digits
        self.allowed_steps = allowed_steps

    def register_secret(self, user_id: str, secret: str) -> None:
        """Inject one explicitly provisioned seed without persisting it.

        The caller owns the provisioning workflow. This method only decodes a
        supplied seed into process memory so a long-running application can
        bootstrap an already-created identity without accepting secrets in
        command-line arguments or writing them to disk.
        """

        self._secrets[str(user_id)] = _decode_totp_secret(secret)

    def __call__(self, user: "User", otp: str) -> bool:
        secret = self._secrets.get(user.user_id)
        if secret is None or not isinstance(otp, str) or not re.fullmatch(rf"\d{{{self.digits}}}", otp):
            return False
        counter = int(self.clock() // self.period_seconds)
        for offset in range(-self.allowed_steps, self.allowed_steps + 1):
            candidate = _totp_code(secret, counter + offset, self.digits)
            if hmac.compare_digest(candidate, otp):
                return True
        return False


class JsonUserStore:
    """Explicit JSON identity store containing only salted password hashes.

    The store is opt-in and refuses unsafe or ambiguous paths. It is suitable
    for a single-process laboratory deployment; a production installation
    still needs a reviewed identity service, file ownership and backup policy.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = _validate_state_path(Path(path), suffix=".json")

    def load(self) -> Mapping[str, User]:
        if not self.path.exists():
            return {}
        if self.path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("identity store is too large")
        try:
            with _identity_path_lock(self.path, exclusive=False):
                with self.path.open("r", encoding="utf-8") as handle:
                    payload = json.load(handle)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("identity store cannot be loaded") from exc
        if not isinstance(payload, dict) or payload.get("version") != 1 or not isinstance(payload.get("users"), list):
            raise ValueError("identity store format is invalid")
        users: dict[str, User] = {}
        usernames: set[str] = set()
        for entry in payload["users"]:
            user = self._decode_user(entry)
            if user.user_id in users or user.username in usernames:
                raise ValueError("identity store contains duplicates")
            users[user.user_id] = user
            usernames.add(user.username)
        return users

    def save(self, users: Mapping[str, User]) -> None:
        if not self.path.parent.exists() or not self.path.parent.is_dir():
            raise ValueError("identity store parent directory must exist")
        entries = [self._encode_user(user) for user in sorted(users.values(), key=lambda item: item.user_id)]
        payload = json.dumps({"version": 1, "users": entries}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        temporary_path: str | None = None
        try:
            with _identity_path_lock(self.path, exclusive=True):
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
                    handle.write(payload)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary_path, self.path)
                temporary_path = None
                os.chmod(self.path, 0o600)
        except OSError as exc:
            raise ValueError("identity store cannot be saved") from exc
        finally:
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except FileNotFoundError:
                    pass

    @staticmethod
    def _encode_user(user: User) -> dict[str, object]:
        return {
            "user_id": user.user_id,
            "username": user.username,
            "role": user.role.value,
            "password_salt": base64.b64encode(user.password_salt).decode("ascii"),
            "password_hash": base64.b64encode(user.password_hash).decode("ascii"),
            "enabled": user.enabled,
            "requires_2fa": user.requires_2fa,
        }

    @staticmethod
    def _decode_user(entry: object) -> User:
        if not isinstance(entry, dict):
            raise ValueError("identity record is invalid")
        try:
            user_id = entry["user_id"]
            username = entry["username"]
            role = Role(entry["role"])
            salt = base64.b64decode(entry["password_salt"], validate=True)
            password_hash = base64.b64decode(entry["password_hash"], validate=True)
            enabled = entry["enabled"]
            requires_2fa = entry["requires_2fa"]
        except (KeyError, TypeError, ValueError, base64.binascii.Error) as exc:
            raise ValueError("identity record is invalid") from exc
        if (
            not isinstance(user_id, str)
            or not isinstance(username, str)
            or not USERNAME_PATTERN.fullmatch(username)
            or not isinstance(enabled, bool)
            or not isinstance(requires_2fa, bool)
            or len(salt) < 16
            or len(password_hash) < 32
        ):
            raise ValueError("identity record fields are invalid")
        return User(
            user_id=user_id,
            username=username,
            role=role,
            password_salt=salt,
            password_hash=password_hash,
            enabled=enabled,
            requires_2fa=requires_2fa,
        )


@dataclass(frozen=True)
class Session:
    session_id: str
    user_id: str
    csrf_token: str
    created_at: float
    expires_at: float


class AuthService:
    """Authentication service with an explicit, optional identity store.

    Without a store users and sessions remain in memory. No default account
    is created; production identity storage still requires a separate review.
    """

    def __init__(
        self,
        *,
        user_store: UserStore | None = None,
        clock: Callable[[], float] | None = None,
        session_ttl_seconds: int = 1800,
        max_failed_attempts: int = 5,
        attempt_window_seconds: int = 300,
        otp_verifier: Callable[[User, str], bool] | None = None,
    ) -> None:
        self.clock = clock or time.time
        self.session_ttl_seconds = session_ttl_seconds
        self.max_failed_attempts = max_failed_attempts
        self.attempt_window_seconds = attempt_window_seconds
        self.otp_verifier = otp_verifier
        self.user_store = user_store
        self._users: dict[str, User] = dict(user_store.load()) if user_store is not None else {}
        self._sessions: dict[str, Session] = {}
        self._failed_attempts: dict[str, list[float]] = {}

    def register_user(
        self,
        *,
        user_id: str,
        username: str,
        password: str,
        role: Role,
        requires_2fa: bool = False,
    ) -> User:
        if not USERNAME_PATTERN.fullmatch(username):
            raise ValueError("invalid username")
        if len(password) < 12:
            raise ValueError("password must contain at least 12 characters")
        if user_id in self._users or any(user.username == username for user in self._users.values()):
            raise ValueError("user already exists")
        salt = secrets.token_bytes(16)
        user = User(
            user_id=user_id,
            username=username,
            role=role,
            password_salt=salt,
            password_hash=_hash_password(password, salt),
            requires_2fa=requires_2fa,
        )
        updated_users = dict(self._users)
        updated_users[user_id] = user
        if self.user_store is not None:
            self.user_store.save(updated_users)
        self._users = updated_users
        return user

    def has_username(self, username: str) -> bool:
        """Return whether an enabled or disabled identity already exists."""

        return any(user.username == username for user in self._users.values())

    @property
    def users(self) -> tuple[User, ...]:
        """Return identity metadata for internal readiness checks only."""

        return tuple(self._users.values())

    def user_for_username(self, username: str) -> User | None:
        """Return an identity for explicit bootstrap/provisioning checks."""

        return next((user for user in self._users.values() if user.username == username), None)

    def login(self, *, username: str, password: str, otp: str | None = None) -> Session:
        now = self.clock()
        self._prune_attempts(username, now)
        if len(self._failed_attempts.get(username, [])) >= self.max_failed_attempts:
            raise RateLimitError("too many authentication attempts")
        user = next((candidate for candidate in self._users.values() if candidate.username == username), None)
        valid = user is not None and user.enabled and _verify_password(password, user.password_hash, user.password_salt)
        if not valid:
            self._failed_attempts.setdefault(username, []).append(now)
            raise AuthenticationError("invalid credentials")
        if user.requires_2fa:
            if self.otp_verifier is None or otp is None or not self.otp_verifier(user, otp):
                raise AuthenticationError("second factor required")
        self._failed_attempts.pop(username, None)
        session = Session(
            session_id=secrets.token_urlsafe(32),
            user_id=user.user_id,
            csrf_token=secrets.token_urlsafe(24),
            created_at=now,
            expires_at=now + self.session_ttl_seconds,
        )
        self._sessions[session.session_id] = session
        return session

    def user_for_session(self, session_id: str) -> User:
        session = self._sessions.get(session_id)
        if session is None or session.expires_at <= self.clock():
            if session is not None:
                self._sessions.pop(session_id, None)
            raise AuthenticationError("session is missing or expired")
        try:
            user = self._users[session.user_id]
        except KeyError as exc:
            raise AuthenticationError("session user is missing") from exc
        if not user.enabled:
            raise AuthenticationError("user is disabled")
        return user

    def session_for(self, session_id: str) -> Session:
        self.user_for_session(session_id)
        return self._sessions[session_id]

    def logout(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def require(self, session_id: str, permission: Permission) -> User:
        user = self.user_for_session(session_id)
        if permission not in user.permissions:
            raise AuthorizationError("permission denied")
        return user

    def require_csrf(self, session_id: str, csrf_token: str | None) -> User:
        user = self.user_for_session(session_id)
        session = self._sessions[session_id]
        if csrf_token is None or not hmac.compare_digest(session.csrf_token, csrf_token):
            raise CSRFError("invalid csrf token")
        return user

    @staticmethod
    def cookie_header(session: Session, *, secure: bool = True) -> str:
        flags = [
            f"cc_session={session.session_id}",
            "Path=/",
            "HttpOnly",
            "SameSite=Strict",
            f"Max-Age={max(0, int(session.expires_at - session.created_at))}",
        ]
        if secure:
            flags.append("Secure")
        return "; ".join(flags)

    def _prune_attempts(self, username: str, now: float) -> None:
        cutoff = now - self.attempt_window_seconds
        attempts = [timestamp for timestamp in self._failed_attempts.get(username, []) if timestamp >= cutoff]
        if attempts:
            self._failed_attempts[username] = attempts
        else:
            self._failed_attempts.pop(username, None)


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)


def _verify_password(password: str, expected: bytes, salt: bytes) -> bool:
    return hmac.compare_digest(_hash_password(password, salt), expected)


def _decode_totp_secret(value: str) -> bytes:
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        raise ValueError("invalid TOTP secret")
    normalized = "".join(value.split()).upper()
    try:
        decoded = base64.b32decode(normalized + "=" * ((8 - len(normalized) % 8) % 8), casefold=True)
    except (base64.binascii.Error, ValueError) as exc:
        raise ValueError("invalid TOTP secret") from exc
    if len(decoded) < 10:
        raise ValueError("TOTP secret is too short")
    return decoded


def _totp_code(secret: bytes, counter: int, digits: int) -> str:
    if counter < 0:
        return "0" * digits
    message = counter.to_bytes(8, "big")
    digest = hmac.new(secret, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def _validate_state_path(path: Path, *, suffix: str) -> Path:
    if not path.is_absolute() or path.suffix != suffix or path.name in {".env", "INVENTORY.json", "AGENTS.md"}:
        raise ValueError("unsafe state path")
    if ".git" in path.parts or any(part.startswith(".env") for part in path.parts):
        raise ValueError("unsafe state path")
    if path.is_symlink() or (path.parent.exists() and not path.parent.is_dir()):
        raise ValueError("state path parent is not a directory")
    return path


@contextmanager
def _identity_path_lock(path: Path, *, exclusive: bool) -> Iterator[None]:
    """Coordinate identity snapshots across application processes."""

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
        raise ValueError("identity store lock cannot be acquired") from exc
