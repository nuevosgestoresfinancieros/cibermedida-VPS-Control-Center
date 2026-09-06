"""Deterministic local Supervisor/Planner for safe conversational workflows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol
from uuid import uuid4

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret
from core_operator.safe_logging import redact_text

from .audit import MetadataAuditLog
from .auth import AuthService, Permission
from .state import JsonMetadataStore


@dataclass(frozen=True)
class ChatMessage:
    message_id: str
    user_id: str
    role: str
    content: str
    timestamp: str


@dataclass(frozen=True)
class ConversationResult:
    message_id: str
    intent: str
    risk: str
    requires_approval: bool
    executable: bool
    response: str
    plan: tuple[str, ...]


@dataclass(frozen=True)
class ProviderChatResult:
    intent: str
    risk: str
    requires_approval: bool
    response: str
    plan: tuple[str, ...]


class ChatProvider(Protocol):
    name: str

    def generate(self, *, message: str, role: str) -> ProviderChatResult:
        """Return a structured proposal; it must never authorize execution."""


class ConversationService:
    def __init__(
        self,
        *,
        auth: AuthService,
        audit: MetadataAuditLog,
        provider: ChatProvider | None = None,
        ai_enabled: bool = False,
        state_store: JsonMetadataStore | None = None,
    ) -> None:
        self.auth = auth
        self.audit = audit
        self.provider = provider
        self.ai_enabled = ai_enabled
        self.state_store = state_store
        self._messages: list[ChatMessage] = []
        if self.state_store is not None:
            for raw_message in self.state_store.load():
                self._messages.append(_decode_message(raw_message))

    @property
    def messages(self) -> tuple[ChatMessage, ...]:
        return tuple(self._messages)

    def handle(self, *, session_id: str, message: str) -> ConversationResult:
        user = self.auth.require(session_id, Permission.VIEW_DASHBOARD)
        safe_message = redact_text(message).strip()
        if not safe_message or len(safe_message) > 4000:
            raise ValueError("message is empty or too long")
        user_message = ChatMessage(
            message_id=str(uuid4()),
            user_id=user.user_id,
            role="user",
            content=safe_message,
            timestamp=_now(),
        )
        result, source = self._plan(safe_message, user.role.value)
        assistant_message = ChatMessage(
            message_id=result.message_id,
            user_id=user.user_id,
            role="assistant",
            content=result.response,
            timestamp=_now(),
        )
        updated_messages = [*self._messages, user_message, assistant_message]
        self._persist(updated_messages)
        self._messages = updated_messages
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            action="conversation_planned",
            risk=result.risk,
            authorization="permission:VIEW_DASHBOARD",
            result="approval_required" if result.requires_approval else "read_only",
            metadata={"intent": result.intent, "executable": result.executable, "source": source},
        )
        return result

    def _plan(self, message: str, role: str) -> tuple[ConversationResult, str]:
        if not self.ai_enabled or self.provider is None:
            return _plan_message(message), "local_planner"
        try:
            proposed = self.provider.generate(message=message, role=role)
            return _validated_provider_result(proposed), f"provider:{self.provider.name}"
        except Exception:
            fallback = _plan_message(message)
            return fallback, "local_fallback_after_provider_failure"

    def _persist(self, messages: list[ChatMessage]) -> None:
        if self.state_store is not None:
            self.state_store.save(_encode_message(message) for message in messages)


def _plan_message(message: str) -> ConversationResult:
    normalized = message.casefold()
    message_id = str(uuid4())
    high_risk_terms = ("deploy", "desplieg", "rollback", "revert", "reinicia", "restart", "borra", "delete")
    diagnosis_terms = ("diagnost", "analiza", "error", "lento", "incidente", "problema")
    status_terms = ("estado", "cómo está", "como esta", "status", "salud")
    if any(term in normalized for term in high_risk_terms):
        return ConversationResult(
            message_id=message_id,
            intent="controlled_operation_request",
            risk="HIGH",
            requires_approval=True,
            executable=False,
            response="He preparado una intención de operación, pero no se ejecuta. Requiere política, backup, autorización y validación.",
            plan=("interpretar", "analizar impacto", "evaluar riesgo", "comprobar backup", "solicitar autorización", "bloquear ejecución real"),
        )
    if any(term in normalized for term in diagnosis_terms):
        return ConversationResult(
            message_id=message_id,
            intent="diagnosis_read_only",
            risk="LOW",
            requires_approval=False,
            executable=False,
            response="Puedo preparar un diagnóstico read-only, pero esta versión solo trabaja con metadatos autorizados y no lee logs reales.",
            plan=("observar", "recopilar metadatos autorizados", "correlacionar", "formular hipótesis", "proponer siguiente paso"),
        )
    if any(term in normalized for term in status_terms):
        return ConversationResult(
            message_id=message_id,
            intent="status_read_only",
            risk="LOW",
            requires_approval=False,
            executable=False,
            response="El Control Center está protegido: API local, datos mock, auditoría de metadatos y ejecución real bloqueada.",
            plan=("consultar estado seguro", "mostrar política", "mostrar límites", "no ejecutar"),
        )
    return ConversationResult(
        message_id=message_id,
        intent="unsupported_request",
        risk="MEDIUM",
        requires_approval=True,
        executable=False,
        response="La solicitud no tiene un flujo seguro definido todavía. No se ejecuta ninguna acción.",
        plan=("aclarar intención", "definir política", "solicitar autorización si aplica", "no ejecutar"),
    )


def _validated_provider_result(value: object) -> ConversationResult:
    if not isinstance(value, ProviderChatResult):
        raise ValueError("chat provider response has an invalid shape")
    fields = (value.intent, value.risk, value.response, *value.plan)
    if (
        not isinstance(value.plan, tuple)
        or not value.plan
        or any(not isinstance(item, str) or not item.strip() or len(item) > 512 for item in fields)
        or any(contains_secret(item) or RAW_STREAM_PATTERN.search(item) for item in fields)
        or not isinstance(value.requires_approval, bool)
    ):
        raise ValueError("chat provider response contains unsafe metadata")
    return ConversationResult(
        message_id=str(uuid4()),
        intent=value.intent,
        risk=value.risk.upper(),
        requires_approval=True if value.risk.upper() in {"HIGH", "CRITICAL"} else value.requires_approval,
        executable=False,
        response=redact_text(value.response),
        plan=tuple(redact_text(item) for item in value.plan),
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _encode_message(message: ChatMessage) -> dict[str, object]:
    return {
        "message_id": message.message_id,
        "user_id": message.user_id,
        "role": message.role,
        "content": message.content,
        "timestamp": message.timestamp,
    }


def _decode_message(value: dict[str, object]) -> ChatMessage:
    fields = ("message_id", "user_id", "role", "content", "timestamp")
    if any(not isinstance(value.get(field), str) or not value[field].strip() for field in fields):
        raise ValueError("conversation state record is invalid")
    role = value["role"]
    if role not in {"user", "assistant"}:
        raise ValueError("conversation state role is invalid")
    content = value["content"]
    if (
        contains_secret(content)
        or RAW_STREAM_PATTERN.search(content)
        or len(content) > 4000
        or any(ord(character) < 32 and character not in {"\n", "\t"} for character in content)
    ):
        raise ValueError("conversation state contains unsafe content")
    return ChatMessage(
        message_id=value["message_id"],
        user_id=value["user_id"],
        role=role,
        content=content,
        timestamp=value["timestamp"],
    )
