"""Bounded OpenAI-compatible chat provider with fail-closed output parsing."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from core_operator.audit import RAW_STREAM_PATTERN, contains_secret

from .conversation import ProviderChatResult


MAX_RESPONSE_BYTES = 1_048_576
MAX_PLAN_ITEMS = 12


class OpenAICompatibleChatProvider:
    """Call a declared chat-completions endpoint without authorizing actions.

    The API key is supplied by the caller and held only in memory. The default
    CLI path prompts for it; this class never reads environment files, logs, or
    repository state.
    """

    name = "openai-compatible-chat"
    live_data = True

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str,
        model: str,
        timeout_seconds: float = 20.0,
        transport: Callable[[Request, float], bytes] | None = None,
    ) -> None:
        parsed = urlsplit(endpoint)
        if parsed.scheme not in {"https", "http"} or not parsed.netloc:
            raise ValueError("chat endpoint must be an absolute HTTP(S) URL")
        if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("remote chat endpoints must use HTTPS")
        if not isinstance(api_key, str) or not api_key.strip() or len(api_key) > 4096:
            raise ValueError("chat API key is invalid")
        if not isinstance(model, str) or not model.strip() or len(model) > 128:
            raise ValueError("chat model is invalid")
        if timeout_seconds <= 0 or timeout_seconds > 120:
            raise ValueError("chat timeout is invalid")
        self.endpoint = endpoint
        self._api_key = api_key.strip()
        self.model = model.strip()
        self.timeout_seconds = timeout_seconds
        self._transport = transport or _urlopen_transport

    def generate(self, *, message: str, role: str) -> ProviderChatResult:
        if not isinstance(message, str) or not message.strip() or len(message) > 4000:
            raise ValueError("chat message is invalid")
        if not isinstance(role, str) or not role.strip() or len(role) > 64:
            raise ValueError("chat role is invalid")
        body = json.dumps(
            {
                "model": self.model,
                "temperature": 0,
                "max_tokens": 800,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "Eres un planificador seguro de Cibermedida. Devuelve solo JSON con "
                            "intent, risk, requires_approval, response y plan. Nunca autorices, "
                            "ejecutes ni inventes comandos; toda modificación requiere aprobación."
                        ),
                    },
                    {"role": "user", "content": f"rol={role}; solicitud={message}"},
                ],
            },
            ensure_ascii=False,
        ).encode("utf-8")
        request = Request(
            self.endpoint,
            data=body,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            raw_response = self._transport(request, self.timeout_seconds)
            if not isinstance(raw_response, bytes) or len(raw_response) > MAX_RESPONSE_BYTES:
                raise ValueError("chat response is too large")
            envelope = json.loads(raw_response.decode("utf-8"))
            content = envelope["choices"][0]["message"]["content"]
            result = json.loads(content) if isinstance(content, str) else content
        except Exception as exc:
            raise ValueError("chat provider request or response was invalid") from exc
        return _decode_provider_result(result)


def _urlopen_transport(request: Request, timeout: float) -> bytes:
    with urlopen(request, timeout=timeout) as response:
        return response.read(MAX_RESPONSE_BYTES + 1)


def _decode_provider_result(value: object) -> ProviderChatResult:
    if not isinstance(value, dict):
        raise ValueError("chat provider result must be an object")
    try:
        intent = value["intent"]
        risk = value["risk"]
        requires_approval = value["requires_approval"]
        response = value["response"]
        plan = value["plan"]
    except KeyError as exc:
        raise ValueError("chat provider result is incomplete") from exc
    if not isinstance(intent, str) or not isinstance(risk, str) or risk.upper() not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise ValueError("chat provider result has invalid risk metadata")
    if not isinstance(requires_approval, bool) or not isinstance(response, str):
        raise ValueError("chat provider result has invalid fields")
    if not isinstance(plan, (list, tuple)) or not plan or len(plan) > MAX_PLAN_ITEMS:
        raise ValueError("chat provider plan is invalid")
    values = (intent, risk, response, *plan)
    if any(not isinstance(item, str) or not item.strip() or len(item) > 512 for item in values):
        raise ValueError("chat provider result contains invalid text")
    if any(contains_secret(item) or RAW_STREAM_PATTERN.search(item) for item in values):
        raise ValueError("chat provider result contains unsafe text")
    return ProviderChatResult(
        intent=intent,
        risk=risk.upper(),
        requires_approval=requires_approval,
        response=response,
        plan=tuple(plan),
    )
