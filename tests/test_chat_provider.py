from __future__ import annotations

import json
import unittest
from urllib.request import Request

from control_center.chat_provider import OpenAICompatibleChatProvider


class ChatProviderTests(unittest.TestCase):
    def test_openai_compatible_provider_decodes_structured_safe_plan(self) -> None:
        requests: list[Request] = []

        def transport(request: Request, _timeout: float) -> bytes:
            requests.append(request)
            return json.dumps(
                {
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {
                                        "intent": "status_read_only",
                                        "risk": "LOW",
                                        "requires_approval": False,
                                        "response": "Estado preparado como consulta segura.",
                                        "plan": ["consultar estado", "no ejecutar"],
                                    }
                                )
                            }
                        }
                    ]
                }
            ).encode("utf-8")

        provider = OpenAICompatibleChatProvider(
            endpoint="https://chat.example.test/v1/chat/completions",
            api_key="test-api-key",
            model="test-model",
            transport=transport,
        )
        result = provider.generate(message="¿Cuál es el estado?", role="VIEWER")
        self.assertEqual(result.intent, "status_read_only")
        self.assertFalse(result.requires_approval)
        self.assertEqual(requests[0].get_header("Authorization"), "Bearer test-api-key")
        self.assertNotIn("test-api-key", json.dumps(json.loads(requests[0].data.decode("utf-8"))))

    def test_provider_rejects_secret_like_model_output(self) -> None:
        def transport(_request: Request, _timeout: float) -> bytes:
            return json.dumps(
                {
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {
                                        "intent": "unsafe",
                                        "risk": "LOW",
                                        "requires_approval": False,
                                        "response": "password=must-not-pass",
                                        "plan": ["stop"],
                                    }
                                )
                            }
                        }
                    ]
                }
            ).encode("utf-8")

        provider = OpenAICompatibleChatProvider(
            endpoint="https://chat.example.test/v1/chat/completions",
            api_key="test-api-key",
            model="test-model",
            transport=transport,
        )
        with self.assertRaises(ValueError):
            provider.generate(message="status", role="VIEWER")

    def test_remote_http_endpoint_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            OpenAICompatibleChatProvider(
                endpoint="http://chat.example.test/v1/chat/completions",
                api_key="test-api-key",
                model="test-model",
            )


if __name__ == "__main__":
    unittest.main()
