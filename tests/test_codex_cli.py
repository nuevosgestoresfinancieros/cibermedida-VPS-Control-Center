from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from control_center.codex_cli import CodexCliProvider


class CodexCliProviderTests(unittest.TestCase):
    def test_provider_uses_read_only_sandbox_and_bounded_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            calls: list[tuple[tuple[str, ...], Path, float]] = []

            def runner(argv, cwd, timeout):
                calls.append((tuple(argv), cwd, timeout))
                return (
                    0,
                    json.dumps(
                        {
                            "summary": "analysis completed",
                            "findings": ["tests_present", "human_review_required"],
                            "files_examined": 3,
                            "changed_files": 0,
                            "duration_ms": 4,
                        }
                    ).encode("utf-8"),
                    b"",
                )

            provider = CodexCliProvider(
                projects={"control-center": temporary_directory},
                runner=runner,
            )
            evidence = provider.analyze(project="control-center", request_kind="repository")

            self.assertEqual(evidence.provider, "codex-provider")
            self.assertEqual(evidence.changed_files, 0)
            self.assertEqual(len(calls), 1)
            argv, cwd, _timeout = calls[0]
            self.assertEqual(cwd, Path(temporary_directory).resolve())
            self.assertIn("--sandbox", argv)
            self.assertIn("read-only", argv)
            self.assertIn("--ask-for-approval", argv)
            self.assertIn("never", argv)

    def test_provider_rejects_changes_and_raw_secret_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            def changed_runner(_argv, _cwd, _timeout):
                return (
                    0,
                    b'{"summary":"changed","findings":[],"files_examined":1,"changed_files":1,"duration_ms":1}',
                    b"",
                )

            provider = CodexCliProvider(
                projects={"control-center": temporary_directory},
                runner=changed_runner,
            )
            with self.assertRaises(ValueError):
                provider.analyze(project="control-center", request_kind="impact")

            def secret_runner(_argv, _cwd, _timeout):
                return (
                    0,
                    b'{"summary":"password=should-not-escape","findings":[],"files_examined":0,"changed_files":0,"duration_ms":1}',
                    b"",
                )

            secret_provider = CodexCliProvider(
                projects={"control-center": temporary_directory},
                runner=secret_runner,
            )
            with self.assertRaises(ValueError):
                secret_provider.analyze(project="control-center", request_kind="diagnosis")

    def test_project_and_request_are_declared(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            provider = CodexCliProvider(
                projects={"control-center": temporary_directory},
                runner=lambda _argv, _cwd, _timeout: (1, b"", b""),
            )
            with self.assertRaises(ValueError):
                provider.analyze(project="other", request_kind="repository")
            with self.assertRaises(ValueError):
                provider.analyze(project="control-center", request_kind="write")

    def test_provider_accepts_nested_jsonl_metadata_without_persisting_raw_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            def runner(_argv, _cwd, _timeout):
                events = [
                    {"type": "thread.started", "thread_id": "metadata-only"},
                    {
                        "type": "item.completed",
                        "item": {
                            "type": "agent_message",
                            "text": json.dumps(
                                {
                                    "summary": "nested analysis",
                                    "findings": ["review_required"],
                                    "files_examined": 2,
                                    "changed_files": 0,
                                    "duration_ms": 3,
                                }
                            ),
                        },
                    },
                ]
                return 0, "\n".join(json.dumps(event) for event in events).encode(), b""

            provider = CodexCliProvider(
                projects={"control-center": temporary_directory},
                runner=runner,
            )
            evidence = provider.analyze(project="control-center", request_kind="repository")
            self.assertEqual(evidence.summary, "nested analysis")
            self.assertEqual(evidence.files_examined, 2)


if __name__ == "__main__":
    unittest.main()
