import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api import readonly_server
from api.readonly_server import PROJECT_ROOT, parse_bootstrap_user, prepare_lab_environment, validate_state_root
from control_center.auth import JsonUserStore, Role


class LabModeTests(unittest.TestCase):
    def test_bootstrap_user_declaration_keeps_role_explicit(self) -> None:
        self.assertEqual(parse_bootstrap_user("operator:OPERATOR"), ("operator", Role.OPERATOR))
        self.assertEqual(parse_bootstrap_user("reviewer"), ("reviewer", Role.VIEWER))
        with self.assertRaises(ValueError):
            parse_bootstrap_user("operator user:OPERATOR")
        with self.assertRaises(ValueError):
            parse_bootstrap_user("operator:UNKNOWN")

    def test_state_root_requires_an_external_existing_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cibermedida-state-") as temporary_directory:
            root = Path(temporary_directory)
            self.assertEqual(validate_state_root(root), root.resolve())
            with self.assertRaises(ValueError):
                validate_state_root(PROJECT_ROOT)
            logs = root / "logs"
            logs.mkdir()
            with self.assertRaises(ValueError):
                validate_state_root(logs)

    def test_lab_profile_creates_only_declared_fixture_roots(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cibermedida-lab-test-") as temporary_directory:
            paths = prepare_lab_environment(Path(temporary_directory) / "profile")

            self.assertEqual(set(paths), {
                "root",
                "state_root",
                "backup_source_root",
                "backup_destination_root",
                "release_artifact_root",
                "release_root",
            })
            self.assertTrue((paths["backup_source_root"] / "README.txt").is_file())
            self.assertTrue((paths["release_artifact_root"] / "lab-commit" / "README.txt").is_file())
            self.assertTrue(paths["state_root"].is_dir())
            self.assertFalse(PROJECT_ROOT in paths["root"].parents)
            self.assertFalse(paths["root"] in PROJECT_ROOT.parents)

    def test_lab_profile_rejects_project_related_roots(self) -> None:
        with self.assertRaises(ValueError):
            prepare_lab_environment(PROJECT_ROOT)
        with self.assertRaises(ValueError):
            prepare_lab_environment(PROJECT_ROOT / "tmp-lab")
        with self.assertRaises(ValueError):
            prepare_lab_environment(Path("relative-lab"))


    def test_state_root_persists_bootstrap_user_outside_lab_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cibermedida-production-state-") as temporary_directory:
            state_root = Path(temporary_directory)

            class FakeServer:
                def serve_forever(self) -> None:
                    raise KeyboardInterrupt

                def server_close(self) -> None:
                    return None

            def capture_server(*_args, **_kwargs):
                return FakeServer()

            argv = [
                "readonly_server",
                "--state-root",
                str(state_root),
                "--bootstrap-username",
                "admin",
                "--bootstrap-role",
                "ADMIN",
            ]
            with patch("sys.argv", argv), patch(
                "api.readonly_server.getpass", return_value="admin-password-123"
            ), patch("api.readonly_server.create_server", side_effect=capture_server):
                readonly_server.main()

            users_path = state_root / "users.json"
            self.assertTrue(users_path.is_file())
            users = JsonUserStore(users_path).load()
            self.assertEqual(len(users), 1)
            user = next(iter(users.values()))
            self.assertEqual(user.username, "admin")
            self.assertEqual(user.role, Role.ADMIN)

if __name__ == "__main__":
    unittest.main()
