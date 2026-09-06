import tempfile
import unittest
from pathlib import Path

from api.readonly_server import PROJECT_ROOT, parse_bootstrap_user, prepare_lab_environment, validate_state_root
from control_center.auth import Role


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


if __name__ == "__main__":
    unittest.main()
