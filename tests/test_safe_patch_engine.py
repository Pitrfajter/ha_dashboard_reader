"""Safety tests for deterministic integration patch planning."""
import unittest
from safe_patch_engine import Replacement, digest, prepare_patch, validate_path


class SafePatchTests(unittest.TestCase):
    def test_plan_and_hash(self):
        source = "VALUE = 1\n"
        result = prepare_patch("custom_components/demo/sensor.py", source,
                               digest(source), [Replacement("VALUE = 1", "VALUE = 2")])
        self.assertTrue(result["changed"])
        self.assertEqual(result["after_sha256"], digest("VALUE = 2\n"))
        self.assertTrue(result["approval_required"])

    def test_hash_mismatch(self):
        with self.assertRaises(ValueError):
            prepare_patch("custom_components/demo/sensor.py", "x = 1", "0" * 64,
                          [Replacement("1", "2")])

    def test_ambiguous_context(self):
        source = "a = 1\nb = 1\n"
        with self.assertRaises(ValueError):
            prepare_patch("custom_components/demo/sensor.py", source, digest(source),
                          [Replacement("1", "2")])

    def test_syntax_failure(self):
        source = "x = 1\n"
        with self.assertRaises(SyntaxError):
            prepare_patch("custom_components/demo/sensor.py", source, digest(source),
                          [Replacement("x = 1", "def broken(")])

    def test_path_validation(self):
        for path in ("../../secrets.yaml", "custom_components/demo/../../secrets.yaml",
                     "config/secrets.yaml", "custom_components/demo/.storage",
                     "custom_components/demo/run.sh"):
            with self.assertRaises(ValueError):
                validate_path(path)


if __name__ == "__main__":
    unittest.main()
