from __future__ import annotations

import unittest
from unittest.mock import patch

from core.backup import create_manifest, load_manifest, sha256_bytes
from core.runner import CommandResult, run
from core.policy import OptimizationPolicy, PolicyViolation, Risk


class BackupTests(unittest.TestCase):
    def test_sha256_is_stable(self):
        self.assertEqual(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad",
        )

    def test_manifest_contains_value_and_hash(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = create_manifest(Path(tmp), {"x": {"a": 1}})
            data = load_manifest(path)
            self.assertEqual(data["items"]["x"]["value"], {"a": 1})
            self.assertEqual(len(data["items"]["x"]["sha256"]), 64)


class PolicyTests(unittest.TestCase):
    def test_experimental_block(self):
        with self.assertRaises(PolicyViolation):
            OptimizationPolicy.check_risk(Risk.EXPERIMENTAL)

    def test_safe_is_allowed(self):
        OptimizationPolicy.check_risk(Risk.SAFE)


class RunnerTests(unittest.TestCase):
    @patch("core.runner.subprocess.run")
    def test_runner_does_not_use_shell(self, mocked):
        mocked.return_value = type(
            "R", (), {"returncode": 0, "stdout": "ok", "stderr": ""}
        )()
        result = run(["example.exe"])
        self.assertEqual(result, CommandResult(0, "ok", ""))
        self.assertFalse(mocked.call_args.kwargs["shell"])


if __name__ == "__main__":
    unittest.main()
