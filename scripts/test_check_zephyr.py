# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Regression checks for bounded west execution and success-marker handling."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).with_name("check_zephyr.py")
SPEC = importlib.util.spec_from_file_location("check_zephyr", SCRIPT)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class WestRunnerTests(unittest.TestCase):
    def run_python(self, code, timeout=2):
        with tempfile.TemporaryDirectory() as temp:
            return RUNNER.run_command([sys.executable, "-c", code], os.environ.copy(),
                                      Path(temp) / "run.log", timeout, True)

    def test_successful_idle_firmware_is_stopped(self):
        start = time.monotonic()
        self.assertTrue(self.run_python(
            "import time; print('PROJECT EXECUTION SUCCESSFUL', flush=True); time.sleep(30)"))
        self.assertLess(time.monotonic() - start, 4)

    def test_failure_wins_over_success(self):
        self.assertFalse(self.run_python(
            "print('PROJECT EXECUTION SUCCESSFUL'); print('PROJECT EXECUTION FAILED')"))

    def test_missing_or_embedded_marker_fails(self):
        self.assertFalse(self.run_python("print('no ztest summary')"))
        self.assertFalse(self.run_python("print('example: PROJECT EXECUTION SUCCESSFUL')"))

    def test_crashed_runner_fails_even_with_marker(self):
        self.assertFalse(self.run_python(
            "import sys; print('PROJECT EXECUTION SUCCESSFUL'); sys.exit(1)"))

    def test_timeout_is_not_a_pass(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_python("import time; time.sleep(30)", timeout=0.2)

    def test_cli_cleans_host_flags_and_runs_selected_suite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            west = root / "west"
            west.write_text("#!" + sys.executable + "\n"
                            "import os, sys\n"
                            "assert 'CPATH' not in os.environ\n"
                            "assert 'CFLAGS' not in os.environ\n"
                            "if '-t' in sys.argv: print('PROJECT EXECUTION SUCCESSFUL')\n")
            west.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       CPATH="host-only-include", CFLAGS="host-only-flags")
            result = subprocess.run([sys.executable, str(SCRIPT), "--test",
                                     "deployment_campaign", "--output-root", str(root / "out")],
                                    env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PASS: deployment_campaign", result.stdout)
            self.assertEqual(len(list((root / "out").glob("*.log"))), 2)

    def test_invalid_timeout_fails(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--run-timeout", "0"],
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("timeouts must be positive", result.stderr)


if __name__ == "__main__":
    unittest.main()
