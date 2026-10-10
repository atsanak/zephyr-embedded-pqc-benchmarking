#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Build and run selected public ztests with bounded west commands."""

import argparse
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
TESTS = ("deployment_advisor", "deployment_campaign", "acvp_serial",
         "tls_selftest", "primitive")
HOST_FLAGS = ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH",
              "CFLAGS", "CXXFLAGS", "LDFLAGS", "SDKROOT", "MACOSX_DEPLOYMENT_TARGET")


def stop_group(process):
    """Stop west and its QEMU/build descendants, not unrelated processes."""
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def run_command(command, env, log, timeout, stop_on_success):
    with log.open("w", encoding="utf-8") as stream:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if stop_on_success:
                    lines = log.read_text(errors="replace").splitlines()
                    if any(line.strip() == "PROJECT EXECUTION FAILED" for line in lines):
                        stop_group(process)
                        return False
                    if any(line.strip() == "PROJECT EXECUTION SUCCESSFUL" for line in lines):
                        # Zephyr can idle after ztest completes; this is not a timeout pass.
                        stop_group(process)
                        return True
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(command, timeout)
                time.sleep(0.1)
            lines = log.read_text(errors="replace").splitlines()
            return process.returncode == 0 and (not stop_on_success or
                ("PROJECT EXECUTION SUCCESSFUL" in lines and
                 "PROJECT EXECUTION FAILED" not in lines))
        finally:
            stop_group(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test", action="append", choices=TESTS,
                        help="Repeat to select suites; default runs all five.")
    parser.add_argument("--board", default="qemu_x86_64")
    parser.add_argument("--output-root", type=Path, default=ROOT / "build-public-smoke")
    parser.add_argument("--build-timeout", type=int, default=600)
    parser.add_argument("--run-timeout", type=int, default=120)
    args = parser.parse_args()
    if args.build_timeout <= 0 or args.run_timeout <= 0:
        parser.error("timeouts must be positive seconds")
    west = shutil.which("west")
    if west is None:
        parser.error("west is not on PATH; activate your Zephyr virtual environment")
    output = args.output_root.resolve()
    if output == ROOT or output in ROOT.parents:
        parser.error("output root must not replace the repository or an ancestor")
    output.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items() if k not in HOST_FLAGS}
    for name in dict.fromkeys(args.test or TESTS):
        build = output / name
        commands = (
            ([west, "build", "-p", "always", "-b", args.board,
              str(ROOT / "tests" / ("ztest_" + name)), "-d", str(build)],
             args.build_timeout, "build"),
            ([west, "build", "-d", str(build), "-t", "run"],
             args.run_timeout, "run"),
        )
        for command, timeout, stage in commands:
            log = output / (name + "-" + stage + ".log")
            print(f"{name}: {stage} (timeout={timeout}s, log={log})", flush=True)
            try:
                passed = run_command(command, env, log, timeout, stage == "run")
            except (OSError, subprocess.TimeoutExpired) as error:
                print(f"FAIL: {name} {stage}: {error}; see {log}", file=sys.stderr)
                return 1
            if not passed:
                print(f"FAIL: {name} {stage}; see {log}",
                      file=sys.stderr)
                return 1
        print(f"PASS: {name}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
