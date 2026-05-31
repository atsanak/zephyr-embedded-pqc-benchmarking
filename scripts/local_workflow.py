#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Shared helpers for local PQCP maintainer workflows."""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import sys
from pathlib import Path

HOST_ENV_BLACKLIST = (
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "CPATH",
    "SDKROOT",
)


def clean_env() -> dict[str, str]:
    """Return a subprocess environment without host compiler leakage."""
    env = os.environ.copy()
    for key in HOST_ENV_BLACKLIST:
        env.pop(key, None)
    return env


def detect_west_root(start: Path, *, strict: bool = True) -> Path:
    """Find the nearest west workspace root above *start*.

    Args:
        start: Path inside a west workspace.
        strict: If true, raise when no workspace is found. If false, return
            the resolved start path for callers that intentionally support
            non-west dry runs.
    """
    current = start.resolve()
    while current != current.parent:
        if (current / ".west").exists():
            return current
        current = current.parent
    if strict:
        raise RuntimeError(
            f"unable to find a west workspace root above {start}; "
            "pass --west-root explicitly"
        )
    return start.resolve()


def discover_west(explicit: str | None, west_root: Path, module_path: Path) -> list[str]:
    """Return a working west command as argv tokens."""
    candidates: list[list[str]] = []
    if explicit:
        candidates.append(shlex.split(explicit))

    path_west = shutil.which("west")
    if path_west:
        candidates.append([path_west])

    for candidate in (
        west_root / ".venv/bin/west",
        module_path / ".venv/bin/west",
    ):
        if candidate.exists():
            candidates.append([str(candidate)])

    candidates.append([sys.executable, "-m", "west"])

    seen: set[tuple[str, ...]] = set()
    for command in candidates:
        key = tuple(command)
        if key in seen:
            continue
        seen.add(key)
        try:
            result = subprocess.run(
                command + ["--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
                check=False,
            )
        except OSError:
            continue
        if result.returncode == 0:
            return command
    raise RuntimeError("unable to find a working west command")


def command_to_text(cmd: list[str]) -> str:
    """Shell-quote an argv list for diagnostics."""
    return " ".join(shlex.quote(part) for part in cmd)


def _terminate_process_group(proc: subprocess.Popen[str], sig: signal.Signals) -> None:
    if os.name == "nt":
        if sig == signal.SIGKILL:
            proc.kill()
        else:
            proc.terminate()
        return
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        pass


def run_command(
    cmd: list[str],
    cwd: Path,
    env: dict[str, str],
    *,
    timeout: int | None = None,
    success_markers: tuple[str, ...] = (),
) -> str:
    """Run a command with readable diagnostics and marker-aware timeouts."""
    print("+ " + command_to_text(cmd))
    popen_kwargs = {}
    if os.name != "nt":
        popen_kwargs["start_new_session"] = True
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        **popen_kwargs,
    )
    try:
        stdout, _ = proc.communicate(timeout=timeout)
        returncode = proc.returncode
    except subprocess.TimeoutExpired:
        _terminate_process_group(proc, signal.SIGTERM)
        try:
            stdout, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            _terminate_process_group(proc, signal.SIGKILL)
            stdout, _ = proc.communicate()
        returncode = 124

    stdout = stdout or ""
    if stdout:
        print(stdout, end="" if stdout.endswith("\n") else "\n")
    if returncode == 124 and success_markers and all(marker in stdout for marker in success_markers):
        print("[PASS] command reached timeout after printing expected success markers")
        return stdout
    if returncode != 0:
        raise RuntimeError(f"command failed with exit {returncode}")
    return stdout


def west_project_abspaths(west_cmd: list[str], west_root: Path, env: dict[str, str]) -> set[Path]:
    """Return absolute project paths known to the active west manifest."""
    result = subprocess.run(
        [*west_cmd, "list", "--all", "-f", "{abspath}"],
        cwd=str(west_root),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"west list failed with exit {result.returncode}:\n{result.stdout}")
    return {
        Path(line.strip()).resolve()
        for line in result.stdout.splitlines()
        if line.strip()
    }


def is_west_manifest_project(
    west_cmd: list[str],
    west_root: Path,
    module_path: Path,
    env: dict[str, str],
) -> bool:
    """Return whether *module_path* is declared by the active west manifest."""
    module_resolved = module_path.resolve()
    return module_resolved in west_project_abspaths(west_cmd, west_root, env)
