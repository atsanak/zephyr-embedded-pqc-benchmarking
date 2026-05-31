#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""
Measure non-MCU resource-budget rows and print reviewed JSON updates.

The release gate enforces measured nucleo_h743zi protocol budgets via
check_resource_budgets.py. This helper gives maintainers the same disciplined
re-baselining path for qemu_x86_64/profile rows that are still marked as
estimated_pending_ci_baseline.

The helper deliberately does not rewrite resource_budgets.json. It prints the
exact updated JSON objects so maintainers can review and commit the changes in
a separate, auditable patch.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Any, Iterable, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from local_workflow import (  # noqa: E402
    HOST_ENV_BLACKLIST,
    clean_env,
    detect_west_root as _shared_detect_west_root,
    discover_west as _shared_discover_west,
)
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_BUDGET_FILE = REPO_ROOT / "scripts" / "resource_budgets.json"
DEFAULT_PROFILE_MATRIX = REPO_ROOT / "scripts" / "profile_validation_matrix.json"
DEFAULT_BUILD_ROOT = REPO_ROOT / "benchmark_results" / "resource_measurements"

PROFILE_KCONFIG = {
    "MCU_MINIMAL": "CONFIG_PQCP_PROFILE_MCU_MINIMAL=y",
    "GATEWAY": "CONFIG_PQCP_PROFILE_GATEWAY=y",
    "NATIVE_LAB": "CONFIG_PQCP_PROFILE_NATIVE_LAB=y",
}

BOARD_SIZE_PREFIX = {
    "qemu_x86_64": "x86_64-zephyr-elf",
    "mps2/an385": "arm-zephyr-eabi",
    "nucleo_h743zi": "arm-zephyr-eabi",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure resource-budget rows and print reviewed JSON updates."
    )
    parser.add_argument("--west-root", type=Path, help="Zephyr workspace root")
    parser.add_argument("--module-path", type=Path, help="PQCP module path")
    parser.add_argument("--west", help="Explicit west binary or command")
    parser.add_argument(
        "--budget-file",
        type=Path,
        default=DEFAULT_BUDGET_FILE,
        help="resource_budgets.json file to read",
    )
    parser.add_argument(
        "--profile-matrix",
        type=Path,
        default=DEFAULT_PROFILE_MATRIX,
        help="profile_validation_matrix.json used to discover overlays",
    )
    parser.add_argument(
        "--board",
        action="append",
        dest="boards",
        help="Board filter; defaults to qemu_x86_64",
    )
    parser.add_argument(
        "--profile",
        action="append",
        dest="profiles",
        choices=sorted(PROFILE_KCONFIG),
        help="Profile filter; defaults to MCU_MINIMAL and GATEWAY",
    )
    parser.add_argument(
        "--sample",
        action="append",
        dest="samples",
        help="Sample/test budget row filter, for example ztest_primitive",
    )
    parser.add_argument(
        "--status",
        default="estimated_pending_ci_baseline",
        help="Only measure rows with this status; use 'any' to ignore status",
    )
    parser.add_argument(
        "--headroom",
        type=float,
        default=1.10,
        help="Budget multiplier applied to measured ROM/RAM values",
    )
    parser.add_argument(
        "--build-dir-root",
        "--output-root",
        type=Path,
        default=DEFAULT_BUILD_ROOT,
        dest="build_dir_root",
        help="Directory for per-row west build directories",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="Optional JSON report containing raw measurements",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose command logging")
    return parser.parse_args()


def detect_west_root(start: Path) -> Path:
    return _shared_detect_west_root(start, strict=False)


def discover_west(explicit: Optional[str], west_root: Path, module_path: Path) -> list[str]:
    return _shared_discover_west(explicit, west_root, module_path)


def build_env() -> dict[str, str]:
    return clean_env()


def run_command(
    cmd: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    verbose: bool,
) -> subprocess.CompletedProcess[str]:
    if verbose:
        print(" ".join(shlex.quote(part) for part in cmd))
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )


def slugify(value: str) -> str:
    lowered = value.strip().lower().replace("/", "_").replace("-", "_")
    return re.sub(r"[^a-z0-9_]+", "_", lowered).strip("_")


def normalize_filters(values: Optional[Iterable[str]], defaults: Iterable[str]) -> set[str]:
    return {item.strip() for item in (values or defaults) if item.strip()}


def resolve_target(module_path: Path, sample: str) -> Path:
    if "/" in sample:
        target = module_path / sample
        if target.exists():
            return target

    for prefix in ("tests", "samples"):
        target = module_path / prefix / sample
        if target.exists():
            return target

    raise RuntimeError(f"Unable to resolve resource-budget sample '{sample}'")


def load_profile_overlays(path: Path) -> dict[tuple[str, str, str], str]:
    if not path.exists():
        return {}

    raw = json.loads(path.read_text())
    overlays: dict[tuple[str, str, str], str] = {}
    for profile, rows in raw.items():
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            overlay = row.get("overlay")
            board = row.get("board")
            target = row.get("target")
            if overlay and board and target:
                sample = str(target).rstrip("/").split("/")[-1]
                overlays[(str(board), str(profile), sample)] = str(overlay)
    return overlays


def find_size_tool(board: str, env: dict[str, str]) -> list[str]:
    prefix = BOARD_SIZE_PREFIX.get(board, "x86_64-zephyr-elf")
    binary = f"{prefix}-size"

    path_binary = shutil.which(binary, path=env.get("PATH"))
    if path_binary:
        return [path_binary]

    sdk = env.get("ZEPHYR_SDK_INSTALL_DIR")
    if sdk:
        for sdk_binary in (
            Path(sdk) / "gnu" / prefix / "bin" / binary,
            Path(sdk) / "gnu" / prefix / prefix / "bin" / binary,
        ):
            if sdk_binary.exists():
                return [str(sdk_binary)]

    host_size = shutil.which("size", path=env.get("PATH"))
    if host_size:
        return [host_size]

    raise RuntimeError(f"Unable to find a size tool for board '{board}'")


def measure_elf(elf_path: Path, size_cmd: list[str], env: dict[str, str]) -> dict[str, int]:
    result = subprocess.run(
        [*size_cmd, str(elf_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(f"size failed for {elf_path}:\n{result.stdout}")

    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and all(part.isdigit() for part in parts[:3]):
            text, data, bss = (int(parts[0]), int(parts[1]), int(parts[2]))
            return {
                "text": text,
                "data": data,
                "bss": bss,
                "rom": text + data,
                "ram": data + bss,
            }

    raise RuntimeError(f"Unable to parse size output for {elf_path}:\n{result.stdout}")


def west_build_measurement(
    *,
    west_cmd: list[str],
    west_root: Path,
    module_path: Path,
    build_root: Path,
    board: str,
    profile: str,
    sample: str,
    target: Path,
    overlay: Optional[str],
    env: dict[str, str],
    verbose: bool,
) -> Path:
    run_id = "__".join([slugify(board), slugify(profile), slugify(sample)])
    build_dir = build_root / run_id
    conf_path = build_root / f"{run_id}.conf"
    conf_path.parent.mkdir(parents=True, exist_ok=True)
    conf_path.write_text(f"{PROFILE_KCONFIG[profile]}\n", encoding="utf-8")

    cmake_args = [
        f"-DZEPHYR_EXTRA_MODULES={module_path}",
        f"-DEXTRA_CONF_FILE={conf_path}",
    ]
    if overlay:
        overlay_path = target / overlay
        if not overlay_path.exists():
            raise RuntimeError(f"Overlay {overlay_path} does not exist")
        cmake_args.append(f"-DOVERLAY_CONFIG={overlay_path}")

    cmd = [
        *west_cmd,
        "build",
        "-p",
        "always",
        "-d",
        str(build_dir),
        "-b",
        board,
        str(target),
        "--",
        *cmake_args,
    ]
    result = run_command(cmd, cwd=west_root, env=env, verbose=verbose)
    if result.returncode != 0:
        print(result.stdout)
        raise RuntimeError(f"west build failed for {board}/{profile}/{sample}")

    elf_path = build_dir / "zephyr" / "zephyr.elf"
    if not elf_path.exists():
        raise RuntimeError(f"west build did not produce {elf_path}")
    return elf_path


def selected_budget_rows(
    budgets: list[dict[str, Any]],
    *,
    boards: set[str],
    profiles: set[str],
    samples: Optional[set[str]],
    status: str,
) -> list[tuple[int, dict[str, Any]]]:
    selected: list[tuple[int, dict[str, Any]]] = []
    for index, row in enumerate(budgets):
        if not isinstance(row, dict):
            continue
        if str(row.get("board", "")) not in boards:
            continue
        if str(row.get("profile", "")) not in profiles:
            continue
        if samples is not None and str(row.get("sample", "")) not in samples:
            continue
        if status != "any" and str(row.get("status", "")) != status:
            continue
        selected.append((index, row))
    return selected


def suggested_budget_row(
    row: dict[str, Any],
    measurement: dict[str, Any],
    headroom: float,
) -> dict[str, Any]:
    updated = dict(row)
    rom_limit = int(math.ceil(int(measurement["rom_bytes"]) * headroom))
    ram_limit = int(math.ceil(int(measurement["ram_bytes"]) * headroom))

    updated["status"] = "measured"
    updated["measured_rom_bytes"] = int(measurement["rom_bytes"])
    updated["measured_ram_bytes"] = int(measurement["ram_bytes"])
    updated["measured_on_board"] = measurement["board"]
    updated["measured_sdk"] = measurement["sdk"]
    updated["measured_toolchain"] = measurement["toolchain"]
    updated["measured_at"] = measurement["measured_at"]
    updated["measured_notes"] = (
        "Recorded by scripts/measure_resource_budgets.py from a build-only "
        "Zephyr ELF measurement."
    )
    updated["rom_bytes_max"] = rom_limit
    updated["ram_bytes_max"] = ram_limit
    updated["limits"] = {
        "rom": rom_limit,
        "ram": ram_limit,
    }
    return updated


def main() -> int:
    args = parse_args()
    if args.headroom < 1.0:
        raise RuntimeError("--headroom must be >= 1.0")

    module_path = args.module_path.resolve() if args.module_path else REPO_ROOT
    west_root = args.west_root.resolve() if args.west_root else detect_west_root(module_path)
    budget_file = args.budget_file.resolve()
    build_root = args.build_dir_root.resolve()
    env = build_env()
    west_cmd = discover_west(args.west, west_root, module_path)

    boards = normalize_filters(args.boards, ["qemu_x86_64"])
    profiles = normalize_filters(args.profiles, ["MCU_MINIMAL", "GATEWAY"])
    samples = normalize_filters(args.samples, []) if args.samples else None
    overlays = load_profile_overlays(args.profile_matrix.resolve())

    raw = json.loads(budget_file.read_text())
    budgets = raw.get("budgets")
    if not isinstance(budgets, list):
        raise RuntimeError(f"{budget_file} must contain a 'budgets' list")

    rows = selected_budget_rows(
        budgets,
        boards=boards,
        profiles=profiles,
        samples=samples,
        status=args.status,
    )
    if not rows:
        print("No matching budget rows selected.")
        return 0

    build_root.mkdir(parents=True, exist_ok=True)
    report_rows: list[dict[str, Any]] = []
    suggested_rows: list[dict[str, Any]] = []

    print("PQCP Resource Budget Measurements")
    print(f"  budgets : {budget_file}")
    print(f"  boards  : {', '.join(sorted(boards))}")
    print(f"  profiles: {', '.join(sorted(profiles))}")

    for index, row in rows:
        board = str(row["board"])
        profile = str(row["profile"])
        sample = str(row["sample"])
        target = resolve_target(module_path, sample)
        overlay = overlays.get((board, profile, sample))
        size_cmd = find_size_tool(board, env)
        elf_path = west_build_measurement(
            west_cmd=west_cmd,
            west_root=west_root,
            module_path=module_path,
            build_root=build_root,
            board=board,
            profile=profile,
            sample=sample,
            target=target,
            overlay=overlay,
            env=env,
            verbose=args.verbose,
        )
        sizes = measure_elf(elf_path, size_cmd, env)
        measurement = {
            "index": index,
            "board": board,
            "profile": profile,
            "sample": sample,
            "target": str(target.relative_to(module_path)),
            "overlay": overlay or "",
            "rom_bytes": sizes["rom"],
            "ram_bytes": sizes["ram"],
            "text_bytes": sizes["text"],
            "data_bytes": sizes["data"],
            "bss_bytes": sizes["bss"],
            "sdk": Path(env.get("ZEPHYR_SDK_INSTALL_DIR", "unknown")).name,
            "toolchain": Path(size_cmd[0]).name,
            "measured_at": date.today().isoformat(),
        }
        report_rows.append(measurement)
        suggested_rows.append(suggested_budget_row(row, measurement, args.headroom))
        print(
            f"  - {board} {profile} {sample}: "
            f"ROM={sizes['rom']} RAM={sizes['ram']}"
        )

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report_rows, indent=2) + "\n", encoding="utf-8")

    print("\nCopy the following JSON updates to resource_budgets.json:")
    print(json.dumps(suggested_rows, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
