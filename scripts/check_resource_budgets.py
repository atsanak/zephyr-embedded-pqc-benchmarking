#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""
Run MCU protocol build-only cost-of-assurance rows and enforce ROM/RAM budgets.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from local_workflow import (  # noqa: E402
    HOST_ENV_BLACKLIST,
    clean_env,
    detect_west_root as _shared_detect_west_root,
    discover_west as _shared_discover_west,
)
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_MATRIX = REPO_ROOT / "scripts" / "cost_of_assurance_matrix.json"
DEFAULT_BUDGETS = REPO_ROOT / "scripts" / "resource_budgets.json"
DEFAULT_OUTPUT_ROOT = REPO_ROOT / "benchmark_results/extended/mcu_protocol_footprint"
DEFAULT_CSV = "cost_of_assurance_protocols_mcu.csv"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build MCU protocol benchmark rows and enforce ROM/RAM budgets."
    )
    parser.add_argument("--west-root", type=Path, help="Zephyr workspace root")
    parser.add_argument("--module-path", type=Path, help="PQCP module path")
    parser.add_argument("--west", help="Explicit west binary or command")
    parser.add_argument(
        "--matrix",
        type=Path,
        default=DEFAULT_MATRIX,
        help="Cost-of-assurance matrix JSON to consume",
    )
    parser.add_argument(
        "--budget-file",
        type=Path,
        default=DEFAULT_BUDGETS,
        help="Resource budget JSON file",
    )
    parser.add_argument(
        "--board",
        default="nucleo_h743zi",
        help="MCU board to build (default: nucleo_h743zi)",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=DEFAULT_OUTPUT_ROOT,
        help="Directory for build artifacts and MCU CSV output",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose command logging")
    return parser.parse_args()


def detect_west_root(start: Path) -> Path:
    return _shared_detect_west_root(start, strict=False)


def discover_west(explicit: Optional[str], west_root: Path, module_path: Path) -> List[str]:
    return _shared_discover_west(explicit, west_root, module_path)


def build_env() -> Dict[str, str]:
    return clean_env()


def run_command(
    cmd: List[str],
    *,
    cwd: Path,
    env: Dict[str, str],
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
    lowered = value.strip().lower().replace("-", "_").replace("/", "_")
    return re.sub(r"[^a-z0-9_]+", "_", lowered).strip("_")


def normalize_backend(value: Optional[str]) -> str:
    backend = str(value or "auto").strip().lower().replace("-", "_")
    return backend or "auto"


def normalize_implementation(value: Optional[str]) -> str:
    implementation = str(value or "pqcp").strip().lower().replace("-", "_")
    return implementation or "pqcp"


def resolve_mode(entry: Dict[str, Any]) -> str:
    if entry.get("mode") is not None:
        return str(entry["mode"]).strip().lower().replace("-", "_")
    if entry.get("run_mode") is not None:
        return str(entry["run_mode"]).strip().lower().replace("-", "_")
    if entry.get("build_only") or (entry.get("build") and not entry.get("run", True)):
        return "build_only"
    return "run"


def make_run_id(
    board: str,
    profile: str,
    sample: str,
    implementation: Optional[str],
    backend: Optional[str],
) -> str:
    parts = [slugify(board), slugify(profile), slugify(sample)]
    implementation_name = normalize_implementation(implementation)
    if implementation_name != "pqcp":
        parts.append(slugify(implementation_name))
    backend_name = normalize_backend(backend)
    if backend_name != "auto":
        parts.append(slugify(backend_name))
    return "__".join(parts)


def load_matrix_protocol_rows(path: Path, board: str) -> Dict[str, Dict[str, Any]]:
    data = json.loads(path.read_text())
    rows: Dict[str, Dict[str, Any]] = {}
    for entry in data.get("runs", []):
        if entry.get("board") != board:
            continue
        if entry.get("sample") != "pqcp_bench_protocol":
            continue
        if resolve_mode(entry) != "build_only":
            continue
        backend = normalize_backend(entry.get("backend"))
        implementation = normalize_implementation(entry.get("implementation"))
        if backend not in {"auto", "clean"}:
            continue
        if implementation not in {"pqcp", "baseline"}:
            continue

        run_id = str(
            entry.get(
                "run_id",
                make_run_id(
                    str(entry["board"]),
                    str(entry["profile"]),
                    str(entry["sample"]),
                    implementation,
                    backend,
                ),
            )
        )
        rows[run_id] = {
            "run_id": run_id,
            "board": str(entry["board"]),
            "profile": str(entry["profile"]),
            "sample": str(entry["sample"]),
            "suite": str(entry.get("suite", "")),
            "implementation": implementation,
            "backend": backend,
        }
    if not rows:
        raise RuntimeError(
            f"No build-only MCU protocol rows found for board '{board}' in {path}"
        )
    return rows


def load_budget_rows(path: Path, board: str) -> Dict[str, Dict[str, Any]]:
    raw = json.loads(path.read_text())
    budgets = raw.get("budgets", raw)
    if not isinstance(budgets, list):
        raise RuntimeError("resource budget file must contain a 'budgets' list")

    selected: Dict[str, Dict[str, Any]] = {}
    for entry in budgets:
        if not isinstance(entry, dict):
            continue
        if entry.get("board") != board or entry.get("sample") != "pqcp_bench_protocol":
            continue
        run_id = entry.get("run_id")
        if not run_id:
            continue
        limits = entry.get("limits", {})
        rom_limit = entry.get("rom_bytes_max", limits.get("rom"))
        ram_limit = entry.get("ram_bytes_max", limits.get("ram"))
        if rom_limit is None or ram_limit is None:
            raise RuntimeError(
                f"resource budget entry for {run_id} is missing rom/ram limits"
            )
        selected[str(run_id)] = {
            "rom_bytes_max": int(rom_limit),
            "ram_bytes_max": int(ram_limit),
            "description": str(entry.get("description", "")),
        }
    if not selected:
        raise RuntimeError(
            f"No MCU protocol resource budgets found for board '{board}' in {path}"
        )
    return selected


def run_protocol_build_matrix(
    *,
    west_root: Path,
    module_path: Path,
    west_cmd: List[str],
    board: str,
    output_root: Path,
    env: Dict[str, str],
    verbose: bool,
) -> None:
    if output_root.exists():
        shutil.rmtree(output_root)
    output_root.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        str(module_path / "scripts/run_benchmarks.py"),
        "--cost-of-assurance-matrix",
        "--board",
        board,
        "--samples",
        "pqcp_bench_protocol",
        "--backend-policies",
        "auto",
        "clean",
        "--output",
        str(output_root),
        "--west-root",
        str(west_root),
        "--module-path",
        str(module_path),
        "--west",
        " ".join(west_cmd),
    ]
    result = run_command(cmd, cwd=module_path, env=env, verbose=verbose)
    if result.returncode != 0:
        print(result.stdout)
        raise RuntimeError("run_benchmarks.py failed for MCU protocol builds")


def write_protocol_csv(rows: List[Dict[str, Any]], output_path: Path) -> None:
    fieldnames = ["board", "suite", "implementation", "rom_bytes", "ram_bytes"]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    args = parse_args()
    module_path = args.module_path.resolve() if args.module_path else REPO_ROOT
    west_root = args.west_root.resolve() if args.west_root else detect_west_root(module_path)
    west_cmd = discover_west(args.west, west_root, module_path)
    env = build_env()
    output_root = args.output_root.resolve()

    matrix_rows = load_matrix_protocol_rows(args.matrix.resolve(), args.board)
    budget_rows = load_budget_rows(args.budget_file.resolve(), args.board)

    run_protocol_build_matrix(
        west_root=west_root,
        module_path=module_path,
        west_cmd=west_cmd,
        board=args.board,
        output_root=output_root,
        env=env,
        verbose=args.verbose,
    )

    runs_path = output_root / "runs.json"
    if not runs_path.exists():
        raise RuntimeError(f"Expected build results at {runs_path}")
    runs = {
        row["run_id"]: row
        for row in json.loads(runs_path.read_text())
        if row.get("sample") == "pqcp_bench_protocol"
    }

    csv_rows: List[Dict[str, Any]] = []
    failures: List[str] = []

    for run_id, matrix_row in sorted(matrix_rows.items()):
        run = runs.get(run_id)
        if run is None:
            failures.append(f"missing build result for {run_id}")
            continue
        if not run.get("build_ok"):
            failures.append(f"build failed for {run_id}")
            continue

        rom_bytes = int(run.get("rom_bytes", 0) or 0)
        ram_bytes = int(run.get("ram_bytes", 0) or 0)
        csv_rows.append(
            {
                "board": matrix_row["board"],
                "suite": matrix_row["suite"],
                "implementation": matrix_row["implementation"],
                "rom_bytes": rom_bytes,
                "ram_bytes": ram_bytes,
            }
        )

        budget = budget_rows.get(run_id)
        if budget is None:
            failures.append(f"missing resource budget entry for {run_id}")
            continue
        if rom_bytes > budget["rom_bytes_max"]:
            failures.append(
                f"FAIL {matrix_row['board']} {matrix_row['suite']} {matrix_row['implementation']}: "
                f"ROM {rom_bytes} bytes > budget {budget['rom_bytes_max']} bytes"
            )
        if ram_bytes > budget["ram_bytes_max"]:
            failures.append(
                f"FAIL {matrix_row['board']} {matrix_row['suite']} {matrix_row['implementation']}: "
                f"RAM {ram_bytes} bytes > budget {budget['ram_bytes_max']} bytes"
            )

    csv_path = output_root / DEFAULT_CSV
    write_protocol_csv(csv_rows, csv_path)

    print("MCU Protocol Footprint")
    print(f"  board      : {args.board}")
    print(f"  output dir : {output_root}")
    print(f"  csv        : {csv_path}")
    for row in csv_rows:
        print(
            f"  - {row['suite']} / {row['implementation']}: "
            f"ROM={row['rom_bytes']} RAM={row['ram_bytes']}"
        )

    if failures:
        print("MCU protocol budget failures:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("MCU protocol budgets satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
