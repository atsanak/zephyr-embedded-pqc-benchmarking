#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""
Export PQCP benchmark matrix results into a publication-friendly CSV.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform as host_platform
import shlex
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

PROVENANCE_SCHEMA_VERSION = 1

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))
from local_workflow import (  # noqa: E402
    HOST_ENV_BLACKLIST,
    clean_env,
    detect_west_root as _shared_detect_west_root,
    discover_west as _shared_discover_west,
)
DEFAULT_MATRIX = REPO_ROOT / "scripts" / "cost_of_assurance_matrix.json"
DEFAULT_OUTPUT = REPO_ROOT / "results" / "benchmark_results.csv"
CSV_FIELDNAMES = [
    "suite",
    "parameter_set",
    "implementation",
    "backend",
    "operation",
    "cycles",
    "time_us",
    "rom_bytes",
    "ram_bytes",
    "platform",
    "timestamp",
]
EXPECTED_PRIMITIVE_ROWS = {
    "ML-KEM-512": ("keygen", "encaps", "decaps"),
    "ML-KEM-768": ("keygen", "encaps", "decaps"),
    "ML-KEM-1024": ("keygen", "encaps", "decaps"),
    "ML-DSA-44": ("keygen", "sign", "verify"),
    "ML-DSA-65": ("keygen", "sign", "verify"),
    "ML-DSA-87": ("keygen", "sign", "verify"),
}
EXPECTED_BASE_OPERATIONS = {
    operation
    for operations in EXPECTED_PRIMITIVE_ROWS.values()
    for operation in operations
}
DISTRIBUTION_METRICS = (
    "cycles_min",
    "cycles_median",
    "cycles_p90",
    "cycles_p99",
    "cycles_max",
    "cycles_mad",
    "sample_count",
)
REQUIRED_BENCHMARK_METADATA_KEYS = (
    "backend.selector",
    "board.name",
    "compiler.id",
    "distribution.sample_cap",
    "profile.flags",
    "zephyr.version",
)
# This is a sanity floor, not a regression budget.  QEMU/native timing can make
# the PQCP path substantially faster than the native-C baseline, so only reject
# near-zero ratios that indicate broken timing extraction.
MIN_PQCP_BASELINE_TIME_RATIO = 0.1
MAX_PQCP_BASELINE_TIME_RATIO = 10.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the cost-of-assurance matrix and export benchmark CSV results."
    )
    parser.add_argument(
        "--matrix",
        type=Path,
        default=DEFAULT_MATRIX,
        help="Matrix JSON to execute (default: scripts/cost_of_assurance_matrix.json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output CSV path (default: results/benchmark_results.csv)",
    )
    parser.add_argument(
        "--platform",
        default="qemu_x86_64",
        help="Board/platform to export (default: qemu_x86_64)",
    )
    parser.add_argument("--west-root", type=Path, help="Zephyr workspace root")
    parser.add_argument("--module-path", type=Path, help="PQCP module path")
    parser.add_argument("--west", help="Explicit west binary or command")
    parser.add_argument(
        "--validate-only",
        type=Path,
        help="Validate an existing benchmark CSV instead of generating a new one",
    )
    parser.add_argument(
        "--verify-provenance",
        action="store_true",
        help=(
            "When used with --validate-only, also load the matching "
            "benchmark_provenance.json sidecar and verify that its "
            "recorded csv.sha256 matches the CSV content."
        ),
    )
    parser.add_argument(
        "--provenance-output",
        type=Path,
        help=(
            "Override the benchmark_provenance.json path. Defaults to "
            "writing the sidecar next to the CSV output."
        ),
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="Run only the first three runnable matrix entries for pipeline smoke checks",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Echo commands")
    parser.add_argument("--source-dataset", default="local-benchmark-matrix")
    parser.add_argument("--environment-type", choices=("qemu", "native_host", "physical_hardware"), default=None)
    parser.add_argument("--board-class", default=None)
    parser.add_argument("--clock-assumption", default=None)
    parser.add_argument("--statistic-type", default="single_or_distribution")
    parser.add_argument("--compiler", default=None)
    parser.add_argument("--toolchain", default=None)
    parser.add_argument("--optimization-flags", default=None)
    return parser.parse_args()


def detect_west_root(start: Path) -> Path:
    return _shared_detect_west_root(start, strict=False)


def discover_west(explicit: Optional[str], west_root: Path, module_path: Path) -> List[str]:
    return _shared_discover_west(explicit, west_root, module_path)


def shutil_which(name: str) -> Optional[str]:
    for path_dir in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(path_dir) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def build_env() -> Dict[str, str]:
    return clean_env()


def load_matrix(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text())
    return list(data.get("runs", []))


def entry_is_runnable(entry: Dict[str, Any]) -> bool:
    run_mode = entry.get("run_mode")
    if run_mode is not None:
        return str(run_mode).strip().lower().replace("-", "_") == "run"
    if entry.get("build_only"):
        return False
    if "run" in entry or "build" in entry:
        run_enabled = bool(entry.get("run"))
        build_enabled = bool(entry.get("build"))
        if run_enabled:
            return True
        if build_enabled:
            return False
    return True


def select_entries(
    entries: Iterable[Dict[str, Any]],
    *,
    platform: str,
    smoke: bool,
) -> List[Dict[str, Any]]:
    runnable = [
        entry
        for entry in entries
        if entry.get("board") == platform and entry_is_runnable(entry)
    ]
    if smoke:
        return [
            entry
            for entry in runnable
            if entry.get("sample") in {"pqcp_basic_kem", "pqcp_basic_sig"}
            and (
                (
                    entry.get("implementation") == "pqcp"
                    and entry.get("backend") == "auto"
                )
                or (
                    entry.get("implementation") == "baseline"
                    and entry.get("backend") == "clean"
                )
            )
        ]
    return runnable


def run_matrix(
    matrix_entries: List[Dict[str, Any]],
    *,
    matrix_path: Path,
    output_dir: Path,
    west_root: Path,
    module_path: Path,
    west_cmd: List[str],
    verbose: bool,
) -> None:
    filtered_config = {"runs": matrix_entries}
    filtered_path = output_dir / "filtered_matrix.json"
    filtered_path.write_text(json.dumps(filtered_config, indent=2) + "\n")

    cmd = [
        sys.executable,
        str(module_path / "scripts" / "run_benchmarks.py"),
        "--config",
        str(filtered_path),
        "--output",
        str(output_dir),
        "--west-root",
        str(west_root),
        "--module-path",
        str(module_path),
        "--west",
        " ".join(west_cmd),
    ]
    if verbose:
        print("[export] Running matrix command:")
        print("         " + " ".join(shlex.quote(part) for part in cmd))

    result = subprocess.run(
        cmd,
        cwd=str(module_path),
        env=build_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.returncode != 0:
        raise RuntimeError(
            f"run_benchmarks.py exited with {result.returncode}"
        )


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def canonical_algorithm_name(name: str, level: int) -> str:
    mapping = {
        "MLKEM": "ML-KEM",
        "MLDSA": "ML-DSA",
    }
    base = mapping.get(name, name)
    return f"{base}-{level}" if level > 0 else base


def protocol_parameter_sets(
    metric_rows: Iterable[Dict[str, Any]],
) -> Dict[str, str]:
    suites: Dict[str, Dict[str, str]] = defaultdict(dict)
    for row in metric_rows:
        if row.get("component") != "protocol":
            continue
        operation = row.get("operation")
        algorithm = str(row.get("algorithm", ""))
        level = int(row.get("level", 0))
        if operation == "auth" and level > 0:
            suites[row["run_id"]]["sig"] = canonical_algorithm_name(algorithm, level)
        elif operation == "key_exchange" and level > 0:
            suites[row["run_id"]]["kem"] = canonical_algorithm_name(algorithm, level)

    resolved: Dict[str, str] = {}
    for run_id, parts in suites.items():
        kem = parts.get("kem")
        sig = parts.get("sig")
        if kem and sig:
            resolved[run_id] = f"{kem} + {sig}"
        elif kem:
            resolved[run_id] = kem
        elif sig:
            resolved[run_id] = sig
    return resolved


def normalize_operation(operation: str, metric: str) -> str:
    if metric in {"cycles", "time"}:
        return operation
    return f"{operation}_{metric}"


def to_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def export_rows(
    metric_rows: List[Dict[str, Any]],
    runs: List[Dict[str, Any]],
    *,
    platform: str,
) -> List[Dict[str, Any]]:
    run_lookup = {row["run_id"]: row for row in runs}
    protocol_sets = protocol_parameter_sets(metric_rows)
    exported: Dict[
        Tuple[str, str, str, str, str, str, str],
        Dict[str, Any],
    ] = {}

    for row in metric_rows:
        if row.get("board") != platform:
            continue

        run_id = row["run_id"]
        run = run_lookup.get(run_id)
        if run is None:
            continue

        component = row.get("component")
        metric = str(row.get("metric", ""))
        unit = str(row.get("unit", ""))
        cycles = None
        time_us = None

        if unit == "cyc" or metric == "cycles":
            cycles = to_int(row.get("value"))
        elif unit == "count" or metric == "sample_count":
            cycles = to_int(row.get("value"))
        elif unit == "us":
            time_us = to_int(row.get("value"))
        elif unit == "ms":
            raw = to_int(row.get("value"))
            time_us = raw * 1000 if raw is not None else None
        else:
            continue

        if cycles is None and time_us is None:
            continue

        if component == "protocol":
            suite = str(row.get("algorithm", "TLS13"))
            parameter_set = protocol_sets.get(run_id, str(run.get("sample", "")))
        else:
            suite = canonical_algorithm_name(str(row.get("algorithm", "")), 0)
            parameter_set = canonical_algorithm_name(
                str(row.get("algorithm", "")),
                int(row.get("level", 0)),
            )

        key = (
            suite,
            parameter_set,
            str(run["implementation"]),
            str(run["backend"]),
            normalize_operation(str(row.get("operation", "")), metric),
            platform,
            str(row.get("timestamp", "")),
        )
        record = exported.setdefault(
            key,
            {
                "suite": suite,
                "parameter_set": parameter_set,
                "implementation": run["implementation"],
                "backend": run["backend"],
                "operation": normalize_operation(str(row.get("operation", "")), metric),
                "cycles": "",
                "time_us": "",
                "rom_bytes": run.get("rom_bytes", ""),
                "ram_bytes": run.get("ram_bytes", ""),
                "platform": platform,
                "timestamp": row.get("timestamp", ""),
            },
        )
        if cycles is not None:
            record["cycles"] = cycles
        if time_us is not None:
            record["time_us"] = time_us

    rows = sorted(
        exported.values(),
        key=lambda row: (
            row["suite"],
            row["parameter_set"],
            row["operation"],
            row["implementation"],
            row["backend"],
        ),
    )
    return add_single_observation_distribution_rows(rows)


def add_single_observation_distribution_rows(
    rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Add distribution rows for legacy single-observation benchmark samples.

    Older sample applications emit one timing row per operation. Distribution
    aware samples can emit richer rows directly; for legacy rows we preserve the
    old benchmark contract and add an explicit one-sample distribution so the
    release evidence pack can still state what statistic was available.
    """
    existing = {
        (
            row.get("parameter_set"),
            row.get("implementation"),
            row.get("backend"),
            row.get("operation"),
            row.get("platform"),
            row.get("timestamp"),
        )
        for row in rows
    }
    additions: List[Dict[str, Any]] = []
    for row in rows:
        parameter_set = str(row.get("parameter_set", ""))
        operation = str(row.get("operation", ""))
        if operation not in EXPECTED_PRIMITIVE_ROWS.get(parameter_set, ()):
            continue
        cycles = to_int(row.get("cycles"))
        if cycles is None:
            continue
        values = {
            "cycles_min": cycles,
            "cycles_median": cycles,
            "cycles_p90": cycles,
            "cycles_p99": cycles,
            "cycles_max": cycles,
            "cycles_mad": 0,
            "sample_count": 1,
        }
        for metric, value in values.items():
            derived = dict(row)
            derived["operation"] = f"{operation}_{metric}"
            derived["cycles"] = value
            derived["time_us"] = ""
            key = (
                derived.get("parameter_set"),
                derived.get("implementation"),
                derived.get("backend"),
                derived.get("operation"),
                derived.get("platform"),
                derived.get("timestamp"),
            )
            if key in existing:
                continue
            existing.add(key)
            additions.append(derived)

    return sorted(
        [*rows, *additions],
        key=lambda row: (
            row["suite"],
            row["parameter_set"],
            row["operation"],
            row["implementation"],
            row["backend"],
        ),
    )


def collect_benchmark_metadata(metric_rows: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Collect build metadata rows emitted beside benchmark timing rows.

    The benchmark CSV intentionally remains numeric and stable.  This sidecar
    metadata binds those numbers to the compiler, Zephyr tree, board, profile
    mask, backend selector, and distribution sample cap that produced them.
    """
    by_key: Dict[str, set[str]] = defaultdict(set)
    run_ids: set[str] = set()
    row_count = 0

    for row in metric_rows:
        if row.get("component") != "build" or row.get("operation") != "metadata":
            continue

        algorithm = str(row.get("algorithm", "")).strip()
        metric = str(row.get("metric", "")).strip()
        if not algorithm or not metric:
            continue

        value = str(row.get("value", "")).strip()
        unit = str(row.get("unit", "")).strip()
        key = f"{algorithm}.{metric}"
        by_key[key].add(f"{value} {unit}".strip())
        row_count += 1
        if row.get("run_id"):
            run_ids.add(str(row["run_id"]))

    return {
        "row_count": row_count,
        "keys": sorted(by_key),
        "required_keys": list(REQUIRED_BENCHMARK_METADATA_KEYS),
        "by_key": {key: sorted(values) for key, values in sorted(by_key.items())},
        "run_ids": sorted(run_ids),
    }


def validate_benchmark_metadata_document(
    metadata: Any,
) -> List[Dict[str, str]]:
    failures: List[Dict[str, str]] = []
    if not isinstance(metadata, dict):
        return [
            {
                "check": "provenance_metadata",
                "message": "benchmark_metadata is missing or not an object",
            }
        ]

    row_count = metadata.get("row_count")
    if not isinstance(row_count, int) or row_count <= 0:
        failures.append(
            {
                "check": "provenance_metadata",
                "message": "benchmark_metadata.row_count is missing or zero",
            }
        )

    by_key = metadata.get("by_key")
    if not isinstance(by_key, dict):
        by_key = {}
        failures.append(
            {
                "check": "provenance_metadata",
                "message": "benchmark_metadata.by_key is missing or not an object",
            }
        )

    keys = set(metadata.get("keys") or by_key.keys())
    for key in REQUIRED_BENCHMARK_METADATA_KEYS:
        values = by_key.get(key)
        if key not in keys or not isinstance(values, list) or not values:
            failures.append(
                {
                    "check": "provenance_metadata",
                    "message": f"benchmark metadata key {key!r} is missing",
                }
            )

    return failures


def build_comparison_context(
    *,
    platform: str,
    source_dataset: str = "local-benchmark-matrix",
    environment_type: str | None = None,
    board_class: str | None = None,
    clock_assumption: str | None = None,
    statistic_type: str = "single_or_distribution",
    compiler: str | None = None,
    toolchain: str | None = None,
    optimization_flags: str | None = None,
) -> Dict[str, Any]:
    inferred_environment = environment_type
    if inferred_environment is None:
        inferred_environment = "qemu" if platform.startswith("qemu") else "native_host" if platform == "native_sim" else "physical_hardware"
    inferred_board_class = board_class
    if inferred_board_class is None:
        inferred_board_class = "qemu" if platform.startswith("qemu") else "native_sim" if platform == "native_sim" else "mcu"
    return {
        "source_dataset": source_dataset,
        "source_ecosystem": "pqcp-zephyr-trust-stack",
        "board_class": inferred_board_class,
        "clock_assumption": clock_assumption or "runner/platform clock as reported by Zephyr build environment",
        "compiler": compiler or "recorded in benchmark_metadata.compiler.id when emitted",
        "toolchain": toolchain or "Zephyr SDK/toolchain recorded in provenance.tooling",
        "optimization_flags": optimization_flags or "recorded in benchmark_metadata.profile.flags when emitted",
        "backend_family": "PQ Code Package native backends",
        "statistic_type": statistic_type,
        "environment_type": inferred_environment,
        "is_physical_measurement": inferred_environment == "physical_hardware",
    }


def validate_comparison_context(context: Any) -> List[Dict[str, str]]:
    if not isinstance(context, dict):
        return [{"check": "comparison_context", "message": "comparison_context is missing or not an object"}]
    failures: List[Dict[str, str]] = []
    for key in (
        "source_dataset",
        "source_ecosystem",
        "board_class",
        "clock_assumption",
        "backend_family",
        "statistic_type",
        "environment_type",
    ):
        if context.get(key) in (None, ""):
            failures.append({"check": "comparison_context", "message": f"{key} is required"})
    if context.get("environment_type") not in {"qemu", "native_host", "physical_hardware"}:
        failures.append(
            {
                "check": "comparison_context",
                "message": f"invalid environment_type {context.get('environment_type')!r}",
            }
        )
    return failures


def write_csv(rows: List[Dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def metric_value_for_summary(row: Dict[str, Any]) -> Tuple[Optional[int], str]:
    cycles = to_int(row.get("cycles"))
    if cycles is not None:
        return cycles, "cycles"
    time_us = to_int(row.get("time_us"))
    if time_us is not None:
        return time_us, "us"
    return None, ""


def write_summary(rows: List[Dict[str, Any]], summary_path: Path) -> None:
    grouped: Dict[Tuple[str, str, str], Dict[str, Dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        key = (row["suite"], row["parameter_set"], row["operation"])
        grouped[key][f"{row['implementation']}:{row['backend']}"] = row

    lines = [
        "# Benchmark Summary",
        "",
        "| Suite | Parameter Set | Operation | Metric | PQCP | Baseline | Overhead |",
        "|---|---|---|---|---:|---:|---:|",
    ]

    comparison_rows = 0
    for key in sorted(grouped):
        variants = grouped[key]
        pqcp_row = variants.get("pqcp:auto")
        baseline_row = variants.get("baseline:clean")
        if pqcp_row is None or baseline_row is None:
            continue

        pqcp_value, metric_unit = metric_value_for_summary(pqcp_row)
        baseline_value, baseline_unit = metric_value_for_summary(baseline_row)
        if pqcp_value is None or baseline_value is None:
            continue
        if metric_unit != baseline_unit or baseline_value == 0:
            continue

        overhead_pct = ((pqcp_value - baseline_value) / baseline_value) * 100.0
        suite, parameter_set, operation = key
        lines.append(
            f"| {suite} | {parameter_set} | {operation} | {metric_unit} | "
            f"{pqcp_value} | {baseline_value} | {overhead_pct:+.2f}% |"
        )
        comparison_rows += 1

    if comparison_rows == 0:
        lines.extend(
            [
                "",
                "No PQCP-vs-baseline comparison rows were present in this export slice.",
            ]
        )

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text("\n".join(lines) + "\n")


def _parse_positive_number(value: Any, label: str) -> Tuple[Optional[float], Optional[str]]:
    if value in ("", None, "n/a"):
        return None, f"{label} is missing"
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return None, f"{label} is not numeric: {value!r}"
    if not math.isfinite(numeric):
        return None, f"{label} is not finite: {value!r}"
    if numeric <= 0:
        return None, f"{label} must be > 0, got {value!r}"
    return numeric, None


def validate_benchmark_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    failures: List[Dict[str, str]] = []
    primitive_rows = [
        row for row in rows
        if row.get("parameter_set") in EXPECTED_PRIMITIVE_ROWS
        and row.get("operation") in EXPECTED_PRIMITIVE_ROWS[row["parameter_set"]]
        and row.get("implementation") in {"pqcp", "baseline"}
    ]

    if len(primitive_rows) < 18:
        failures.append(
            {
                "check": "row_count",
                "message": (
                    f"expected at least 18 primitive benchmark rows, found {len(primitive_rows)}"
                ),
            }
        )

    seen_rows = {
        (row["parameter_set"], row["operation"], row["implementation"])
        for row in primitive_rows
    }
    for parameter_set, operations in EXPECTED_PRIMITIVE_ROWS.items():
        for operation in operations:
            for implementation in ("pqcp", "baseline"):
                key = (parameter_set, operation, implementation)
                if key not in seen_rows:
                    failures.append(
                        {
                            "check": "missing_row",
                            "message": (
                                "missing benchmark row for "
                                f"{parameter_set} {operation} ({implementation})"
                            ),
                        }
                    )

    pqcp_vs_baseline_us: Dict[Tuple[str, str], Dict[str, float]] = defaultdict(dict)
    for row in primitive_rows:
        context = (
            f"{row['parameter_set']} {row['operation']} ({row['implementation']})"
        )
        for column in ("cycles", "time_us", "rom_bytes", "ram_bytes"):
            numeric, error = _parse_positive_number(row.get(column), f"{context} {column}")
            if error is not None:
                failures.append({"check": "numeric", "message": error})
                continue
            if column == "time_us" and numeric is not None:
                pqcp_vs_baseline_us[(row["parameter_set"], row["operation"])][
                    row["implementation"]
                ] = numeric

    for key, values in sorted(pqcp_vs_baseline_us.items()):
        if "pqcp" not in values or "baseline" not in values:
            failures.append(
                {
                    "check": "ratio_missing",
                    "message": (
                        f"missing pqcp/baseline time_us pair for {key[0]} {key[1]}"
                    ),
                }
            )
            continue
        ratio = values["pqcp"] / values["baseline"]
        if ratio < MIN_PQCP_BASELINE_TIME_RATIO or ratio > MAX_PQCP_BASELINE_TIME_RATIO:
            failures.append(
                {
                    "check": "ratio",
                    "message": (
                        f"{key[0]} {key[1]} pqcp/baseline time_us ratio "
                        f"{ratio:.2f} outside "
                        f"[{MIN_PQCP_BASELINE_TIME_RATIO:.2f}, {MAX_PQCP_BASELINE_TIME_RATIO:.2f}]"
                    ),
                }
            )

    return failures


def validate_benchmark_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != CSV_FIELDNAMES:
            return [
                {
                    "check": "header",
                    "message": (
                        "benchmark export CSV header mismatch: "
                        f"got {reader.fieldnames}, expected {CSV_FIELDNAMES}"
                    ),
                }
            ]
        rows = list(reader)
    return validate_benchmark_rows(rows)


def _file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _git_rev(path: Path) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(path),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    sha = result.stdout.strip()
    return sha or None


def _git_branch(path: Path) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(path),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    branch = result.stdout.strip()
    return branch if branch and branch != "HEAD" else None


def _git_dirty(path: Path) -> Optional[bool]:
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(path),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return bool(result.stdout.strip())


def _west_version(west_cmd: Optional[List[str]]) -> Optional[str]:
    if not west_cmd:
        return None
    try:
        result = subprocess.run(
            list(west_cmd) + ["--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip().splitlines()[0] if result.stdout else None


def build_provenance(
    *,
    csv_path: Path,
    matrix_path: Path,
    rows: List[Dict[str, Any]],
    platform: str,
    smoke: bool,
    module_path: Path,
    west_root: Path,
    west_cmd: Optional[List[str]],
    metric_rows: Optional[List[Dict[str, Any]]] = None,
    comparison_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Collect provenance metadata for a generated benchmark CSV.

    The resulting document is written as a sidecar JSON next to the CSV. It
    gives reviewers an auditable answer to "why should these numbers be
    trusted?" by binding the CSV hash to git SHAs, host info, tooling, and
    per-layer row counts.
    """
    primitive_rows = [
        row
        for row in rows
        if row.get("parameter_set") in EXPECTED_PRIMITIVE_ROWS
    ]
    distribution_rows = [
        row
        for row in primitive_rows
        if row.get("operation") not in EXPECTED_BASE_OPERATIONS
    ]
    protocol_rows = [
        row
        for row in rows
        if row.get("parameter_set") not in EXPECTED_PRIMITIVE_ROWS
    ]
    pqcp_pairs = {
        (row["parameter_set"], row["operation"])
        for row in primitive_rows
        if row.get("implementation") == "pqcp"
    }
    baseline_pairs = {
        (row["parameter_set"], row["operation"])
        for row in primitive_rows
        if row.get("implementation") == "baseline"
    }
    paired_primitive = sorted(pqcp_pairs & baseline_pairs)

    uname = host_platform.uname()
    provenance: Dict[str, Any] = {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/export_results.py",
        "platform": platform,
        "smoke": bool(smoke),
        "csv": {
            "path": csv_path.name,
            "sha256": _file_sha256(csv_path),
            "row_count": len(rows),
            "primitive_row_count": len(primitive_rows),
            "protocol_row_count": len(protocol_rows),
            "distribution_row_count": len(distribution_rows),
            "paired_primitive_rows": [
                f"{pair[0]}/{pair[1]}" for pair in paired_primitive
            ],
        },
        "matrix": {
            "path": str(matrix_path),
            "sha256": _file_sha256(matrix_path) if matrix_path.exists() else None,
        },
        "git": {
            "module_sha": _git_rev(module_path),
            "module_branch": _git_branch(module_path),
            "module_dirty": _git_dirty(module_path),
            "workspace_sha": _git_rev(west_root),
        },
        "host": {
            "system": uname.system,
            "release": uname.release,
            "machine": uname.machine,
            "python": sys.version.split()[0],
        },
        "tooling": {
            "west": _west_version(west_cmd),
            "zephyr_sdk_install_dir": os.environ.get("ZEPHYR_SDK_INSTALL_DIR"),
            "zephyr_toolchain_variant": os.environ.get("ZEPHYR_TOOLCHAIN_VARIANT"),
            "ci": bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")),
        },
        "benchmark_metadata": collect_benchmark_metadata(metric_rows or []),
        "comparison_context": comparison_context
        or build_comparison_context(platform=platform),
    }
    return provenance


def write_provenance(provenance: Dict[str, Any], provenance_path: Path) -> None:
    provenance_path.parent.mkdir(parents=True, exist_ok=True)
    provenance_path.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")


def verify_provenance(csv_path: Path, provenance_path: Path) -> List[Dict[str, str]]:
    """Verify a provenance sidecar matches its CSV.

    Returns a list of failure dicts following the validate_benchmark_rows
    convention. Missing provenance is not an error — callers may opt in.
    """
    failures: List[Dict[str, str]] = []
    try:
        document = json.loads(provenance_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        failures.append({"check": "provenance_load", "message": str(exc)})
        return failures

    if document.get("schema_version") != PROVENANCE_SCHEMA_VERSION:
        failures.append(
            {
                "check": "provenance_schema",
                "message": (
                    f"unexpected schema_version "
                    f"{document.get('schema_version')!r}; expected "
                    f"{PROVENANCE_SCHEMA_VERSION}"
                ),
            }
        )

    csv_meta = document.get("csv") or {}
    recorded_hash = csv_meta.get("sha256")
    actual_hash = _file_sha256(csv_path)
    if recorded_hash != actual_hash:
        failures.append(
            {
                "check": "provenance_hash",
                "message": (
                    f"provenance sha256 {recorded_hash!r} does not match CSV "
                    f"sha256 {actual_hash!r}"
                ),
            }
        )
    failures.extend(validate_comparison_context(document.get("comparison_context")))
    return failures


def validate_output(rows: List[Dict[str, Any]], output_path: Path) -> None:
    if not rows:
        raise RuntimeError("benchmark export produced no timing rows")
    failures = validate_benchmark_csv(output_path)
    if failures:
        rendered = "\n".join(
            f"  - [{failure['check']}] {failure['message']}" for failure in failures
        )
        raise RuntimeError(f"benchmark export CSV validation failed:\n{rendered}")


def main() -> int:
    args = parse_args()
    if args.validate_only is not None:
        csv_path = args.validate_only.resolve()
        failures = validate_benchmark_csv(csv_path)
        if args.verify_provenance:
            provenance_path = (
                args.provenance_output.resolve()
                if args.provenance_output is not None
                else csv_path.with_name("benchmark_provenance.json")
            )
            if not provenance_path.exists():
                failures.append(
                    {
                        "check": "provenance_missing",
                        "message": (
                            f"--verify-provenance requested but {provenance_path} "
                            f"is missing"
                        ),
                    }
                )
            else:
                failures.extend(verify_provenance(csv_path, provenance_path))
        if failures:
            print("[export] Benchmark CSV validation failed:")
            for failure in failures:
                print(f"  - [{failure['check']}] {failure['message']}")
            return 1
        print(f"[export] Benchmark CSV validation passed: {csv_path}")
        if args.verify_provenance:
            print("[export] Provenance sidecar hash matches CSV content")
        return 0

    module_path = args.module_path.resolve() if args.module_path else REPO_ROOT
    west_root = args.west_root.resolve() if args.west_root else detect_west_root(module_path)
    matrix_path = args.matrix.resolve()
    output_path = args.output.resolve()
    summary_path = output_path.with_name("benchmark_summary.md")
    west_cmd = discover_west(args.west, west_root, module_path)

    matrix_entries = select_entries(
        load_matrix(matrix_path),
        platform=args.platform,
        smoke=args.smoke,
    )
    if not matrix_entries:
        raise RuntimeError(
            f"No runnable matrix entries found for platform '{args.platform}'"
        )

    with tempfile.TemporaryDirectory(prefix="pqcp-export-results-") as tmpdir:
        run_output = Path(tmpdir) / "benchmark_run"
        run_output.mkdir(parents=True, exist_ok=True)
        run_matrix(
            matrix_entries,
            matrix_path=matrix_path,
            output_dir=run_output,
            west_root=west_root,
            module_path=module_path,
            west_cmd=west_cmd,
            verbose=args.verbose,
        )

        metric_rows = load_json(run_output / "consolidated_metrics.json")
        runs = load_json(run_output / "runs.json")
        exported = export_rows(metric_rows, runs, platform=args.platform)

    write_csv(exported, output_path)
    write_summary(exported, summary_path)
    validate_output(exported, output_path)

    provenance_path = (
        args.provenance_output.resolve()
        if args.provenance_output is not None
        else output_path.with_name("benchmark_provenance.json")
    )
    provenance = build_provenance(
        csv_path=output_path,
        matrix_path=matrix_path,
        rows=exported,
        metric_rows=metric_rows,
        platform=args.platform,
        smoke=args.smoke,
        module_path=module_path,
        west_root=west_root,
        west_cmd=west_cmd,
        comparison_context=build_comparison_context(
            platform=args.platform,
            source_dataset=args.source_dataset,
            environment_type=args.environment_type,
            board_class=args.board_class,
            clock_assumption=args.clock_assumption,
            statistic_type=args.statistic_type,
            compiler=args.compiler,
            toolchain=args.toolchain,
            optimization_flags=args.optimization_flags,
        ),
    )
    write_provenance(provenance, provenance_path)

    print(
        f"[export] Wrote {len(exported)} benchmark rows to {output_path}"
    )
    print(f"[export] Wrote summary markdown to {summary_path}")
    print(f"[export] Wrote provenance sidecar to {provenance_path}")
    print(f"[export] Generated at {datetime.now(timezone.utc).isoformat()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
