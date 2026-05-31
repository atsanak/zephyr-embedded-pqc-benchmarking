#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation

"""Summarize paired PQCP-vs-baseline benchmark CSV files."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "csv",
        type=Path,
        nargs="?",
        default=Path("results/final/validated_primitive_benchmarks_qemu.csv"),
        help="Benchmark CSV with paired pqcp/baseline rows.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional CSV summary output path.",
    )
    return parser.parse_args()


def load_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise FileNotFoundError(path)
    with path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    required = {
        "suite",
        "parameter_set",
        "implementation",
        "operation",
        "cycles",
        "platform",
    }
    missing = required - set(rows[0].keys() if rows else [])
    if missing:
        raise ValueError(f"{path} missing required columns: {sorted(missing)}")
    return rows


def summarize(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    grouped: dict[tuple[str, str, str, str], dict[str, dict[str, str]]] = {}
    for row in rows:
        key = (
            row["suite"],
            row["parameter_set"],
            row["operation"],
            row["platform"],
        )
        grouped.setdefault(key, {})[row["implementation"]] = row

    output: list[dict[str, str]] = []
    for key, pair in sorted(grouped.items()):
        if "pqcp" not in pair or "baseline" not in pair:
            continue
        pqcp_cycles = int(pair["pqcp"]["cycles"])
        baseline_cycles = int(pair["baseline"]["cycles"])
        overhead = ((pqcp_cycles - baseline_cycles) / baseline_cycles) * 100.0
        output.append(
            {
                "suite": key[0],
                "parameter_set": key[1],
                "operation": key[2],
                "platform": key[3],
                "pqcp_cycles": str(pqcp_cycles),
                "baseline_cycles": str(baseline_cycles),
                "overhead_percent": f"{overhead:.2f}",
                "status": "faster" if overhead < 0 else "slower",
            }
        )
    return output


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "suite",
        "parameter_set",
        "operation",
        "platform",
        "pqcp_cycles",
        "baseline_cycles",
        "overhead_percent",
        "status",
    ]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    args = parse_args()
    try:
        summary = summarize(load_rows(args.csv))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.output:
        write_csv(args.output, summary)

    print("suite,parameter_set,operation,platform,pqcp_cycles,baseline_cycles,overhead_percent,status")
    for row in summary:
        print(
            ",".join(
                row[key]
                for key in (
                    "suite",
                    "parameter_set",
                    "operation",
                    "platform",
                    "pqcp_cycles",
                    "baseline_cycles",
                    "overhead_percent",
                    "status",
                )
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
