#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation

"""Verify hashes, byte counts, provenance, and benchmark coverage."""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "results/summaries/included_results_manifest.csv"
SUMMARY = ROOT / "results/summaries/results_summary.csv"
PROVENANCE = ROOT / "results/final/benchmark_provenance.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repository_path(raw_path: str) -> Path:
    logical = PurePosixPath(raw_path)
    if logical.is_absolute() or ".." in logical.parts:
        raise ValueError(f"unsafe manifest path: {raw_path}")
    resolved = (ROOT / Path(*logical.parts)).resolve()
    if ROOT not in resolved.parents:
        raise ValueError(f"manifest path escapes repository: {raw_path}")
    return resolved


def verify_manifest() -> int:
    with MANIFEST.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    if not rows:
        raise ValueError("artifact manifest is empty")
    if set(rows[0]) != {"path", "sha256", "bytes"}:
        raise ValueError("artifact manifest has unexpected columns")

    seen: set[str] = set()
    for row in rows:
        raw_path = row["path"]
        if raw_path in seen:
            raise ValueError(f"duplicate artifact path: {raw_path}")
        seen.add(raw_path)

        path = repository_path(raw_path)
        if not path.is_file():
            raise FileNotFoundError(raw_path)
        expected_bytes = int(row["bytes"])
        actual_bytes = path.stat().st_size
        if actual_bytes != expected_bytes:
            raise ValueError(
                f"{raw_path}: bytes {actual_bytes}, expected {expected_bytes}"
            )
        actual_hash = sha256(path)
        if actual_hash != row["sha256"]:
            raise ValueError(
                f"{raw_path}: sha256 {actual_hash}, expected {row['sha256']}"
            )
    return len(rows)


def verify_summary() -> int:
    with SUMMARY.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    required = {
        "suite",
        "parameter_set",
        "operation",
        "platform",
        "pqcp_cycles",
        "baseline_cycles",
        "overhead_percent",
        "pqcp_rom_bytes",
        "pqcp_ram_bytes",
        "status",
    }
    if not rows or required - set(rows[0]):
        raise ValueError("results summary is empty or missing required columns")

    expected_parameter_sets = {
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
    }
    observed_parameter_sets = {row["parameter_set"] for row in rows}
    if observed_parameter_sets != expected_parameter_sets:
        raise ValueError(
            "unexpected parameter-set coverage: "
            f"{sorted(observed_parameter_sets)}"
        )
    if any(row["platform"] != "qemu_x86_64" for row in rows):
        raise ValueError("summary mixes platforms without an explicit split")
    if any(int(row["pqcp_cycles"]) <= 0 for row in rows):
        raise ValueError("summary contains a non-positive PQCP cycle count")
    if any(int(row["baseline_cycles"]) <= 0 for row in rows):
        raise ValueError("summary contains a non-positive baseline cycle count")
    return len(rows)


def verify_provenance() -> int:
    data = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    csv_record = data["csv"]
    csv_path = repository_path(csv_record["path"])
    if sha256(csv_path) != csv_record["sha256"]:
        raise ValueError("benchmark provenance does not bind the current CSV")
    with csv_path.open(newline="", encoding="utf-8") as handle:
        row_count = sum(1 for _ in csv.DictReader(handle))
    if row_count != int(csv_record["row_count"]):
        raise ValueError(
            f"benchmark row count {row_count}, "
            f"expected {csv_record['row_count']}"
        )
    if len(csv_record["paired_primitive_rows"]) * 2 != row_count:
        raise ValueError("paired primitive coverage does not match source rows")
    return row_count


def main() -> int:
    try:
        artifact_count = verify_manifest()
        summary_count = verify_summary()
        source_count = verify_provenance()
    except (KeyError, OSError, TypeError, ValueError) as exc:
        print(f"public artifact verification failed: {exc}", file=sys.stderr)
        return 1

    print(
        "public artifact verification: PASS "
        f"({artifact_count} hashed artifacts, "
        f"{summary_count} summary rows, {source_count} source rows)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
