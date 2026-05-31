#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""
PQCP Benchmark Log Parser

Parses serial output logs from PQCP benchmarks and generates CSV files.

Supports two log formats:
1. Legacy: PRIM,MLKEM768,KEYGEN,cycles=12345,stack=2048,text=4096,bss=256,backend=C
2. New:    PQCP_METRIC,primitive,keygen,MLKEM,768,cycles,12345,cyc

Usage:
    python parse_logs.py <log_file> [--output-dir <dir>]
    python parse_logs.py benchmark_results.json --from-json
    python parse_logs.py --self-test
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import List, Dict, Optional
from collections import defaultdict

ANSI_ESCAPE_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def parse_pqcp_metric_line(line: str) -> Optional[Dict]:
    """Parse a PQCP_METRIC line.

    Format: PQCP_METRIC,<component>,<operation>,<algo>,<level>,<metric>,<value>,<unit>
    """
    pattern = re.compile(
        r'^PQCP_METRIC,([^,]+),([^,]+),([^,]+),(-?\d+),([^,]+),([^,]*),([^,]*)$'
    )

    m = pattern.match(line)
    if not m:
        return None

    return {
        'type': 'pqcp_metric',
        'component': m.group(1),
        'operation': m.group(2),
        'algorithm': m.group(3),
        'level': int(m.group(4)),
        'metric': m.group(5),
        'value': m.group(6),  # Keep as string for status values
        'unit': m.group(7) or '',
    }


def parse_primitive_line(line: str) -> Optional[Dict]:
    """Parse a primitive benchmark line."""
    # Format: PRIM,MLKEM768,KEYGEN,cycles=12345,us=67,stack=2048,text=4096,bss=256,backend=C
    pattern = re.compile(
        r'PRIM,(\w+?)(\d+),(\w+),'
        r'(\w+)=(\d+),'  # time unit
        r'(?:us=(\d+),)?'
        r'stack=(\d+),'
        r'text=(\d+),'
        r'bss=(\d+)'
        r'(?:,backend=(\w+))?'
    )

    m = pattern.match(line)
    if not m:
        return None

    return {
        'type': 'primitive',
        'algorithm': m.group(1),
        'level': int(m.group(2)),
        'operation': m.group(3),
        'time_unit': m.group(4),
        'time_value': int(m.group(5)),
        'time_us': int(m.group(6)) if m.group(6) else None,
        'stack_bytes': int(m.group(7)),
        'text_bytes': int(m.group(8)),
        'bss_bytes': int(m.group(9)),
        'backend': m.group(10) or 'unknown',
    }


def parse_protocol_line(line: str) -> Optional[Dict]:
    """Parse a protocol benchmark line."""
    # Format: TLS,MLKEM768+MLDSA65,handshake_ms=150,cpu_pct=45,peak_kib=32,...
    pattern = re.compile(
        r'^TLS,([^,]+),handshake_ms=(\d+),'
        r'cpu_pct=(\d+),'
        r'peak_kib=(\d+),'
        r'transcript_bytes=(\d+),'
        r'frags=(\d+)'
        r'(?:,p50=(\d+))?'
        r'(?:,p90=(\d+))?'
        r'(?:,p99=(\d+))?$'
    )

    m = pattern.match(line)
    if not m:
        return None

    return {
        'type': 'protocol',
        'suite': m.group(1),
        'handshake_ms': int(m.group(2)),
        'cpu_percent': int(m.group(3)),
        'peak_ram_kib': int(m.group(4)),
        'transcript_bytes': int(m.group(5)),
        'fragments': int(m.group(6)),
        'p50_ms': int(m.group(7)) if m.group(7) else None,
        'p90_ms': int(m.group(8)) if m.group(8) else None,
        'p99_ms': int(m.group(9)) if m.group(9) else None,
    }


def parse_log_file(log_path: Path) -> List[Dict]:
    """Parse a log file and extract benchmark results."""
    results = []

    with open(log_path, 'r') as f:
        for line in f:
            line = ANSI_ESCAPE_RE.sub('', line).strip()

            # Try new PQCP_METRIC format first
            result = parse_pqcp_metric_line(line)
            if result:
                results.append(result)
                continue

            # Try legacy PRIM format
            result = parse_primitive_line(line)
            if result:
                results.append(result)
                continue

            # Try legacy TLS format
            result = parse_protocol_line(line)
            if result:
                results.append(result)

    return results


def load_json_results(json_path: Path) -> List[Dict]:
    """Load results from JSON file."""
    with open(json_path, 'r') as f:
        return json.load(f)


def write_primitive_csv(results: List[Dict], output_path: Path):
    """Write primitive benchmark results to CSV."""
    primitives = [r for r in results if r.get('type') == 'primitive']

    if not primitives:
        print("No legacy primitive results to write")
    else:
        fieldnames = [
            'algorithm', 'level', 'operation',
            'time_unit', 'time_value',
            'time_us',
            'stack_bytes', 'text_bytes', 'bss_bytes',
            'backend', 'target', 'timestamp'
        ]

        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(primitives)

        print(f"Wrote {len(primitives)} legacy primitive results to {output_path}")


def write_metrics_csv(results: List[Dict], output_path: Path):
    """Write PQCP_METRIC results to CSV."""
    metrics = [r for r in results if r.get('type') == 'pqcp_metric']

    if not metrics:
        print("No PQCP_METRIC results to write")
        return

    fieldnames = [
        'component', 'operation', 'algorithm', 'level',
        'metric', 'value', 'unit'
    ]

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(metrics)

    print(f"Wrote {len(metrics)} PQCP_METRIC results to {output_path}")


def write_protocol_csv(results: List[Dict], output_path: Path):
    """Write protocol benchmark results to CSV."""
    protocols = [r for r in results if r.get('type') == 'protocol']

    if not protocols:
        print("No protocol results to write")
        return

    fieldnames = [
        'suite', 'handshake_ms', 'cpu_percent',
        'peak_ram_kib', 'transcript_bytes', 'fragments',
        'p50_ms', 'p90_ms', 'p99_ms',
        'target', 'timestamp'
    ]

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(protocols)

    print(f"Wrote {len(protocols)} protocol results to {output_path}")


def write_summary(results: List[Dict], output_path: Path):
    """Write a human-readable summary."""

    # Group by algorithm and operation
    primitives = defaultdict(list)
    for r in results:
        if r.get('type') == 'primitive':
            key = (r['algorithm'], r['level'], r['operation'])
            primitives[key].append(r)

    with open(output_path, 'w') as f:
        f.write("PQCP Benchmark Summary\n")
        f.write("=" * 60 + "\n\n")

        # Primitive benchmarks
        f.write("Primitive Benchmarks\n")
        f.write("-" * 40 + "\n\n")

        f.write(f"{'Algorithm':<15} {'Op':<10} {'Time':<12} {'Stack':<8} {'Code':<8}\n")
        f.write("-" * 60 + "\n")

        for key in sorted(primitives.keys()):
            alg, level, op = key
            data = primitives[key]

            # Average if multiple runs
            avg_time = sum(r.get('time_value', r.get('cycles', 0)) for r in data) // len(data)
            avg_stack = sum(r.get('stack_bytes', r.get('stack', 0)) for r in data) // len(data)
            text_size = data[0].get('text_bytes', data[0].get('text', 0))

            time_unit = data[0].get('time_unit', 'cycles')

            f.write(f"{alg}-{level:<6} {op:<10} {avg_time:>8} {time_unit:<3} "
                   f"{avg_stack:>6}B {text_size:>6}B\n")

        # Protocol benchmarks
        protocols = [r for r in results if r.get('type') == 'protocol']
        if protocols:
            f.write("\n\nProtocol Benchmarks\n")
            f.write("-" * 40 + "\n\n")

            f.write(f"{'Suite':<25} {'Latency':<10} {'RAM':<8} {'TX Bytes':<10}\n")
            f.write("-" * 60 + "\n")

            for p in protocols:
                f.write(f"{p['suite']:<25} {p['handshake_ms']:>6} ms "
                       f"{p['peak_ram_kib']:>5} KiB {p['transcript_bytes']:>8}\n")

    print(f"Wrote summary to {output_path}")


def run_self_test() -> None:
    """Exercise parser examples that mirror the emitted benchmark ABI."""
    primitive = parse_primitive_line(
        "PRIM,MLKEM768,MLKEM_KEYPAIR,cycles=12345,us=67,"
        "stack=2048,text=4096,bss=256,backend=C"
    )
    assert primitive is not None
    assert primitive["algorithm"] == "MLKEM"
    assert primitive["level"] == 768
    assert primitive["operation"] == "MLKEM_KEYPAIR"
    assert primitive["time_unit"] == "cycles"
    assert primitive["time_value"] == 12345
    assert primitive["time_us"] == 67
    assert primitive["stack_bytes"] == 2048
    assert primitive["text_bytes"] == 4096
    assert primitive["bss_bytes"] == 256
    assert primitive["backend"] == "C"

    metric = parse_pqcp_metric_line(
        "PQCP_METRIC,primitive,keygen,MLKEM,768,time,67,us"
    )
    assert metric is not None
    assert metric["component"] == "primitive"
    assert metric["operation"] == "keygen"
    assert metric["algorithm"] == "MLKEM"
    assert metric["level"] == 768
    assert metric["metric"] == "time"
    assert metric["value"] == "67"
    assert metric["unit"] == "us"

    distribution = parse_pqcp_metric_line(
        "PQCP_METRIC,primitive,keygen,MLKEM,768,cycles_median,12345,cyc"
    )
    assert distribution is not None
    assert distribution["metric"] == "cycles_median"
    assert distribution["value"] == "12345"
    assert distribution["unit"] == "cyc"

    metadata = parse_pqcp_metric_line(
        "PQCP_METRIC,build,metadata,compiler,0,id,clang-18,"
    )
    assert metadata is not None
    assert metadata["component"] == "build"
    assert metadata["operation"] == "metadata"
    assert metadata["algorithm"] == "compiler"
    assert metadata["metric"] == "id"
    assert metadata["value"] == "clang-18"

    print("parse_logs.py self-test passed")


def main():
    parser = argparse.ArgumentParser(description="PQCP Benchmark Log Parser")
    parser.add_argument("input", nargs="?", help="Input log file or JSON")
    parser.add_argument("--output-dir", "-o", default=".",
                        help="Output directory for CSV files")
    parser.add_argument("--from-json", action="store_true",
                        help="Input is JSON instead of raw log")
    parser.add_argument("--self-test", action="store_true",
                        help="Run built-in parser contract tests")

    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return

    if args.input is None:
        parser.error("input is required unless --self-test is used")

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Parse input
    if args.from_json:
        results = load_json_results(input_path)
    else:
        results = parse_log_file(input_path)

    print(f"Parsed {len(results)} results")

    # Count by type
    metric_count = sum(1 for r in results if r.get('type') == 'pqcp_metric')
    legacy_count = sum(1 for r in results if r.get('type') == 'primitive')
    proto_count = sum(1 for r in results if r.get('type') == 'protocol')

    print(f"  - PQCP_METRIC: {metric_count}")
    print(f"  - Legacy PRIM: {legacy_count}")
    print(f"  - Protocol:    {proto_count}")

    # Generate outputs
    stem = input_path.stem

    write_metrics_csv(results, output_dir / f"{stem}_metrics.csv")
    write_primitive_csv(results, output_dir / f"{stem}_primitives.csv")
    write_protocol_csv(results, output_dir / f"{stem}_protocols.csv")
    write_summary(results, output_dir / f"{stem}_summary.txt")


if __name__ == "__main__":
    main()
