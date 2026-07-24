#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Instruction-count constant-time check for ML-KEM decapsulation.

Builds tests/ztest_ct_instr, builds the pqcp_ct_insn TCG plugin, resolves
the bracketing marker addresses from the ELF symbol table, runs the image
under QEMU with the plugin, and asserts that every valid-ciphertext
decapsulation region executed the same number of guest instructions as
every corrupted-ciphertext region.

Equality means the decapsulation control flow is input-independent at
guest-instruction granularity - stronger than the wall-clock ct_smoke
bound, still not a formal constant-time proof. The C plugin and firmware do
the measurement; this script only orchestrates and compares.
"""

import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from local_workflow import (  # noqa: E402
    clean_env,
    detect_west_root,
    discover_west,
    run_command,
)

PLUGIN_DIR = MODULE_PATH / "tools" / "tcg_ct_plugin"
TEST_APP = MODULE_PATH / "tests" / "ztest_ct_instr"
DEVICE_MARKER = "PQCP_CT_INSTR alg=MLKEM-768"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--west-root", type=Path, help="Zephyr workspace root")
    parser.add_argument("--west", help="Explicit west binary or command")
    parser.add_argument("--build-dir", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument(
        "--qemu-plugin-inc",
        type=Path,
        default=None,
        help="Directory containing qemu-plugin.h (autodetected from SDK)",
    )
    parser.add_argument("--run-timeout", type=int, default=120)
    return parser.parse_args()


def detect_plugin_include(env: dict) -> Path | None:
    sdk = env.get("ZEPHYR_SDK_INSTALL_DIR") or os.environ.get(
        "ZEPHYR_SDK_INSTALL_DIR")
    candidates = []
    if sdk:
        candidates.append(Path(sdk) / "hosttools/opt/qemu/include")
    home = Path(os.path.expanduser("~"))
    candidates += sorted(home.glob("zephyr-sdk-*/hosttools/opt/qemu/include"))
    for cand in candidates:
        if (cand / "qemu-plugin.h").exists():
            return cand
    return None


def glib_cflags() -> str:
    if shutil.which("pkg-config"):
        result = subprocess.run(
            ["pkg-config", "--cflags", "glib-2.0"],
            capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    for base in ("/opt/homebrew", "/usr/local"):
        inc = Path(base) / "include/glib-2.0"
        lib_inc = Path(base) / "lib/glib-2.0/include"
        if inc.exists() and lib_inc.exists():
            return f"-I{inc} -I{lib_inc}"
    return ""


def resolve_symbol(elf: Path, symbol: str, env: dict) -> int:
    nm = shutil.which("nm") or "nm"
    result = subprocess.run(
        [nm, str(elf)], capture_output=True, text=True, env=env)
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == symbol:
            return int(parts[0], 16)
    raise RuntimeError(f"symbol {symbol} not found in {elf}")


def qemu_run_command(build_dir: Path) -> list[str]:
    ninja = build_dir / "build.ninja"
    text = ninja.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        if "qemu-system-" not in line or " -kernel " not in line:
            continue
        # Strip any "cd <dir> && " prefix but keep the full qemu binary path.
        cmd = line.split("COMMAND = ", 1)[-1].strip()
        if "&& " in cmd:
            cmd = cmd.split("&& ", 1)[1].strip()
        return cmd
    raise RuntimeError("could not find a qemu run command in build.ninja")


def main() -> int:
    if shutil.which("cmake") is None and shutil.which("make") is None:
        print("[ct-insn] SKIP: no host build tools")
        return 0

    args = parse_args()
    env = clean_env()
    output_dir = args.output_dir or (MODULE_PATH / "build-ct-instruction")
    output_dir.mkdir(parents=True, exist_ok=True)
    build_dir = args.build_dir or (output_dir / "build-ct-instr")
    plugin_inc = args.qemu_plugin_inc or detect_plugin_include(env)
    if plugin_inc is None:
        print("[ct-insn] FAIL: could not locate qemu-plugin.h")
        return 1

    west_root = detect_west_root(args.west_root or MODULE_PATH)
    west_cmd = discover_west(args.west, west_root, MODULE_PATH)

    print("[ct-insn] Building ztest_ct_instr for qemu_x86_64")
    run_command(
        [
            *west_cmd, "build", "-p", "always", "-b", "qemu_x86_64",
            str(TEST_APP), "-d", str(build_dir),
            "--", f"-DZEPHYR_EXTRA_MODULES={MODULE_PATH}",
        ],
        cwd=west_root, env=env, timeout=600)

    print("[ct-insn] Building pqcp_ct_insn TCG plugin")
    plugin_ext = "dylib" if sys.platform == "darwin" else "so"
    run_command(
        ["make", "-C", str(PLUGIN_DIR), "clean"],
        cwd=MODULE_PATH, env=env, timeout=60)
    run_command(
        ["make", "-C", str(PLUGIN_DIR),
         f"QEMU_PLUGIN_INC={plugin_inc}",
         f"GLIB_CFLAGS={glib_cflags()}"],
        cwd=MODULE_PATH, env=env, timeout=120)
    plugin_path = PLUGIN_DIR / f"libpqcp_ct_insn.{plugin_ext}"
    if not plugin_path.exists():
        print(f"[ct-insn] FAIL: plugin not built at {plugin_path}")
        return 1

    # The locore/main split ELFs the qemu command boots are produced by
    # dedicated ninja targets, not the default build.
    print("[ct-insn] Generating QEMU loader images")
    run_command(
        ["ninja", "-C", str(build_dir),
         "zephyr/qemu_locore_image_target",
         "zephyr/qemu_main_image_target"],
        cwd=MODULE_PATH, env=env, timeout=120)

    elf = build_dir / "zephyr" / "zephyr.elf"
    begin = resolve_symbol(elf, "pqcp_ct_region_begin", env)
    end = resolve_symbol(elf, "pqcp_ct_region_end", env)
    print(f"[ct-insn] markers begin=0x{begin:x} end=0x{end:x}")

    outfile = output_dir / "ct_insn_regions.txt"
    if outfile.exists():
        outfile.unlink()
    device_log = output_dir / "ct_instr_device.log"

    qemu_cmd = qemu_run_command(build_dir)
    plugin_arg = (f"{plugin_path},begin=0x{begin:x},end=0x{end:x},"
                  f"outfile={outfile}")
    # Inject -plugin immediately after the qemu binary token.
    binary_token, rest = qemu_cmd.split(" ", 1)
    qemu_cmd = f"{binary_token} -plugin {plugin_arg} {rest}"

    print("[ct-insn] Running ML-KEM decapsulation under the plugin")
    log_handle = device_log.open("w")
    proc = subprocess.Popen(
        qemu_cmd, shell=True, cwd=str(build_dir), env=env,
        stdout=log_handle, stderr=subprocess.STDOUT,
        start_new_session=True)
    deadline = time.time() + args.run_timeout
    saw_marker = False
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        if device_log.exists() and DEVICE_MARKER in device_log.read_text(
                errors="replace"):
            saw_marker = True
            time.sleep(1)
            break
        time.sleep(1)
    if proc.poll() is None:
        os.killpg(os.getpgid(proc.pid), signal.SIGINT)
        time.sleep(2)
        if proc.poll() is None:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    log_handle.close()

    device_text = device_log.read_text(errors="replace")
    if DEVICE_MARKER not in device_text:
        print("[ct-insn] FAIL: device marker not observed")
        print(device_text[-2000:])
        return 1
    print(f"[ct-insn] {DEVICE_MARKER} observed")

    if not outfile.exists():
        print("[ct-insn] FAIL: plugin produced no region outfile")
        return 1

    counts: list[tuple[int, int, int]] = []
    for line in outfile.read_text().splitlines():
        m = re.match(
            r"PQCP_CT_INSN region=(\d+) insns=(\d+) loads=(\d+) stores=(\d+)",
            line)
        if m:
            counts.append((int(m.group(2)), int(m.group(3)),
                           int(m.group(4))))
    print(f"[ct-insn] captured {len(counts)} region counts")

    half = len(counts) // 2
    if len(counts) < 2 or half == 0:
        print("[ct-insn] FAIL: too few regions captured")
        print(outfile.read_text())
        return 1

    valid_counts = counts[:half]
    corrupt_counts = counts[half:]
    unique = sorted(set(counts))
    print(f"[ct-insn] valid-region (insns, loads, stores): "
          f"{sorted(set(valid_counts))}")
    print(f"[ct-insn] corrupt-region (insns, loads, stores): "
          f"{sorted(set(corrupt_counts))}")

    if len(unique) != 1:
        print("[ct-insn] FAIL: execution profiles differ across regions: "
              f"{unique}")
        print("[ct-insn] valid vs corrupt decapsulation are distinguishable "
              "at instruction or memory-access granularity")
        return 1

    insns, loads, stores = unique[0]
    print(f"PQCP_CT_INSTRUCTION_COUNT PASS regions={len(counts)} "
          f"insns_per_region={insns} loads_per_region={loads} "
          f"stores_per_region={stores} alg=MLKEM-768")
    print("[ct-insn] PASS: valid and corrupted decapsulation execute an "
          "identical guest-instruction count and an identical "
          "guest memory-access count")
    return 0


if __name__ == "__main__":
    sys.exit(main())
