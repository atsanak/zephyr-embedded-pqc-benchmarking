#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""
PQCP benchmark orchestration.

Builds and runs a configurable board/profile/sample matrix, captures per-run
logs, parses PQCP_METRIC output, and writes consolidated CSV/JSON artifacts.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import os
import re
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
PARSER_SPEC = importlib.util.spec_from_file_location(
    "pqcp_parse_logs", SCRIPT_DIR / "parse_logs.py"
)
if PARSER_SPEC is None or PARSER_SPEC.loader is None:
    raise RuntimeError("Unable to load parse_logs.py")
PARSER_MODULE = importlib.util.module_from_spec(PARSER_SPEC)
PARSER_SPEC.loader.exec_module(PARSER_MODULE)

parse_log_file = PARSER_MODULE.parse_log_file
write_metrics_csv = PARSER_MODULE.write_metrics_csv
write_primitive_csv = PARSER_MODULE.write_primitive_csv
write_protocol_csv = PARSER_MODULE.write_protocol_csv
write_summary = PARSER_MODULE.write_summary

DEFAULT_BOARDS = ["qemu_x86_64", "mps2/an385"]
DEFAULT_MATRIX_SAMPLES = [
    "pqcp_basic_kem",
    "pqcp_basic_sig",
    "pqcp_streaming_hash_mldsa",
    "pqcp_tls_mbedtls_psa",
    "pqcp_bench_protocol",
]

SAMPLE_SUCCESS_MARKERS = (
    "PROJECT EXECUTION SUCCESSFUL",
    "Sample completed successfully!",
    "Protocol benchmark completed!",
)

PROFILES: Dict[str, Dict[str, str]] = {
    "MCU_MINIMAL": {
        "kconfig": "CONFIG_PQCP_PROFILE_MCU_MINIMAL=y",
        "description": "Conservative production-oriented MCU profile",
    },
    "GATEWAY": {
        "kconfig": "CONFIG_PQCP_PROFILE_GATEWAY=y",
        "description": "PSA/TLS capable gateway profile",
    },
    "NATIVE_LAB": {
        "kconfig": "CONFIG_PQCP_PROFILE_NATIVE_LAB=y",
        "description": "Lab/development profile with benchmarking",
    },
    "COA_QEMU_SINGLE_LEVEL": {
        "kconfig": "",
        "description": (
            "Analysis-only qemu_x86_64 single-level profile label used by "
            "cost-of-assurance runs that must override the production profile "
            "level selects without changing their semantics"
        ),
    },
    "COA_MCU_SINGLE_LEVEL": {
        "kconfig": "",
        "description": (
            "Analysis-only MCU single-level profile label used by "
            "cost-of-assurance build-only rows that override production "
            "levels without changing their documented semantics"
        ),
    },
}

BACKEND_POLICIES: Dict[str, Dict[str, Any]] = {
    "auto": {
        "kconfig": [],
        "description": "Automatic backend selection for the current target",
    },
    "force_c": {
        "kconfig": ["CONFIG_PQCP_BACKEND_FORCE_C=y"],
        "description": "Portable C backend forced for comparison runs",
    },
    "force_native": {
        "kconfig": ["CONFIG_PQCP_BACKEND_FORCE_NATIVE=y"],
        "description": "Native backend forced for comparison runs",
    },
    "clean": {
        "kconfig": ["CONFIG_PQCP_BACKEND_CLEAN=y"],
        "description": "Native-C/reference backend label used by the QEMU baseline provider",
    },
}

IMPLEMENTATION_FAMILIES: Dict[str, Dict[str, Any]] = {
    "pqcp": {
        "kconfig": [],
        "description": "PQ Code Package provider family",
    },
    "baseline": {
        "kconfig": ["CONFIG_PQCP_IMPLEMENTATION_BASELINE=y"],
        "description": "QEMU-only native-C reference baseline provider",
    },
}

DEFAULT_BENCHMARK_MATRIX = SCRIPT_DIR / "benchmark_matrix.json"
DEFAULT_COST_OF_ASSURANCE_MATRIX = SCRIPT_DIR / "cost_of_assurance_matrix.json"
DEFAULT_PROFILE_VALIDATION_MATRIX = SCRIPT_DIR / "profile_validation_matrix.json"

sys.path.insert(0, str(SCRIPT_DIR))
from local_workflow import (  # noqa: E402
    HOST_ENV_BLACKLIST,
    detect_west_root as _shared_detect_west_root,
    discover_west as _shared_discover_west,
)

SAMPLES: Dict[str, Dict[str, Any]] = {
    "pqcp_basic_kem": {
        "path": "samples/pqcp_basic_kem",
        "profiles": [
            "MCU_MINIMAL",
            "GATEWAY",
            "NATIVE_LAB",
            "COA_QEMU_SINGLE_LEVEL",
            "COA_MCU_SINGLE_LEVEL",
        ],
        "boards": DEFAULT_BOARDS,
        "overlays": [],
        "run_timeout": 20,
    },
    "pqcp_basic_sig": {
        "path": "samples/pqcp_basic_sig",
        "profiles": [
            "MCU_MINIMAL",
            "GATEWAY",
            "NATIVE_LAB",
            "COA_QEMU_SINGLE_LEVEL",
            "COA_MCU_SINGLE_LEVEL",
        ],
        "boards": DEFAULT_BOARDS,
        "overlays": [],
        "run_timeout": 20,
    },
    "pqcp_streaming_hash_mldsa": {
        "path": "samples/pqcp_streaming_hash_mldsa",
        "profiles": ["GATEWAY", "NATIVE_LAB"],
        "boards": DEFAULT_BOARDS,
        "overlays": [],
        "run_timeout": 60,
    },
    "pqcp_tls_mbedtls_psa": {
        "path": "samples/pqcp_tls_mbedtls_psa",
        "profiles": ["GATEWAY", "NATIVE_LAB"],
        "boards": ["qemu_x86_64"],
        "overlays": ["overlay-selftest.conf"],
        "run_timeout": 60,
    },
    "pqcp_bench_protocol": {
        "path": "samples/pqcp_bench_protocol",
        "profiles": [
            "MCU_MINIMAL",
            "GATEWAY",
            "NATIVE_LAB",
            "COA_QEMU_SINGLE_LEVEL",
            "COA_MCU_SINGLE_LEVEL",
        ],
        "boards": DEFAULT_BOARDS,
        "overlays": [],
        "run_timeout": 60,
    },
    "pqcp_kat_deterministic": {
        "path": "samples/pqcp_kat_deterministic",
        "profiles": ["NATIVE_LAB"],
        "boards": ["qemu_x86_64"],
        "overlays": [],
        "run_timeout": 60,
    },
}


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    timed_out: bool


@dataclass
class RunSpec:
    run_id: str
    board: str
    profile: str
    sample: str
    implementation: str
    backend: str
    app_path: str
    overlays: List[str]
    extra_kconfig: List[str]
    run_timeout: int
    run_mode: str
    build_only: bool


@dataclass
class RunRecord:
    run_id: str
    board: str
    profile: str
    sample: str
    implementation: str
    backend: str
    app_path: str
    build_dir: str
    log_path: str
    build_ok: bool
    run_ok: bool
    timed_out: bool
    run_mode: str
    build_only: bool
    metric_count: int
    size_text: int
    size_data: int
    size_bss: int
    rom_bytes: int
    ram_bytes: int
    budget_ok: bool
    budget_failures: List[str]


def slugify(value: str) -> str:
    return value.replace("/", "_").replace(" ", "_").lower()


def default_timeout_for_path(app_path: str) -> int:
    return 120 if app_path.startswith("tests/") else 60


def normalize_backend_policy(value: Optional[str]) -> str:
    policy = str(value or "auto").strip().lower().replace("-", "_")
    if policy not in BACKEND_POLICIES:
        raise ValueError(
            f"Unknown backend policy '{value}'. Expected one of: "
            f"{', '.join(sorted(BACKEND_POLICIES))}"
        )
    return policy


def normalize_implementation_name(value: Optional[str]) -> str:
    implementation = str(value or "pqcp").strip().lower().replace("-", "_")
    if not implementation:
        raise ValueError("Implementation name must not be empty")
    if not re.fullmatch(r"[a-z0-9_]+", implementation):
        raise ValueError(
            f"Invalid implementation '{value}'. Use lowercase letters, digits, or underscores."
        )
    return implementation


def implementation_kconfig_lines(implementation: str) -> List[str]:
    return list(IMPLEMENTATION_FAMILIES.get(implementation, {}).get("kconfig", []))


def normalize_run_mode(value: Optional[str], *, build_only: bool = False) -> str:
    if value is None:
        return "build_only" if build_only else "run"

    run_mode = str(value).strip().lower().replace("-", "_")
    if run_mode not in {"run", "build_only"}:
        raise ValueError(
            f"Unknown run mode '{value}'. Expected one of: run, build_only"
        )
    return run_mode


def resolve_run_mode(
    value: Optional[str],
    *,
    build_only: bool = False,
    run: Optional[bool] = None,
    build: Optional[bool] = None,
) -> str:
    if value is not None:
        return normalize_run_mode(value, build_only=build_only)

    if build_only:
        return "build_only"

    if run is None and build is None:
        return normalize_run_mode(None, build_only=False)

    run_enabled = bool(run)
    build_enabled = bool(build)

    if run_enabled and not build_enabled:
        return "run"
    if build_enabled and not run_enabled:
        return "build_only"
    if run_enabled and build_enabled:
        return "run"

    raise ValueError(
        "Matrix entries using run/build booleans must enable at least one mode"
    )


def make_run_id(
    board: str,
    profile: str,
    label: str,
    backend: Optional[str] = None,
    implementation: Optional[str] = None,
    variant: Optional[str] = None,
) -> str:
    parts = [slugify(board), slugify(profile), slugify(label)]
    if variant:
        parts.append(slugify(variant))
    implementation_name = normalize_implementation_name(implementation)
    if implementation_name != "pqcp":
        parts.append(slugify(implementation_name))
    backend_policy = normalize_backend_policy(backend)
    if backend_policy != "auto":
        parts.append(slugify(backend_policy))
    return "__".join(parts)


def infer_level_variant(extra_kconfig: Iterable[str]) -> Optional[str]:
    levels: List[str] = []
    for line in extra_kconfig:
        normalized = str(line).strip()
        if normalized.startswith("CONFIG_PQCP_MLKEM_LEVEL_") and normalized.endswith("=y"):
            levels.append("mlkem" + normalized.removeprefix("CONFIG_PQCP_MLKEM_LEVEL_").removesuffix("=y"))
        elif normalized.startswith("CONFIG_PQCP_MLDSA_LEVEL_") and normalized.endswith("=y"):
            levels.append("mldsa" + normalized.removeprefix("CONFIG_PQCP_MLDSA_LEVEL_").removesuffix("=y"))
    return "_".join(levels).lower() if levels else None


def normalize_overlays(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value]


def is_protocol_label(label: str) -> bool:
    return label in {
        "pqcp_bench_protocol",
        "pqcp_tls_mbedtls_psa",
        "ztest_tls_selftest",
    }


def is_protocol_run(spec: RunSpec) -> bool:
    label = spec.sample or Path(spec.app_path).name
    app_name = Path(spec.app_path).name
    return is_protocol_label(label) or is_protocol_label(app_name)


def filter_specs(
    specs: Iterable[RunSpec],
    *,
    boards: Optional[Iterable[str]] = None,
    profiles: Optional[Iterable[str]] = None,
    samples: Optional[Iterable[str]] = None,
    backends: Optional[Iterable[str]] = None,
    protocol_only: bool = False,
    skip_protocol: bool = False,
) -> List[RunSpec]:
    board_set = {item for item in boards or []}
    profile_set = {item for item in profiles or []}
    sample_set = {item for item in samples or []}
    backend_set = {normalize_backend_policy(item) for item in backends or []}
    filtered: List[RunSpec] = []

    for spec in specs:
        if board_set and spec.board not in board_set:
            continue
        if profile_set and spec.profile not in profile_set:
            continue
        if sample_set and spec.sample not in sample_set:
            continue
        if backend_set and spec.backend not in backend_set:
            continue
        if protocol_only and not is_protocol_run(spec):
            continue
        if skip_protocol and is_protocol_run(spec):
            continue

        filtered.append(spec)

    return filtered


def load_config_file(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(path)

    if path.suffix in {".yml", ".yaml"}:
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError("PyYAML is required for YAML config files") from exc
        return yaml.safe_load(path.read_text()) or {}

    return json.loads(path.read_text())


def discover_west(explicit: Optional[str], west_root: Path, module_path: Path) -> List[str]:
    return _shared_discover_west(explicit, west_root, module_path)


ROM_LIKE_SECTION_NAMES = {
    ".ARM.exidx",
    "device_area",
    "initlevel",
    "log_backend_area",
    "log_const_area",
    "rodata",
    "rom_start",
    "sw_isr_table",
}

RAM_LIKE_SECTION_NAMES = {
    ".last_ram_section",
    "data",
    "datas",
    "device_states",
    "k_sem_area",
    "log_mpsc_pbuf_area",
    "log_msg_ptr_area",
    "pagetables",
}

OBJDUMP_MAC_RE = re.compile(
    r"^\s*\d+\s+(?P<name>\S+)\s+(?P<size>[0-9a-fA-F]+)\s+"
    r"(?P<vma>[0-9a-fA-F]+)(?:\s+(?P<lma>[0-9a-fA-F]+))?\s+"
    r"(?P<section_type>TEXT|DATA|BSS)\s*$"
)


def discover_objdump_tool() -> Optional[List[str]]:
    for tool in ("llvm-objdump", "objdump"):
        path = shutil.which(tool)
        if path:
            return [path]
    return None


def classify_macos_objdump_section(
    section_name: str,
    section_type: str,
    vma: str,
    lma: Optional[str],
) -> Optional[str]:
    if section_type == "TEXT":
        return "text"
    if section_type == "BSS":
        return "bss"
    if section_type != "DATA":
        return None

    if lma is not None and vma.lower() != lma.lower():
        return "data"

    if section_name in ROM_LIKE_SECTION_NAMES or section_name.endswith("_api_area"):
        return "text"
    if section_name in RAM_LIKE_SECTION_NAMES:
        return "data"
    return "data"


def parse_objdump_sections(output: str) -> Dict[str, int]:
    totals = {"text": 0, "data": 0, "bss": 0}
    pending_gnu_section: Optional[tuple[str, int]] = None

    for raw_line in output.splitlines():
        mac_match = OBJDUMP_MAC_RE.match(raw_line)
        if mac_match is not None:
            bucket = classify_macos_objdump_section(
                mac_match.group("name"),
                mac_match.group("section_type"),
                mac_match.group("vma"),
                mac_match.group("lma"),
            )
            if bucket is not None:
                totals[bucket] += int(mac_match.group("size"), 16)
            pending_gnu_section = None
            continue

        stripped = raw_line.strip()
        if not stripped:
            continue

        parts = stripped.split()
        if parts and parts[0].isdigit() and len(parts) >= 7:
            try:
                pending_gnu_section = (parts[1], int(parts[2], 16))
            except ValueError:
                pending_gnu_section = None
            continue

        if pending_gnu_section is None:
            continue

        section_name, section_size = pending_gnu_section
        flags = {item.strip() for item in stripped.split(",")}
        pending_gnu_section = None

        if "ALLOC" not in flags:
            continue
        if "CODE" in flags or "READONLY" in flags:
            totals["text"] += section_size
        elif "LOAD" in flags:
            totals["data"] += section_size
        else:
            totals["bss"] += section_size

    return totals


def load_resource_budgets(path: Path) -> Dict[str, Dict[str, Any]]:
    raw = json.loads(path.read_text())
    budgets = raw.get("budgets", raw)
    if not isinstance(budgets, list):
        raise RuntimeError("resource budget file must contain a 'budgets' list")

    normalized: Dict[str, Dict[str, Any]] = {}
    for entry in budgets:
        if not isinstance(entry, dict):
            raise RuntimeError("each resource budget entry must be an object")

        limits = entry.get("limits")
        if not isinstance(limits, dict) or not limits:
            raise RuntimeError("each resource budget entry must contain non-empty limits")

        run_id = entry.get("run_id")
        if run_id is None:
            board = entry.get("board")
            profile = entry.get("profile")
            sample = entry.get("sample")
            if not board or not profile or not sample:
                raise RuntimeError(
                    "resource budget entries must define run_id or board/profile/sample"
                )
            run_id = make_run_id(str(board), str(profile), str(sample))

        normalized[str(run_id)] = {
            "description": str(entry.get("description", "")).strip(),
            "limits": {str(name): int(value) for name, value in limits.items()},
        }

    return normalized


class BenchmarkRunner:
    def __init__(
        self,
        west_root: Path,
        module_path: Path,
        output_dir: Path,
        west_cmd: List[str],
        build_only: bool,
        default_timeout: int,
        verbose: bool,
        resource_budgets: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        self.west_root = west_root
        self.module_path = module_path
        self.output_dir = output_dir
        self.west_cmd = west_cmd
        self.build_only = build_only
        self.default_timeout = default_timeout
        self.verbose = verbose
        self.command_env = self._build_command_env()
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.objdump_tool = discover_objdump_tool()
        self.resource_budgets = resource_budgets or {}
        self.records: List[RunRecord] = []
        self.metric_rows: List[Dict[str, Any]] = []
        self.all_results: List[Dict[str, Any]] = []

        (self.output_dir / "runs").mkdir(parents=True, exist_ok=True)
        (self.output_dir / "build").mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _count_pqcp_metric_rows(rows: Iterable[Dict[str, Any]]) -> int:
        return sum(1 for row in rows if row.get("component") != "build")

    @staticmethod
    def _count_build_metric_rows(rows: Iterable[Dict[str, Any]]) -> int:
        return sum(1 for row in rows if row.get("component") == "build")

    def _build_command_env(self) -> Dict[str, str]:
        env = os.environ.copy()
        for key in HOST_ENV_BLACKLIST:
            env.pop(key, None)
        return env

    def _zephyr_version(self) -> str:
        version_file = self.west_root / "zephyr" / "VERSION"
        if not version_file.exists():
            return "unknown"
        values: Dict[str, str] = {}
        for raw_line in version_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in raw_line:
                continue
            key, value = raw_line.split("=", 1)
            values[key.strip()] = value.strip()
        major = values.get("VERSION_MAJOR")
        minor = values.get("VERSION_MINOR")
        patch = values.get("PATCHLEVEL")
        if major and minor and patch:
            return f"{major}.{minor}.{patch}"
        return "unknown"

    @staticmethod
    def _compiler_id(build_stdout: str) -> str:
        match = re.search(r"-- The C compiler identification is (?P<compiler>.+)", build_stdout)
        if match:
            return match.group("compiler").strip()
        return "unknown"

    @staticmethod
    def _distribution_sample_cap(spec: RunSpec) -> str:
        config_lines = [
            PROFILES.get(spec.profile, {}).get("kconfig", ""),
            *spec.extra_kconfig,
        ]
        for raw_line in config_lines:
            for line in str(raw_line).splitlines():
                line = line.strip()
                if line.startswith("CONFIG_PQCP_BENCH_DISTRIBUTION_SAMPLES="):
                    return line.split("=", 1)[1].strip()
        return "128"

    def _cleanup_qemu(self, build_dir: Path) -> None:
        pid_path = build_dir / "qemu.pid"
        if not pid_path.exists():
            return

        try:
            pid = int(pid_path.read_text().strip())
        except (OSError, ValueError):
            pid_path.unlink(missing_ok=True)
            return

        try:
            ps_result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "command="],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
                check=False,
            )
            command = ps_result.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            command = ""

        if "qemu" in command and str(build_dir) in command:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except PermissionError:
                pass

        pid_path.unlink(missing_ok=True)

    def _run_command(
        self,
        cmd: List[str],
        *,
        cwd: Path,
        timeout: Optional[int] = None,
        success_markers: tuple[str, ...] = (),
    ) -> CommandResult:
        if self.verbose:
            print(" ".join(cmd))

        proc: subprocess.Popen[str] | None = None
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(cwd),
                env=self.command_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            if success_markers:
                return self._communicate_until_marker(
                    proc,
                    timeout=timeout,
                    success_markers=success_markers,
                )
            stdout, _ = proc.communicate(timeout=timeout)
            return CommandResult(proc.returncode, stdout or "", False)
        except subprocess.TimeoutExpired:
            stdout = ""
            if proc is not None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    pass
                try:
                    stdout, _ = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except PermissionError:
                        pass
                    stdout, _ = proc.communicate()
            return CommandResult(124, stdout or "", True)

    def _terminate_process_group(self, proc: subprocess.Popen[str], sig: int) -> None:
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass
        except PermissionError:
            pass

    def _communicate_until_marker(
        self,
        proc: subprocess.Popen[str],
        *,
        timeout: Optional[int],
        success_markers: tuple[str, ...],
    ) -> CommandResult:
        chunks: list[bytes] = []
        deadline = time.monotonic() + timeout if timeout else None
        marker_bytes = tuple(marker.encode("utf-8") for marker in success_markers)
        selector = selectors.DefaultSelector()

        if proc.stdout is not None:
            selector.register(proc.stdout, selectors.EVENT_READ)

        try:
            while True:
                for key, _event in selector.select(timeout=0.1):
                    try:
                        chunk = os.read(key.fileobj.fileno(), 4096)
                    except OSError:
                        chunk = b""
                    if not chunk:
                        try:
                            selector.unregister(key.fileobj)
                        except (KeyError, ValueError):
                            pass
                        continue
                    chunks.append(chunk)
                    stdout_bytes = b"".join(chunks)
                    if any(marker in stdout_bytes for marker in marker_bytes):
                        self._terminate_process_group(proc, signal.SIGTERM)
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            self._terminate_process_group(proc, signal.SIGKILL)
                            proc.wait()
                        return CommandResult(
                            0,
                            stdout_bytes.decode("utf-8", errors="replace"),
                            False,
                        )

                if proc.poll() is not None:
                    stdout = b"".join(chunks).decode("utf-8", errors="replace")
                    return CommandResult(proc.returncode, stdout, False)

                if deadline is not None and time.monotonic() >= deadline:
                    self._terminate_process_group(proc, signal.SIGTERM)
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self._terminate_process_group(proc, signal.SIGKILL)
                        proc.wait()
                    stdout = b"".join(chunks).decode("utf-8", errors="replace")
                    return CommandResult(124, stdout, True)
        finally:
            selector.close()
            if proc.stdout is not None:
                proc.stdout.close()

    def _write_extra_conf(self, run_dir: Path, spec: RunSpec) -> Optional[Path]:
        lines = [PROFILES[spec.profile]["kconfig"], *spec.extra_kconfig]
        lines = [line.strip() for line in lines if line and line.strip()]
        if not lines:
            return None

        conf_path = run_dir / "extra.conf"
        conf_path.write_text("\n".join(lines) + "\n")
        return conf_path

    def _build(self, spec: RunSpec, run_dir: Path) -> CommandResult:
        build_dir = self.output_dir / "build" / spec.run_id
        if build_dir.exists():
            shutil.rmtree(build_dir)

        app_dir = self.module_path / spec.app_path
        overlay_args = [
            str(app_dir / overlay) for overlay in spec.overlays
        ]
        extra_conf = self._write_extra_conf(run_dir, spec)

        cmd = [
            *self.west_cmd,
            "build",
            "-d",
            str(build_dir),
            "-b",
            spec.board,
            str(app_dir),
            "--pristine",
            "--",
            f"-DZEPHYR_EXTRA_MODULES={self.module_path}",
        ]

        if overlay_args:
            cmd.append(f"-DOVERLAY_CONFIG={';'.join(overlay_args)}")
        if extra_conf is not None:
            cmd.append(f"-DEXTRA_CONF_FILE={extra_conf}")

        return self._run_command(cmd, cwd=self.west_root)

    def _run_sample(self, spec: RunSpec) -> CommandResult:
        if self.build_only or spec.build_only:
            return CommandResult(0, "", False)

        build_dir = self.output_dir / "build" / spec.run_id
        self._cleanup_qemu(build_dir)
        run_timeout = spec.run_timeout if spec.run_timeout and spec.run_timeout > 0 else self.default_timeout
        if self.default_timeout:
            run_timeout = min(run_timeout, self.default_timeout) if run_timeout else self.default_timeout

        if spec.board.startswith("native_"):
            binary = build_dir / "zephyr/zephyr.exe"
            if not binary.exists():
                return CommandResult(1, f"Binary not found: {binary}\n", False)
            return self._run_command(
                [str(binary)],
                cwd=self.west_root,
                timeout=run_timeout,
                success_markers=SAMPLE_SUCCESS_MARKERS,
            )

        result = self._run_command(
            [*self.west_cmd, "build", "-d", str(build_dir), "-t", "run"],
            cwd=self.west_root,
            timeout=run_timeout,
            success_markers=SAMPLE_SUCCESS_MARKERS,
        )
        self._cleanup_qemu(build_dir)
        return result

    def _get_code_size(self, spec: RunSpec) -> Dict[str, int]:
        build_dir = self.output_dir / "build" / spec.run_id
        elf_path = build_dir / "zephyr/zephyr.elf"
        if self.objdump_tool is None or not elf_path.exists():
            return {}

        result = self._run_command(
            [*self.objdump_tool, "-h", str(elf_path)],
            cwd=self.west_root,
        )
        if result.returncode != 0:
            return {}

        sizes = parse_objdump_sections(result.stdout)
        sizes["rom"] = sizes.get("text", 0) + sizes.get("data", 0)
        sizes["ram"] = sizes.get("data", 0) + sizes.get("bss", 0)
        sizes["total"] = sizes.get("text", 0) + sizes.get("data", 0) + sizes.get("bss", 0)
        return sizes

    def _generate_resource_reports(self, spec: RunSpec) -> Dict[str, int]:
        if spec.run_id not in self.resource_budgets:
            return {}

        build_dir = self.output_dir / "build" / spec.run_id
        report_values: Dict[str, int] = {}
        report_targets = (
            ("rom_report", "rom.json", "rom"),
            ("ram_report", "ram.json", "ram"),
        )

        for target_name, json_name, metric_name in report_targets:
            report_path = build_dir / json_name
            result = self._run_command(
                [*self.west_cmd, "build", "-d", str(build_dir), "-t", target_name],
                cwd=self.west_root,
            )
            if result.returncode != 0 or not report_path.exists():
                return {}

            payload = json.loads(report_path.read_text())
            report_values[metric_name] = int(payload["symbols"]["size"])

        return report_values

    def _evaluate_resource_budget(self, spec: RunSpec, sizes: Dict[str, int]) -> List[str]:
        budget = self.resource_budgets.get(spec.run_id)
        if budget is None:
            return []

        failures: List[str] = []
        for metric, limit in budget["limits"].items():
            actual = sizes.get(metric)
            if actual is None:
                failures.append(f"{metric} missing (limit {limit} B)")
                continue
            if actual > limit:
                failures.append(f"{metric} {actual} B > {limit} B")
        return failures

    def _budget_description(self, spec: RunSpec) -> str:
        budget = self.resource_budgets.get(spec.run_id)
        if budget is None:
            return ""
        return budget.get("description", "")

    def _enrich_metric_rows(
        self,
        spec: RunSpec,
        log_path: Path,
        parsed: List[Dict[str, Any]],
        sizes: Dict[str, int],
        build_stdout: str,
    ) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        metadata = {
            "timestamp": self.timestamp,
            "run_id": spec.run_id,
            "board": spec.board,
            "profile": spec.profile,
            "sample": spec.sample,
            "implementation": spec.implementation,
            "backend": spec.backend,
            "app_path": spec.app_path,
            "overlays": ";".join(spec.overlays),
            "extra_kconfig": ";".join(spec.extra_kconfig),
            "run_mode": spec.run_mode,
            "build_only": spec.build_only,
            "log_path": str(log_path),
        }

        def add_metadata(algorithm: str, metric: str, value: str) -> None:
            rows.append(
                {
                    **metadata,
                    "component": "build",
                    "operation": "metadata",
                    "algorithm": algorithm,
                    "level": 0,
                    "metric": metric,
                    "value": value,
                    "unit": "",
                }
            )

        add_metadata("compiler", "id", self._compiler_id(build_stdout))
        add_metadata("zephyr", "version", self._zephyr_version())
        add_metadata("board", "name", spec.board)
        add_metadata("profile", "flags", ";".join([PROFILES.get(spec.profile, {}).get("kconfig", ""), *spec.extra_kconfig]).strip(";"))
        add_metadata("backend", "selector", spec.backend)
        add_metadata("distribution", "sample_cap", self._distribution_sample_cap(spec))

        for item in parsed:
            enriched = {**metadata, **item}
            self.all_results.append(enriched)

            if item.get("type") == "pqcp_metric":
                rows.append(
                    {
                        **metadata,
                        "component": item["component"],
                        "operation": item["operation"],
                        "algorithm": item["algorithm"],
                        "level": item["level"],
                        "metric": item["metric"],
                        "value": item["value"],
                        "unit": item["unit"],
                    }
                )

        for name, value in sizes.items():
            rows.append(
                {
                    **metadata,
                    "component": "build",
                    "operation": "artifact",
                    "algorithm": "zephyr",
                    "level": 0,
                    "metric": f"{name}_bytes",
                    "value": value,
                    "unit": "B",
                }
            )

        return rows

    def run_one(self, spec: RunSpec) -> None:
        run_dir = self.output_dir / "runs" / spec.run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        print(
            f"\n[{spec.run_id}] {spec.board} / {spec.profile} / "
            f"{spec.sample} / implementation={spec.implementation} / "
            f"backend={spec.backend} / run_mode={spec.run_mode}"
        )
        build_result = self._build(spec, run_dir)
        (run_dir / "build.log").write_text(build_result.stdout)

        if build_result.returncode != 0:
            print("  build failed")
            self.records.append(
                RunRecord(
                    run_id=spec.run_id,
                    board=spec.board,
                    profile=spec.profile,
                    sample=spec.sample,
                    implementation=spec.implementation,
                    backend=spec.backend,
                    app_path=spec.app_path,
                    build_dir=str(self.output_dir / "build" / spec.run_id),
                    log_path=str(run_dir / "run.log"),
                    build_ok=False,
                    run_ok=False,
                    timed_out=False,
                    run_mode=spec.run_mode,
                    build_only=spec.build_only,
                    metric_count=0,
                    size_text=0,
                    size_data=0,
                    size_bss=0,
                    rom_bytes=0,
                    ram_bytes=0,
                    budget_ok=False,
                    budget_failures=["build failed before budget evaluation"],
                )
            )
            return

        sizes = self._get_code_size(spec)
        sizes.update(self._generate_resource_reports(spec))
        budget_failures = self._evaluate_resource_budget(spec, sizes)
        run_result = self._run_sample(spec)
        self._cleanup_qemu(self.output_dir / "build" / spec.run_id)
        log_text = run_result.stdout
        log_path = run_dir / "run.log"
        log_path.write_text(log_text)

        parsed = parse_log_file(log_path) if log_text else []
        write_metrics_csv(parsed, run_dir / "run_metrics.csv")
        write_primitive_csv(parsed, run_dir / "run_primitives.csv")
        write_protocol_csv(parsed, run_dir / "run_protocols.csv")
        write_summary(parsed, run_dir / "run_summary.txt")

        enriched_rows = self._enrich_metric_rows(spec, log_path, parsed, sizes, build_result.stdout)
        self.metric_rows.extend(enriched_rows)
        pqcp_metric_count = self._count_pqcp_metric_rows(enriched_rows)
        build_metric_count = self._count_build_metric_rows(enriched_rows)

        record = RunRecord(
            run_id=spec.run_id,
            board=spec.board,
            profile=spec.profile,
            sample=spec.sample,
            implementation=spec.implementation,
            backend=spec.backend,
            app_path=spec.app_path,
            build_dir=str(self.output_dir / "build" / spec.run_id),
            log_path=str(log_path),
            build_ok=True,
            run_ok=(run_result.returncode == 0 or run_result.timed_out),
            timed_out=run_result.timed_out,
            run_mode=spec.run_mode,
            build_only=spec.build_only,
            metric_count=len(enriched_rows),
            size_text=sizes.get("text", 0),
            size_data=sizes.get("data", 0),
            size_bss=sizes.get("bss", 0),
            rom_bytes=sizes.get("rom", 0),
            ram_bytes=sizes.get("ram", 0),
            budget_ok=(not budget_failures),
            budget_failures=budget_failures,
        )
        self.records.append(record)

        if self.build_only or spec.build_only:
            status = "build-only completed"
        else:
            status = "timed out with partial output" if run_result.timed_out else "completed"
        print(
            f"  run {status}, captured {pqcp_metric_count} PQCP_METRIC row(s)"
            f" and {build_metric_count} build metric row(s)"
        )
        if spec.run_id in self.resource_budgets:
            description = self._budget_description(spec)
            if description:
                print(f"  budget profile: {description}")
            if budget_failures:
                print("  resource budget exceeded:")
                for failure in budget_failures:
                    print(f"    - {failure}")
            else:
                print("  resource budget: OK")

    def write_outputs(self) -> None:
        record_path = self.output_dir / "runs.json"
        record_path.write_text(
            json.dumps([asdict(record) for record in self.records], indent=2)
        )

        all_results_path = self.output_dir / "all_results.json"
        all_results_path.write_text(json.dumps(self.all_results, indent=2))

        metrics_json_path = self.output_dir / "consolidated_metrics.json"
        metrics_json_path.write_text(json.dumps(self.metric_rows, indent=2))

        metrics_csv_path = self.output_dir / "consolidated_metrics.csv"
        fieldnames = [
            "timestamp",
            "run_id",
            "board",
            "profile",
            "sample",
            "implementation",
            "backend",
            "app_path",
            "overlays",
            "extra_kconfig",
            "run_mode",
            "build_only",
            "component",
            "operation",
            "algorithm",
            "level",
            "metric",
            "value",
            "unit",
            "log_path",
        ]
        with metrics_csv_path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.metric_rows)

        print(f"\nWrote run metadata:      {record_path}")
        print(f"Wrote parsed JSON:       {all_results_path}")
        print(f"Wrote consolidated JSON: {metrics_json_path}")
        print(f"Wrote consolidated CSV:  {metrics_csv_path}")


def expand_runs(
    *,
    boards: Iterable[str],
    profiles: Iterable[str],
    samples: Iterable[str],
    implementation: str,
    backend: str,
    extra_kconfig: List[str],
) -> List[RunSpec]:
    specs: List[RunSpec] = []
    implementation_name = normalize_implementation_name(implementation)
    backend_policy = normalize_backend_policy(backend)
    backend_kconfig = list(BACKEND_POLICIES[backend_policy]["kconfig"])
    implementation_kconfig = implementation_kconfig_lines(implementation_name)

    for board in boards:
        for profile in profiles:
            for sample in samples:
                sample_info = SAMPLES[sample]
                if board not in sample_info["boards"]:
                    continue
                if profile not in sample_info["profiles"]:
                    continue

                run_id = make_run_id(
                    board,
                    profile,
                    sample,
                    backend_policy,
                    implementation_name,
                )
                specs.append(
                    RunSpec(
                    run_id=run_id,
                    board=board,
                    profile=profile,
                    sample=sample,
                    implementation=implementation_name,
                    backend=backend_policy,
                    app_path=sample_info["path"],
                    overlays=list(sample_info.get("overlays", [])),
                    extra_kconfig=[
                        *implementation_kconfig,
                        *backend_kconfig,
                        *extra_kconfig,
                    ],
                    run_timeout=int(sample_info.get("run_timeout", 0)),
                    run_mode="run",
                    build_only=False,
                )
            )

    return specs


def expand_runs_from_config(config: Dict[str, Any], cli_kconfig: List[str]) -> List[RunSpec]:
    if config and all(key in PROFILES for key in config.keys()):
        specs: List[RunSpec] = []
        for profile, entries in config.items():
            for item in entries:
                target = item["target"]
                label = item.get("sample", Path(target).name)
                implementation_name = normalize_implementation_name(
                    item.get("implementation")
                )
                run_mode = resolve_run_mode(
                    item.get("mode", item.get("run_mode")),
                    build_only=bool(item.get("build_only", False)),
                    run=item.get("run"),
                    build=item.get("build"),
                )
                backend_policy = normalize_backend_policy(item.get("backend"))
                overlays = normalize_overlays(item.get("overlays"))
                if item.get("overlay"):
                    overlays.append(str(item["overlay"]))
                specs.append(
                    RunSpec(
                        run_id=item.get(
                            "run_id",
                            make_run_id(
                                item["board"],
                                profile,
                                label,
                                backend_policy,
                                implementation_name,
                                infer_level_variant(item.get("extra_kconfig", [])),
                            ),
                        ),
                        board=item["board"],
                        profile=profile,
                        sample=label,
                        implementation=implementation_name,
                        backend=backend_policy,
                        app_path=target,
                        overlays=overlays,
                        extra_kconfig=[
                            *implementation_kconfig_lines(implementation_name),
                            *BACKEND_POLICIES[backend_policy]["kconfig"],
                            *item.get("extra_kconfig", []),
                            *cli_kconfig,
                        ],
                        run_timeout=int(
                            item.get("run_timeout", default_timeout_for_path(target))
                        ),
                        run_mode=run_mode,
                        build_only=(run_mode == "build_only"),
                    )
                )
        return specs

    if "runs" in config:
        specs: List[RunSpec] = []
        for item in config["runs"]:
            sample = item.get("sample")
            target = item.get("target")
            implementation_name = normalize_implementation_name(
                item.get("implementation")
            )
            run_mode = resolve_run_mode(
                item.get("mode", item.get("run_mode")),
                build_only=bool(item.get("build_only", False)),
                run=item.get("run"),
                build=item.get("build"),
            )
            backend_policy = normalize_backend_policy(item.get("backend"))
            sample_info = SAMPLES.get(sample, {}) if sample else {}
            app_path = item.get("app_path") or target or sample_info.get("path")
            if app_path is None:
                raise KeyError("Each run must define either sample, target, or app_path")

            label = sample or Path(app_path).name
            overlays = normalize_overlays(item.get("overlays"))
            if item.get("overlay"):
                overlays.append(str(item["overlay"]))
            run_id = item.get(
                "run_id",
                make_run_id(
                    item["board"],
                    item["profile"],
                    label,
                    backend_policy,
                    implementation_name,
                    infer_level_variant(item.get("extra_kconfig", [])),
                ),
            )
            specs.append(
                RunSpec(
                    run_id=run_id,
                    board=item["board"],
                    profile=item["profile"],
                    sample=label,
                    implementation=implementation_name,
                    backend=backend_policy,
                    app_path=app_path,
                    overlays=overlays or list(sample_info.get("overlays", [])),
                    extra_kconfig=[
                        *implementation_kconfig_lines(implementation_name),
                        *BACKEND_POLICIES[backend_policy]["kconfig"],
                        *item.get("extra_kconfig", []),
                        *cli_kconfig,
                    ],
                    run_timeout=int(
                        item.get(
                            "run_timeout",
                            sample_info.get("run_timeout", default_timeout_for_path(app_path)),
                        )
                    ),
                    run_mode=run_mode,
                    build_only=(run_mode == "build_only"),
                )
            )
        return specs

    return expand_runs(
        boards=config.get("boards", DEFAULT_BOARDS),
        profiles=config.get("profiles", list(PROFILES.keys())),
        samples=config.get("samples", DEFAULT_MATRIX_SAMPLES),
        implementation=config.get("implementation", "pqcp"),
        backend=config.get("backend", "auto"),
        extra_kconfig=[*config.get("extra_kconfig", []), *cli_kconfig],
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PQCP benchmark matrix runner")
    mode_group = parser.add_mutually_exclusive_group()
    protocol_group = parser.add_mutually_exclusive_group()
    parser.add_argument("--board", help="Single board")
    parser.add_argument("--boards", nargs="+", help="Boards for matrix mode")
    parser.add_argument("--profile", choices=list(PROFILES), help="Single profile")
    parser.add_argument("--profiles", nargs="+", choices=list(PROFILES), help="Profiles for matrix mode")
    parser.add_argument(
        "--implementation",
        default="pqcp",
        help="Implementation identity label for generated run metadata",
    )
    parser.add_argument("--backend-policy", choices=list(BACKEND_POLICIES), help="Single backend policy")
    parser.add_argument("--backend-policies", nargs="+", choices=list(BACKEND_POLICIES), help="Backend policies for matrix filtering")
    parser.add_argument("--sample", help="Single sample or run label")
    parser.add_argument("--samples", nargs="+", help="Samples or run labels for matrix mode")
    parser.add_argument("--matrix", action="store_true", help="Run a board/profile/sample matrix")
    mode_group.add_argument("--config", type=Path, help="JSON or YAML matrix config")
    mode_group.add_argument("--benchmark-matrix", action="store_true",
                            help="Run the curated benchmark matrix")
    mode_group.add_argument("--cost-of-assurance-matrix", action="store_true",
                            help="Run the curated backend-comparison benchmark matrix")
    mode_group.add_argument("--profile-validation", action="store_true",
                            help="Run the curated profile validation matrix")
    protocol_group.add_argument("--protocol-only", action="store_true",
                                help="Only run protocol-oriented entries")
    protocol_group.add_argument("--skip-protocol", action="store_true",
                                help="Skip protocol-oriented entries")
    parser.add_argument("--output", "-o", type=Path, default=Path("benchmark_results"), help="Output directory")
    parser.add_argument("--west-root", type=Path, help="West workspace root")
    parser.add_argument("--module-path", type=Path, help="PQCP module path")
    parser.add_argument("--west", help="Explicit west binary or command")
    parser.add_argument(
        "--resource-budgets",
        type=Path,
        help=(
            "Optional JSON file describing ROM/RAM budget limits for curated "
            "runs. Matching runs fail if reported footprint exceeds the limit."
        ),
    )
    parser.add_argument("--kconfig", action="append", default=[], help="Extra Kconfig line, e.g. CONFIG_FOO=y")
    parser.add_argument("--timeout", type=int, default=180, help="Default run timeout in seconds")
    parser.add_argument("--build-only", action="store_true", help="Build without running")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose command logging")
    return parser.parse_args()


def detect_west_root(start: Path) -> Path:
    return _shared_detect_west_root(start, strict=False)


def main() -> int:
    args = parse_args()
    west_root = args.west_root.resolve() if args.west_root else detect_west_root(Path.cwd())
    module_path = args.module_path.resolve() if args.module_path else SCRIPT_DIR.parent
    output_dir = args.output.resolve()
    sample_filters = args.samples or ([args.sample] if args.sample else [])
    board_filters = args.boards or ([args.board] if args.board else [])
    profile_filters = args.profiles or ([args.profile] if args.profile else [])
    backend_filters = args.backend_policies or ([args.backend_policy] if args.backend_policy else [])
    resource_budget_path = args.resource_budgets.resolve() if args.resource_budgets else None

    west_cmd = discover_west(args.west, west_root, module_path)

    print("PQCP Benchmark Runner")
    print(f"  west root : {west_root}")
    print(f"  module    : {module_path}")
    print(f"  west cmd  : {' '.join(west_cmd)}")
    print(f"  output    : {output_dir}")
    if resource_budget_path is not None:
        print(f"  budgets   : {resource_budget_path}")

    if args.benchmark_matrix:
        specs = expand_runs_from_config(
            load_config_file(DEFAULT_BENCHMARK_MATRIX), args.kconfig
        )
    elif args.cost_of_assurance_matrix:
        specs = expand_runs_from_config(
            load_config_file(DEFAULT_COST_OF_ASSURANCE_MATRIX), args.kconfig
        )
    elif args.profile_validation:
        specs = expand_runs_from_config(
            load_config_file(DEFAULT_PROFILE_VALIDATION_MATRIX), args.kconfig
        )
    elif args.config:
        specs = expand_runs_from_config(load_config_file(args.config), args.kconfig)
    elif args.sample:
        if args.sample not in SAMPLES:
            print(f"Unknown sample: {args.sample}")
            print(f"Known direct-run samples: {', '.join(sorted(SAMPLES))}")
            return 2
        specs = expand_runs(
            boards=[args.board or "qemu_x86_64"],
            profiles=[args.profile or "MCU_MINIMAL"],
            samples=[args.sample],
            implementation=args.implementation,
            backend=args.backend_policy or "auto",
            extra_kconfig=args.kconfig,
        )
    elif args.matrix or args.samples or args.boards or args.profiles:
        unknown_samples = [
            sample for sample in (args.samples or []) if sample not in SAMPLES
        ]
        if unknown_samples:
            print(f"Unknown samples for matrix mode: {', '.join(unknown_samples)}")
            print(f"Known matrix samples: {', '.join(sorted(SAMPLES))}")
            return 2
        specs = expand_runs(
            boards=args.boards or ([args.board] if args.board else DEFAULT_BOARDS),
            profiles=args.profiles or ([args.profile] if args.profile else list(PROFILES.keys())),
            samples=args.samples or DEFAULT_MATRIX_SAMPLES,
            implementation=args.implementation,
            backend=args.backend_policy or "auto",
            extra_kconfig=args.kconfig,
        )
    else:
        specs = expand_runs(
            boards=[args.board or "qemu_x86_64"],
            profiles=[args.profile or "MCU_MINIMAL"],
            samples=["pqcp_basic_kem", "pqcp_basic_sig"],
            implementation=args.implementation,
            backend=args.backend_policy or "auto",
            extra_kconfig=args.kconfig,
        )

    specs = filter_specs(
        specs,
        boards=board_filters,
        profiles=profile_filters,
        samples=sample_filters,
        backends=backend_filters,
        protocol_only=args.protocol_only,
        skip_protocol=args.skip_protocol,
    )

    if not specs:
        print("No runnable benchmark combinations matched the selected matrix.")
        return 1

    runner = BenchmarkRunner(
        west_root=west_root,
        module_path=module_path,
        output_dir=output_dir,
        west_cmd=west_cmd,
        build_only=args.build_only,
        default_timeout=args.timeout,
        verbose=args.verbose,
        resource_budgets=(
            load_resource_budgets(resource_budget_path)
            if resource_budget_path is not None
            else None
        ),
    )

    for spec in specs:
        runner.run_one(spec)

    runner.write_outputs()
    failed_records = [
        record
        for record in runner.records
        if not record.build_ok or not record.run_ok or not record.budget_ok
    ]
    if failed_records:
        print("\nOne or more runs failed:")
        for record in failed_records:
            print(
                "  - "
                f"{record.run_id}: build_ok={record.build_ok} "
                f"run_ok={record.run_ok} timed_out={record.timed_out} "
                f"budget_ok={record.budget_ok} implementation={record.implementation} "
                f"backend={record.backend} run_mode={record.run_mode}"
            )
            for failure in record.budget_failures:
                print(f"      budget: {failure}")
        return 1

    print(
        "\nCompleted "
        f"{len(runner.records)} run(s) with "
        f"{runner._count_pqcp_metric_rows(runner.metric_rows)} PQCP_METRIC row(s) "
        f"and {runner._count_build_metric_rows(runner.metric_rows)} build metric row(s)."
    )
    if runner._count_pqcp_metric_rows(runner.metric_rows) == 0:
        print(
            "No PQCP_METRIC rows were emitted; this is expected for build-only "
            "or validation-only runs."
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
