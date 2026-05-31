#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""
Drive the pqcp_serial_acvp sample over either a serial port or a subprocess.

This is intentionally a thin host-side harness rather than a full NIST ACVP
client. Its purpose is to validate the stable `RESULT:*` / `ERROR:*` protocol,
demonstrate how external tooling can integrate with the serial sample, and make
lab-side smoke coverage easy to reproduce.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, List, Optional, Sequence

try:
    import serial  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - optional dependency
    serial = None


MLKEM_SIZES = {
    512: {"pk": 800, "ct": 768},
    768: {"pk": 1184, "ct": 1088},
    1024: {"pk": 1568, "ct": 1568},
}

MLDSA_SIZES = {
    44: {"pk": 1312},
    65: {"pk": 1952},
    87: {"pk": 2592},
}

DEFAULT_SEED_HEX = (
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f"
)
DEFAULT_MESSAGE_HEX = "616376702d736d6f6b652d6d7367"

HOST_ENV_BLACKLIST = (
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "CPATH",
    "SDKROOT",
)
ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
PROTOCOL_RESPONSE_RE = re.compile(
    r"(RESULT:(?:OK|INVALID|[0-9a-f]+)|ERROR:[A-Z0-9_]+)\b"
)
HEX_RE = re.compile(r"[0-9a-fA-F]*")
VALID_STEP_STATUSES = {"ok", "invalid", "payload", "error"}


@dataclass
class CommandRecord:
    command: str
    response: str


@dataclass(frozen=True)
class SmokeScenario:
    name: str
    kem_level: int
    sig_level: int
    seed_hex: str
    message_hex: str
    step_expectations: tuple["StepExpectation", ...] = ()
    expected_errors: tuple["ExpectedCommand", ...] = ()


@dataclass(frozen=True)
class StepExpectation:
    name: str
    status: Optional[str] = None
    response: Optional[str] = None


@dataclass(frozen=True)
class ExpectedCommand:
    name: str
    command: str
    status: Optional[str] = "error"
    response: Optional[str] = None
    append_newline: bool = True
    response_timeout: Optional[float] = None


class SessionError(RuntimeError):
    pass


class BaseTransport:
    def send_line(self, line: str) -> None:
        self.send_text(line, append_newline=True)

    def send_text(self, text: str, *, append_newline: bool) -> None:
        raise NotImplementedError

    def wait_for(self, predicate: Callable[[str], bool], timeout: float) -> str:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    @property
    def transcript(self) -> List[str]:
        raise NotImplementedError


class SubprocessTransport(BaseTransport):
    def __init__(
        self,
        command: str,
        *,
        cwd: Optional[Path],
        env: Optional[dict[str, str]],
        char_delay: float,
    ) -> None:
        self._command = shlex.split(command)
        if not self._command:
            raise SessionError("run command must not be empty")

        self._cwd = str(cwd) if cwd else None
        self._env = env
        self._char_delay = max(char_delay, 0.0)
        self._queue: queue.Queue[Optional[str]] = queue.Queue()
        self._transcript: List[str] = []
        self._partial = ""
        self._proc = subprocess.Popen(
            self._command,
            cwd=self._cwd,
            env=self._env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=0,
            start_new_session=True,
        )
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def _reader(self) -> None:
        assert self._proc.stdout is not None

        while True:
            char = self._proc.stdout.read(1)
            if char == "":
                if self._partial.strip():
                    self._transcript.append(self._partial.rstrip())
                    self._queue.put(self._partial.rstrip())
                self._queue.put(None)
                return

            self._partial += char
            if char == "\n":
                line = self._partial.rstrip("\r\n")
                self._transcript.append(line)
                self._queue.put(line)
                self._partial = ""

    def send_text(self, text: str, *, append_newline: bool) -> None:
        if self._proc.stdin is None:
            raise SessionError("subprocess stdin is unavailable")
        payload = text + ("\n" if append_newline else "")
        if self._char_delay > 0:
            for char in payload:
                self._proc.stdin.write(char)
                self._proc.stdin.flush()
                time.sleep(self._char_delay)
            return
        self._proc.stdin.write(payload)
        self._proc.stdin.flush()

    def wait_for(self, predicate: Callable[[str], bool], timeout: float) -> str:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SessionError("timed out waiting for subprocess response")
            try:
                item = self._queue.get(timeout=remaining)
            except queue.Empty as exc:
                raise SessionError("timed out waiting for subprocess output") from exc
            if item is None:
                raise SessionError("subprocess exited before the expected response")
            if predicate(item):
                return item

    def close(self) -> None:
        if self._proc.poll() is not None:
            return

        try:
            os.killpg(self._proc.pid, signal.SIGTERM)
            self._proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(self._proc.pid, signal.SIGKILL)
            except OSError:
                pass

    @property
    def transcript(self) -> List[str]:
        return list(self._transcript)


class SerialTransport(BaseTransport):
    def __init__(self, port: str, *, baudrate: int, char_delay: float) -> None:
        if serial is None:
            raise SessionError(
                "pyserial is required for --serial-port mode; install it with "
                "'python -m pip install pyserial'"
            )
        self._serial = serial.Serial(
            port=port,
            baudrate=baudrate,
            timeout=0.1,
            write_timeout=5,
        )
        self._char_delay = max(char_delay, 0.0)
        self._transcript: List[str] = []

    def send_text(self, text: str, *, append_newline: bool) -> None:
        payload = text + ("\n" if append_newline else "")
        if self._char_delay > 0:
            for char in payload:
                self._serial.write(char.encode("ascii"))
                self._serial.flush()
                time.sleep(self._char_delay)
            return
        self._serial.write(payload.encode("ascii"))
        self._serial.flush()

    def wait_for(self, predicate: Callable[[str], bool], timeout: float) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            raw = self._serial.readline()
            if not raw:
                continue
            line = raw.decode("ascii", errors="replace").rstrip("\r\n")
            self._transcript.append(line)
            if predicate(line):
                return line
        raise SessionError("timed out waiting for serial response")

    def close(self) -> None:
        self._serial.close()

    @property
    def transcript(self) -> List[str]:
        return list(self._transcript)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an ACVP smoke session against pqcp_serial_acvp"
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument(
        "--serial-port",
        help="Serial port connected to pqcp_serial_acvp",
    )
    target.add_argument(
        "--run-command",
        help=(
            "Command that launches the sample on stdio "
            "(for example: 'west build -d build-acvp -t run')"
        ),
    )
    target.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in parser/startup detection self-checks and exit",
    )
    parser.add_argument("--cwd", type=Path, help="Working directory used with --run-command")
    parser.add_argument("--baudrate", type=int, default=115200, help="Serial baud rate")
    parser.add_argument("--kem-level", type=int, default=768, choices=sorted(MLKEM_SIZES))
    parser.add_argument("--sig-level", type=int, default=65, choices=sorted(MLDSA_SIZES))
    parser.add_argument(
        "--seed-hex",
        default=DEFAULT_SEED_HEX,
        help="Deterministic seed used for the smoke session",
    )
    parser.add_argument(
        "--message-hex",
        default=DEFAULT_MESSAGE_HEX,
        help="Message payload used for ML-DSA sign/verify",
    )
    parser.add_argument(
        "--scenario-file",
        type=Path,
        help="Optional JSON file describing one or more smoke scenarios",
    )
    parser.add_argument("--startup-timeout", type=float, default=60.0)
    parser.add_argument("--response-timeout", type=float, default=20.0)
    parser.add_argument(
        "--command-delay",
        type=float,
        default=0.2,
        help="Small settling delay between command/response exchanges",
    )
    parser.add_argument(
        "--char-delay",
        type=float,
        default=0.001,
        help="Per-character pacing delay used when sending commands",
    )
    parser.add_argument("--json-out", type=Path, help="Optional JSON summary output path")
    parser.add_argument("--transcript-out", type=Path, help="Optional raw transcript output path")
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print command/response pairs as they execute",
    )
    return parser.parse_args()


def expect_result_ok(response: str) -> None:
    if response != "RESULT:OK":
        raise SessionError(f"expected RESULT:OK, got {response}")


def expect_result_invalid(response: str) -> None:
    if response != "RESULT:INVALID":
        raise SessionError(f"expected RESULT:INVALID, got {response}")


def extract_hex_payload(response: str) -> str:
    if not response.startswith("RESULT:") or response in {"RESULT:OK", "RESULT:INVALID"}:
        raise SessionError(f"expected RESULT:<hex payload>, got {response}")
    payload = response.split(":", 1)[1]
    if not re.fullmatch(r"[0-9a-f]+", payload):
        raise SessionError(f"expected lowercase hex payload, got {response}")
    return payload


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub("", text)


def extract_protocol_response(line: str) -> Optional[str]:
    cleaned = strip_ansi(line).strip()
    match = PROTOCOL_RESPONSE_RE.search(cleaned)
    if match is None:
        return None
    return match.group(1)


def is_startup_line(line: str) -> bool:
    cleaned = strip_ansi(line).strip()
    return (
        "Ready for commands" in cleaned
        or "PQCP Serial ACVP Interface" in cleaned
        or "Type HELP:: for syntax" in cleaned
    )


def wait_for_startup(transport: BaseTransport, timeout: float) -> str:
    return transport.wait_for(lambda line: is_startup_line(line), timeout)


def normalize_hex_arg(field: str, value: str) -> str:
    normalized = value.strip()
    if len(normalized) % 2 != 0 or HEX_RE.fullmatch(normalized) is None:
        raise SessionError(f"{field} must be an even-length hex string")
    return normalized.lower()


def normalize_step_status(field: str, value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in VALID_STEP_STATUSES:
        raise SessionError(
            f"{field} must be one of: {', '.join(sorted(VALID_STEP_STATUSES))}"
        )
    return normalized


def normalize_expected_response(field: str, value: str) -> str:
    normalized = strip_ansi(value).strip()
    if PROTOCOL_RESPONSE_RE.fullmatch(normalized) is None:
        raise SessionError(
            f"{field} must be a single RESULT:* or ERROR:* protocol response"
        )
    return normalized


def parse_step_expectations(
    scenario_name: str,
    raw_expectations: object,
) -> tuple[StepExpectation, ...]:
    if raw_expectations is None:
        return ()
    if not isinstance(raw_expectations, dict):
        raise SessionError(f"{scenario_name}.step_expectations must be an object")

    expectations: List[StepExpectation] = []
    for step_name, raw_value in raw_expectations.items():
        if not isinstance(step_name, str) or not step_name:
            raise SessionError(
                f"{scenario_name}.step_expectations keys must be non-empty strings"
            )

        if isinstance(raw_value, str):
            expectation = StepExpectation(
                name=step_name,
                response=normalize_expected_response(
                    f"{scenario_name}.step_expectations.{step_name}",
                    raw_value,
                ),
            )
        elif isinstance(raw_value, dict):
            status_value = raw_value.get("status")
            response_value = raw_value.get("response")
            if status_value is None and response_value is None:
                raise SessionError(
                    f"{scenario_name}.step_expectations.{step_name} must define "
                    "'status' and/or 'response'"
                )
            expectation = StepExpectation(
                name=step_name,
                status=(
                    normalize_step_status(
                        f"{scenario_name}.step_expectations.{step_name}.status",
                        str(status_value),
                    )
                    if status_value is not None
                    else None
                ),
                response=(
                    normalize_expected_response(
                        f"{scenario_name}.step_expectations.{step_name}.response",
                        str(response_value),
                    )
                    if response_value is not None
                    else None
                ),
            )
        else:
            raise SessionError(
                f"{scenario_name}.step_expectations.{step_name} must be a string or object"
            )

        expectations.append(expectation)

    return tuple(expectations)


def parse_expected_commands(
    scenario_name: str,
    raw_expected_commands: object,
) -> tuple[ExpectedCommand, ...]:
    if raw_expected_commands is None:
        return ()
    if not isinstance(raw_expected_commands, list):
        raise SessionError(f"{scenario_name}.expected_errors must be a list")

    expectations: List[ExpectedCommand] = []
    for index, raw_item in enumerate(raw_expected_commands, start=1):
        if not isinstance(raw_item, dict):
            raise SessionError(
                f"{scenario_name}.expected_errors[{index}] must be a JSON object"
            )

        command = expand_expected_command(raw_item).strip()
        if not command:
            raise SessionError(
                f"{scenario_name}.expected_errors[{index}] must include a command"
            )

        name = str(raw_item.get("name") or f"expected-error-{index}")
        status_value = raw_item.get("status", "error")
        response_value = raw_item.get("response")
        append_newline_value = raw_item.get("append_newline", True)
        response_timeout_value = raw_item.get("response_timeout")

        if not isinstance(append_newline_value, bool):
            raise SessionError(
                f"{scenario_name}.expected_errors[{index}].append_newline "
                "must be a boolean"
            )

        if response_timeout_value is not None:
            try:
                parsed_timeout = float(response_timeout_value)
            except (TypeError, ValueError) as exc:
                raise SessionError(
                    f"{scenario_name}.expected_errors[{index}].response_timeout "
                    "must be a positive number"
                ) from exc
            if parsed_timeout <= 0:
                raise SessionError(
                    f"{scenario_name}.expected_errors[{index}].response_timeout "
                    "must be a positive number"
                )
        else:
            parsed_timeout = None

        if status_value is None and response_value is None:
            raise SessionError(
                f"{scenario_name}.expected_errors[{index}] must define "
                "'status' and/or 'response'"
            )

        expectations.append(
            ExpectedCommand(
                name=name,
                command=command,
                status=(
                    normalize_step_status(
                        f"{scenario_name}.expected_errors[{index}].status",
                        str(status_value),
                    )
                    if status_value is not None
                    else None
                ),
                response=(
                    normalize_expected_response(
                        f"{scenario_name}.expected_errors[{index}].response",
                        str(response_value),
                    )
                    if response_value is not None
                    else None
                ),
                append_newline=append_newline_value,
                response_timeout=parsed_timeout,
            )
        )

    return tuple(expectations)


def expand_expected_command(raw_item: dict) -> str:
    command = str(raw_item.get("command", ""))
    repeat = raw_item.get("repeat_hex")
    if repeat is None:
        return command
    if not isinstance(repeat, dict):
        raise SessionError("expected_errors repeat_hex must be an object")
    byte = str(repeat.get("byte", "00"))
    count = repeat.get("count")
    if len(byte) != 2:
        raise SessionError("expected_errors repeat_hex.byte must be two hex characters")
    try:
        int(byte, 16)
    except ValueError as exc:
        raise SessionError("expected_errors repeat_hex.byte must be hexadecimal") from exc
    if not isinstance(count, int) or count < 0:
        raise SessionError("expected_errors repeat_hex.count must be a non-negative integer")
    return command + (byte.lower() * count)


def default_scenario(args: argparse.Namespace) -> SmokeScenario:
    return SmokeScenario(
        name="default",
        kem_level=args.kem_level,
        sig_level=args.sig_level,
        seed_hex=normalize_hex_arg("seed_hex", args.seed_hex),
        message_hex=normalize_hex_arg("message_hex", args.message_hex),
    )


def load_scenarios(args: argparse.Namespace) -> List[SmokeScenario]:
    if args.scenario_file is None:
        return [default_scenario(args)]

    data = json.loads(args.scenario_file.read_text())
    raw_scenarios: Sequence[object]
    if isinstance(data, list):
        raw_scenarios = data
    elif isinstance(data, dict) and isinstance(data.get("scenarios"), list):
        raw_scenarios = data["scenarios"]
    else:
        raise SessionError(
            "scenario file must be a JSON array or an object with a 'scenarios' list"
        )

    if not raw_scenarios:
        raise SessionError("scenario file must contain at least one scenario")

    scenarios: List[SmokeScenario] = []
    for index, item in enumerate(raw_scenarios, start=1):
        if not isinstance(item, dict):
            raise SessionError(f"scenario #{index} must be a JSON object")

        name = str(item.get("name") or f"scenario-{index}")
        kem_level = int(item.get("kem_level", args.kem_level))
        sig_level = int(item.get("sig_level", args.sig_level))
        if kem_level not in MLKEM_SIZES:
            raise SessionError(f"{name}: unsupported ML-KEM level {kem_level}")
        if sig_level not in MLDSA_SIZES:
            raise SessionError(f"{name}: unsupported ML-DSA level {sig_level}")

        scenarios.append(
            SmokeScenario(
                name=name,
                kem_level=kem_level,
                sig_level=sig_level,
                seed_hex=normalize_hex_arg(
                    f"{name}.seed_hex",
                    str(item.get("seed_hex", args.seed_hex)),
                ),
                message_hex=normalize_hex_arg(
                    f"{name}.message_hex",
                    str(item.get("message_hex", args.message_hex)),
                ),
                step_expectations=parse_step_expectations(
                    name, item.get("step_expectations")
                ),
                expected_errors=parse_expected_commands(
                    name, item.get("expected_errors")
                ),
            )
        )

    return scenarios


def response_status(response: str) -> str:
    if response == "RESULT:OK":
        return "ok"
    if response == "RESULT:INVALID":
        return "invalid"
    if response.startswith("RESULT:"):
        return "payload"
    if response.startswith("ERROR:"):
        return "error"
    return "unknown"


def make_step(name: str, response: str) -> dict[str, object]:
    status = response_status(response)
    payload_hex = extract_hex_payload(response) if status == "payload" else None
    return {
        "name": name,
        "status": status,
        "response": response,
        "payload_bytes": len(payload_hex) // 2 if payload_hex is not None else 0,
    }


def apply_expectation(
    step: dict[str, object],
    *,
    status: Optional[str],
    response: Optional[str],
) -> Optional[str]:
    if status is None and response is None:
        return None

    mismatches: List[str] = []
    actual_status = str(step["status"])
    actual_response = str(step["response"])

    if status is not None:
        step["expected_status"] = status
        if actual_status != status:
            mismatches.append(f"expected status {status}, got {actual_status}")

    if response is not None:
        step["expected_response"] = response
        if actual_response != response:
            mismatches.append(f"expected response {response}, got {actual_response}")

    expectation_met = not mismatches
    step["expectation_met"] = expectation_met

    if expectation_met:
        return None

    return f"{step['name']}: " + "; ".join(mismatches)


def issue_command(
    transport: BaseTransport,
    command: str,
    *,
    timeout: float,
    command_delay: float,
    verbose: bool,
    records: List[CommandRecord],
    allow_error: bool = False,
    append_newline: bool = True,
) -> str:
    if command_delay > 0:
        time.sleep(command_delay)
    if verbose:
        print(f"> {command}")
    transport.send_text(command, append_newline=append_newline)
    response_line = transport.wait_for(
        lambda line: extract_protocol_response(line) is not None,
        timeout,
    )
    response = extract_protocol_response(response_line)
    if response is None:
        raise SessionError(f"missing protocol response for {command}")
    records.append(CommandRecord(command=command, response=response))
    if verbose:
        print(response)
    if response.startswith("ERROR:") and not allow_error:
        raise SessionError(f"{command} failed with {response}")
    return response


def tamper_last_byte(hex_payload: str) -> str:
    last = int(hex_payload[-2:], 16) ^ 0x01
    return hex_payload[:-2] + f"{last:02x}"


def run_single_scenario(
    transport: BaseTransport,
    scenario: SmokeScenario,
    args: argparse.Namespace,
) -> dict[str, object]:
    records: List[CommandRecord] = []
    steps: List[dict[str, object]] = []
    mismatches: List[str] = []
    step_expectations = {item.name: item for item in scenario.step_expectations}

    def record_step(name: str, response: str) -> None:
        step = make_step(name, response)
        expectation = step_expectations.get(name)
        mismatch = apply_expectation(
            step,
            status=expectation.status if expectation is not None else None,
            response=expectation.response if expectation is not None else None,
        )
        if mismatch is not None:
            mismatches.append(mismatch)
        steps.append(step)

    response = issue_command(
        transport,
        "SELFTEST::",
        timeout=args.response_timeout,
        command_delay=args.command_delay,
        verbose=args.verbose,
        records=records,
    )
    expect_result_ok(response)
    record_step("SELFTEST", response)

    response = issue_command(
        transport,
        f"SEED:DRBG:0:{scenario.seed_hex}",
        timeout=args.response_timeout,
        command_delay=args.command_delay,
        verbose=args.verbose,
        records=records,
    )
    expect_result_ok(response)
    record_step("SEED", response)

    response = issue_command(
        transport,
        f"KEYGEN:MLKEM:{scenario.kem_level}:",
        timeout=args.response_timeout,
        command_delay=args.command_delay,
        verbose=args.verbose,
        records=records,
    )
    record_step("KEYGEN_MLKEM", response)
    mlkem_keygen = extract_hex_payload(response)
    mlkem_pk_hex_len = MLKEM_SIZES[scenario.kem_level]["pk"] * 2
    mlkem_pk_hex = mlkem_keygen[:mlkem_pk_hex_len]
    mlkem_sk_hex = mlkem_keygen[mlkem_pk_hex_len:]

    response = issue_command(
        transport,
        f"ENCAPS:MLKEM:{scenario.kem_level}:{mlkem_pk_hex}",
        timeout=args.response_timeout,
        command_delay=args.command_delay,
        verbose=args.verbose,
        records=records,
    )
    record_step("ENCAPS_MLKEM", response)
    mlkem_encaps = extract_hex_payload(response)
    mlkem_ct_hex_len = MLKEM_SIZES[scenario.kem_level]["ct"] * 2
    mlkem_ct_hex = mlkem_encaps[:mlkem_ct_hex_len]
    mlkem_ss_hex = mlkem_encaps[mlkem_ct_hex_len:]

    response = issue_command(
        transport,
        f"DECAPS:MLKEM:{scenario.kem_level}:{mlkem_ct_hex}{mlkem_sk_hex}",
        timeout=args.response_timeout,
        command_delay=args.command_delay,
        verbose=args.verbose,
        records=records,
    )
    record_step("DECAPS_MLKEM", response)
    mlkem_decaps = extract_hex_payload(response)
    if mlkem_decaps != mlkem_ss_hex:
        raise SessionError("ML-KEM shared secrets did not match")

    response = issue_command(
        transport,
        f"KEYGEN:MLDSA:{scenario.sig_level}:",
        timeout=args.response_timeout,
        command_delay=args.command_delay,
        verbose=args.verbose,
        records=records,
    )
    record_step("KEYGEN_MLDSA", response)
    mldsa_keygen = extract_hex_payload(response)
    mldsa_pk_hex_len = MLDSA_SIZES[scenario.sig_level]["pk"] * 2
    mldsa_pk_hex = mldsa_keygen[:mldsa_pk_hex_len]
    mldsa_sk_hex = mldsa_keygen[mldsa_pk_hex_len:]

    response = issue_command(
        transport,
        f"SIGN:MLDSA:{scenario.sig_level}:{mldsa_sk_hex}{scenario.message_hex}",
        timeout=args.response_timeout,
        command_delay=args.command_delay,
        verbose=args.verbose,
        records=records,
    )
    record_step("SIGN_MLDSA", response)
    mldsa_sig = extract_hex_payload(response)

    response = issue_command(
        transport,
        f"VERIFY:MLDSA:{scenario.sig_level}:{mldsa_pk_hex}{scenario.message_hex}{mldsa_sig}",
        timeout=args.response_timeout,
        command_delay=args.command_delay,
        verbose=args.verbose,
        records=records,
    )
    expect_result_ok(response)
    record_step("VERIFY_MLDSA", response)

    response = issue_command(
        transport,
        f"VERIFY:MLDSA:{scenario.sig_level}:{mldsa_pk_hex}{scenario.message_hex}{tamper_last_byte(mldsa_sig)}",
        timeout=args.response_timeout,
        command_delay=args.command_delay,
        verbose=args.verbose,
        records=records,
    )
    expect_result_invalid(response)
    record_step("VERIFY_MLDSA_TAMPERED", response)

    for expected in scenario.expected_errors:
        response = issue_command(
            transport,
            expected.command,
            timeout=(
                expected.response_timeout
                if expected.response_timeout is not None
                else args.response_timeout
            ),
            command_delay=args.command_delay,
            verbose=args.verbose,
            records=records,
            allow_error=True,
            append_newline=expected.append_newline,
        )
        step = make_step(expected.name, response)
        mismatch = apply_expectation(
            step,
            status=expected.status,
            response=expected.response,
        )
        if mismatch is not None:
            mismatches.append(mismatch)
        steps.append(step)

    return {
        "name": scenario.name,
        "status": "ok" if not mismatches else "mismatch",
        "kem_level": scenario.kem_level,
        "sig_level": scenario.sig_level,
        "message_hex": scenario.message_hex,
        "seed_hex": scenario.seed_hex,
        "mlkem_pk_bytes": len(mlkem_pk_hex) // 2,
        "mlkem_sk_bytes": len(mlkem_sk_hex) // 2,
        "mlkem_ct_bytes": len(mlkem_ct_hex) // 2,
        "mlkem_ss_bytes": len(mlkem_ss_hex) // 2,
        "mldsa_pk_bytes": len(mldsa_pk_hex) // 2,
        "mldsa_sk_bytes": len(mldsa_sk_hex) // 2,
        "mldsa_sig_bytes": len(mldsa_sig) // 2,
        "mismatches": mismatches,
        "steps": steps,
        "commands": [asdict(record) for record in records],
    }


def run_smoke_session(transport: BaseTransport, args: argparse.Namespace) -> dict[str, object]:
    scenarios = load_scenarios(args)
    wait_for_startup(transport, args.startup_timeout)
    results = [run_single_scenario(transport, scenario, args) for scenario in scenarios]

    if args.scenario_file is None:
        return results[0]

    mismatch_count = sum(1 for item in results if item.get("status") != "ok")
    return {
        "status": "ok" if mismatch_count == 0 else "mismatch",
        "scenario_file": str(args.scenario_file.resolve()),
        "scenario_count": len(results),
        "mismatch_count": mismatch_count,
        "scenarios": results,
    }


def run_self_tests(verbose: bool) -> int:
    response_cases = [
        ("\x1b[32mRESULT:OK\x1b[0m", "RESULT:OK"),
        ("uart: RESULT:INVALID", "RESULT:INVALID"),
        ("<dbg> ERROR:BUFFER_TOO_SMALL extra prompt", "ERROR:BUFFER_TOO_SMALL"),
        ("noise RESULT:deadbeef acvp> ", "RESULT:deadbeef"),
        ("plain text only", None),
    ]
    startup_cases = [
        ("PQCP Serial ACVP Interface", True),
        ("*** Booting Zephyr... Ready for commands (type HELP::)", True),
        ("uart: Type HELP:: for syntax", True),
        ("random debug line", False),
    ]
    normalize_hex_cases = [
        ("seed_hex", "AA00ff", "aa00ff"),
        ("message_hex", " 0011 ", "0011"),
    ]
    response_status_cases = [
        ("RESULT:OK", "ok"),
        ("RESULT:INVALID", "invalid"),
        ("RESULT:deadbeef", "payload"),
        ("ERROR:INVALID_LEVEL", "error"),
        ("debug only", "unknown"),
    ]

    for raw, expected in response_cases:
        actual = extract_protocol_response(raw)
        if actual != expected:
            raise SessionError(
                f"extract_protocol_response({raw!r}) produced {actual!r}, "
                f"expected {expected!r}"
            )
        if verbose:
            print(f"[self-test] response case OK: {raw!r} -> {actual!r}")

    for raw, expected in startup_cases:
        actual = is_startup_line(raw)
        if actual != expected:
            raise SessionError(
                f"is_startup_line({raw!r}) produced {actual!r}, expected {expected!r}"
            )
        if verbose:
            print(f"[self-test] startup case OK: {raw!r} -> {actual!r}")

    for field, raw, expected in normalize_hex_cases:
        actual = normalize_hex_arg(field, raw)
        if actual != expected:
            raise SessionError(
                f"normalize_hex_arg({field!r}, {raw!r}) produced {actual!r}, "
                f"expected {expected!r}"
            )
        if verbose:
            print(f"[self-test] normalize_hex_arg OK: {raw!r} -> {actual!r}")

    for field, raw in (("seed_hex", "abc"), ("message_hex", "00xz")):
        try:
            normalize_hex_arg(field, raw)
        except SessionError:
            pass
        else:
            raise SessionError(
                f"normalize_hex_arg({field!r}, {raw!r}) should have failed"
            )

    for raw, expected in response_status_cases:
        actual = response_status(raw)
        if actual != expected:
            raise SessionError(
                f"response_status({raw!r}) produced {actual!r}, expected {expected!r}"
            )
        if verbose:
            print(f"[self-test] response_status OK: {raw!r} -> {actual!r}")

    scenario_data = {
        "scenarios": [
            {
                "name": "self-test-scenario",
                "kem_level": 768,
                "sig_level": 65,
                "seed_hex": DEFAULT_SEED_HEX,
                "message_hex": DEFAULT_MESSAGE_HEX,
                "step_expectations": {
                    "VERIFY_MLDSA_TAMPERED": {
                        "status": "invalid",
                        "response": "RESULT:INVALID",
                    }
                },
                "expected_errors": [
                    {
                        "name": "INVALID_LEVEL",
                        "command": "KEYGEN:MLKEM:999:",
                        "response": "ERROR:INVALID_LEVEL",
                    },
                    {
                        "name": "PARTIAL_TIMEOUT",
                        "command": "KEYGEN:MLKEM:768:",
                        "append_newline": False,
                        "response_timeout": 7.0,
                        "response": "ERROR:TIMEOUT",
                    }
                ],
            }
        ]
    }
    with tempfile.TemporaryDirectory() as tmp_dir:
        scenario_path = Path(tmp_dir) / "scenarios.json"
        scenario_path.write_text(json.dumps(scenario_data))
        scenario_args = argparse.Namespace(
            scenario_file=scenario_path,
            kem_level=768,
            sig_level=65,
            seed_hex=DEFAULT_SEED_HEX,
            message_hex=DEFAULT_MESSAGE_HEX,
        )
        scenarios = load_scenarios(scenario_args)
        if len(scenarios) != 1:
            raise SessionError("load_scenarios did not return the expected scenario count")
        if scenarios[0].step_expectations[0].response != "RESULT:INVALID":
            raise SessionError("step_expectations were not parsed correctly")
        if scenarios[0].expected_errors[0].response != "ERROR:INVALID_LEVEL":
            raise SessionError("expected_errors were not parsed correctly")
        if scenarios[0].expected_errors[1].append_newline is not False:
            raise SessionError("append_newline was not parsed correctly")
        if scenarios[0].expected_errors[1].response_timeout != 7.0:
            raise SessionError("response_timeout was not parsed correctly")
        if verbose:
            print("[self-test] load_scenarios parsed expectations successfully")

    print("ACVP host-driver self-tests passed.")
    return 0


def build_transport(args: argparse.Namespace) -> BaseTransport:
    if args.serial_port:
        return SerialTransport(
            args.serial_port,
            baudrate=args.baudrate,
            char_delay=args.char_delay,
        )

    env = os.environ.copy()
    for key in HOST_ENV_BLACKLIST:
        env.pop(key, None)

    return SubprocessTransport(
        args.run_command,
        cwd=args.cwd.resolve() if args.cwd else None,
        env=env,
        char_delay=args.char_delay,
    )


def main() -> int:
    args = parse_args()
    if args.self_test:
        try:
            return run_self_tests(args.verbose)
        except SessionError as exc:
            print(f"ACVP host-driver self-tests failed: {exc}", file=sys.stderr)
            return 1

    transport = build_transport(args)

    try:
        summary = run_smoke_session(transport, args)
    except SessionError as exc:
        if args.transcript_out:
            args.transcript_out.write_text("\n".join(transport.transcript) + "\n")
        print(f"ACVP smoke failed: {exc}", file=sys.stderr)
        return 1
    finally:
        transport.close()

    if args.transcript_out:
        args.transcript_out.write_text("\n".join(transport.transcript) + "\n")

    if args.json_out:
        args.json_out.write_text(json.dumps(summary, indent=2) + "\n")

    if summary.get("status") != "ok":
        print("ACVP smoke session completed with expectation mismatches.", file=sys.stderr)
        print(json.dumps(summary, indent=2))
        return 1

    print("ACVP smoke session completed successfully.")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
