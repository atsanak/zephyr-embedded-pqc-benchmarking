# Zephyr Embedded PQC Engineering Portfolio

[![Public portfolio CI](https://github.com/atsanak/zephyr-embedded-pqc-benchmarking/actions/workflows/portfolio-ci.yml/badge.svg)](https://github.com/atsanak/zephyr-embedded-pqc-benchmarking/actions/workflows/portfolio-ci.yml)

A buildable public review cut of a larger Zephyr post-quantum trust stack:
embedded C APIs for ML-KEM and ML-DSA, ACVP/KAT validation, reproducible
benchmark evidence, an allocation-free deployment decision engine, a QEMU
instruction/memory-access plugin, and an offline-first Rust fleet coordinator.

This is not a collection of screenshots or architecture claims. The highlighted
subsystems include source, tests, fixtures, and CI entry points that can be
reviewed independently.

> This repository is source-visible for engineering evaluation under
> [`LICENSE`](LICENSE). It is not a certified cryptographic module. QEMU
> measurements are regression/methodology evidence, build-only results are
> labelled as such, and unpublished secure-world measurements from the larger
> project are intentionally excluded.

## Start here

| If you have… | Review this |
|---|---|
| 2 minutes | The [architecture](docs/ARCHITECTURE.md) and the capability map below |
| 5 minutes | The [technical reviewer route](docs/REVIEWER_GUIDE.md) |
| 10 minutes | The [deployment advisor](src/deployment_advisor.c), its [host regression harness](tests/host_deployment_advisor/main.c), and the [Zephyr ztest](tests/ztest_deployment_advisor/src/main.c) |
| 15 minutes | The [Rust fleet coordinator](tools/pqcp_fleet_coordinator) and its deterministic rollout state machine |
| A Zephyr workspace | Build the samples/tests and replay the retained benchmark workflow |

## Capability map

| Layer | What is implemented | Inspectable proof |
|---|---|---|
| PQC primitives | ML-KEM-512/768/1024 and ML-DSA-44/65/87 through `mlkem-native` and `mldsa-native` | C wrappers in [`src`](src), native dependency pins in [`west.yml`](west.yml) |
| Embedded integration | Out-of-tree Zephyr module, Kconfig gates, RNG abstraction, PSA shims, QEMU and MCU configs | [`CMakeLists.txt`](CMakeLists.txt), [`Kconfig`](Kconfig), [`samples`](samples) |
| Validation | KAT fixtures, ACVP-style serial commands, malformed-input/timeout paths, boot self-test, TLS and timing smoke tests | [`tests`](tests) |
| Reproducible evidence | Stable `PQCP_METRIC` rows, paired comparison, CSV export, provenance sidecar, SHA-256 manifest | [`scripts`](scripts), [`results/final`](results/final), [`verify_public_artifacts.py`](scripts/verify_public_artifacts.py) |
| Deployment intelligence | Deterministic, allocation-free feasibility/ranking engine with blocker masks, evidence gaps, and next-experiment plans | [`deployment_advisor.h`](include/pqcp_zephyr/deployment_advisor.h), [`pqcp_deployment_advisor`](samples/pqcp_deployment_advisor) |
| CT regression instrumentation | QEMU TCG plugin counts instructions, loads, and stores in ELF-resolved firmware regions | [`tcg_ct_plugin`](tools/tcg_ct_plugin), [`ztest_ct_instr`](tests/ztest_ct_instr), [`run_ct_instruction_checks.py`](scripts/run_ct_instruction_checks.py) |
| Fleet operations | SQLite/WAL state, encrypted ML-DSA root, canonical CBOR artifacts, deterministic canaries, CLI, REST, and SSE | [`pqcp_fleet_coordinator`](tools/pqcp_fleet_coordinator) |

## Architecture

![PQCP public engineering architecture](figures/architecture_diagram.svg)

The boundaries are deliberate:

- the cryptographic provider packages implement algorithms;
- the Zephyr module owns embedded APIs, configuration, and stable markers;
- measurement tooling turns device output into provenance-bound evidence;
- the deployment advisor consumes evidence facts without executing crypto;
- the host control plane manages fleet state and signed artifacts.

The detailed data flow and failure semantics are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Selected trust-stack additions

### Allocation-free on-device deployment advisor

The advisor evaluates measured candidates against security, latency, RAM,
stack, heap, flash, energy, provider, and evidence constraints. It preserves
rejected candidates, distinguishes a hard blocker from missing evidence, ranks
only feasible choices, and emits a prioritized experiment plan.

Properties visible in the code:

- caller-owned fixed-capacity storage; no heap allocation;
- deterministic tie-breaking and stable transcript tokens;
- explicit input validation and bounded candidate/gap counts;
- separate `ACCEPTED`, `CONDITIONAL`, and `REJECTED` states;
- replay test proving the same inputs produce the same ranking;
- host-fast checks plus a full Zephyr ztest suite.

Run the toolchain-light check:

```bash
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -Iinclude -Itests/host_deployment_advisor/shim \
  src/deployment_advisor.c tests/host_deployment_advisor/main.c \
  -o /tmp/pqcp-advisor-test
/tmp/pqcp-advisor-test
```

Build the Zephyr demonstration:

```bash
west build -p always -b qemu_x86_64 \
  samples/pqcp_deployment_advisor \
  -d build-deployment-advisor
west build -d build-deployment-advisor -t run
```

### Offline-first Rust fleet coordinator

`pqcp-fleet` is the host-side control plane for a larger device trust protocol.
It stores inventory and rollout state in SQLite/WAL, verifies enrollment,
issues firmware-compatible ML-DSA artifacts, publishes policy/revocation
epochs, and evaluates deterministic canary rollouts.

The local signing root is encrypted with Argon2id and XChaCha20-Poly1305. The
file provider is explicitly a development/evaluation provider; the API boundary
allows replacement with an HSM, secure element, PKCS#11 provider, or managed
signer.

```bash
cargo test --locked --all-targets \
  --manifest-path tools/pqcp_fleet_coordinator/Cargo.toml
```

The public cut contains the independently reviewable coordinator. The complete
firmware fleet plane from the larger private project is not represented as a
public production deployment.

### QEMU instruction and memory-access evidence

The TCG plugin hooks begin/end marker addresses resolved from the exact
firmware ELF and records guest instruction, load, and store counts for every
measured region. The paired Zephyr test exercises valid and corrupted ML-KEM
decapsulation paths; the runner rejects divergent profiles.

This is stronger regression evidence than wall-clock timing alone. It is still
not a formal constant-time proof: memory addresses and microarchitectural
effects remain out of scope.

```bash
python3 scripts/run_ct_instruction_checks.py --help
```

## Retained benchmark evidence

The public result set contains 18 paired primitive summaries spanning all six
parameter sets. A few representative rows are shown below; negative comparison
values mean fewer cycles than the retained baseline in this specific QEMU run.

| Operation | PQCP cycles | Baseline cycles | Comparison |
|---|---:|---:|---:|
| ML-KEM-768 decapsulation | 83,700 | 165,700 | -49.49% |
| ML-DSA-65 verification | 160,100 | 180,900 | -11.50% |
| ML-DSA-44 signing | 349,000 | 703,700 | -50.41% |

Review the complete data rather than extrapolating from these examples:

- [`validated_primitive_benchmarks_qemu.csv`](results/final/validated_primitive_benchmarks_qemu.csv):
  paired source rows;
- [`results_summary.csv`](results/summaries/results_summary.csv): compact
  review table;
- [`benchmark_provenance.json`](results/final/benchmark_provenance.json):
  generator, source hash, environment, and row coverage;
- [`included_results_manifest.csv`](results/summaries/included_results_manifest.csv):
  SHA-256 and byte count for every retained artifact.

Verify the public evidence without installing Zephyr:

```bash
python3 scripts/verify_public_artifacts.py
```

## Build and run the original benchmark paths

Requirements:

- Python 3.12 or newer;
- `west`, Git, and a compatible Zephyr SDK;
- `qemu-system-x86_64` for QEMU runs;
- Rust only for the fleet coordinator.

Initialize the Zephyr workspace:

```bash
west init -l .
west update
west zephyr-export
```

The native backends may also be initialized as submodules for standalone module
development:

```bash
git submodule update --init --recursive
```

Build and run a primitive validation target:

```bash
./scripts/build.sh tests/ztest_primitive qemu_x86_64 build-ztest-primitive
west build -d build-ztest-primitive -t run
```

Export and analyze a compact local benchmark:

```bash
./scripts/run_benchmark.sh
python3 scripts/analyze_results.py \
  results/final/validated_primitive_benchmarks_qemu.csv
```

## Validation matrix

- `tests/ztest_primitive`: ML-KEM/ML-DSA public API behavior.
- `tests/ztest_acvp_serial`: ACVP-style serial commands.
- `tests/ztest_acvp_serial_negative`: malformed frames and recovery paths.
- `tests/ztest_acvp_kat`: checked-in known-answer fixtures.
- `tests/ztest_kat_boot_verify`: boot-time power-on self-test.
- `tests/ztest_ct_smoke`: timing-smoke regression markers.
- `tests/ztest_ct_instr`: instruction and memory-access regions for the QEMU
  plugin.
- `tests/ztest_tls_selftest`: protocol metric smoke output.
- `tests/ztest_deployment_advisor`: feasibility, ranking, blockers, gaps,
  invalid inputs, determinism, and marker validation.

## Repository map

```text
include/pqcp_zephyr/       Public C APIs
src/                       Zephyr module implementation
samples/                   Runnable firmware demonstrations
tests/                     Zephyr and host regression suites
scripts/                   Build, benchmark, parse, and verification tooling
results/final/             Curated provenance-bound result artifacts
tools/tcg_ct_plugin/       QEMU guest execution instrumentation
tools/pqcp_fleet_coordinator/
                           Rust fleet control plane
docs/                      Architecture and technical review route
```

## Scope and limitations

- QEMU cycle counts support regression and methodology review, not physical
  board performance claims.
- `nucleo_h743zi` rows in the retained set are build-only footprint evidence.
- Energy is absent where no retained physical measurement exists.
- Timing-smoke and instruction/access-count equality are not formal
  constant-time proofs.
- The fleet key-file provider is for local evaluation, not production custody.
- The repository is a curated public slice, not the complete private trust
  stack and not a certification claim.

See [`SECURITY.md`](SECURITY.md) for responsible reporting and assurance
boundaries.
