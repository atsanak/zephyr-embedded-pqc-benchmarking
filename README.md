# Zephyr Embedded PQC Engineering

[![Public portfolio CI](https://github.com/atsanak/zephyr-embedded-pqc-benchmarking/actions/workflows/portfolio-ci.yml/badge.svg)](https://github.com/atsanak/zephyr-embedded-pqc-benchmarking/actions/workflows/portfolio-ci.yml)

I built this review version around post-quantum cryptography on Zephyr: first
build the firmware, then exercise the crypto interfaces and collect benchmark
output, and finally check the retained results against their provenance and
artifact hashes. The code is deliberately a small public cut of a larger project.

Start with the [C deployment advisor](src/deployment_advisor.c), the
[results summary](results/summaries/results_summary.csv), or the
[reviewer route](docs/REVIEWER_GUIDE.md). Those are the shortest paths from a
CV description to code and evidence you can check.

## Engineering areas

- **Embedded C / Zephyr:** out-of-tree module, CMake, Kconfig, west, caller-owned
  buffers, entropy backends and ztests. See [module wiring](CMakeLists.txt) and
  [C APIs](include/pqcp_zephyr).
- **PQC integration:** ML-KEM-512/768/1024 through `mlkem-native` and
  ML-DSA-44/65/87 through `mldsa-native` in the firmware, with pinned
  [dependencies](west.yml), [PSA driver shims](src/psa_mlkem_driver.c), and
  [streaming signature support](src/mldsa_streaming.c).
- **Security testing:** known-answer vectors check expected crypto outputs;
  ACVP-style serial tests exercise commands, malformed inputs and recovery.
  [Timing smoke](tests/ztest_ct_smoke) and the [QEMU TCG plugin](tools/tcg_ct_plugin)
  check execution regressions, not formal constant-time security.
- **Measurement / Python tooling:** cycle and footprint measurements, paired
  baselines, CSV analysis and SHA-256-bound result provenance. See
  [export tooling](scripts/export_results.py) and [retained evidence](results/final).
- **On-device decisions:** an [allocation-free advisor](samples/pqcp_deployment_advisor)
  checks resource and evidence constraints, preserves rejected candidates,
  and ranks feasible choices deterministically. The bounded
  [C campaign accumulator](src/deployment_campaign.c) projects repeated
  observations into advisor inputs, with integer median/p90/p99/MAD,
  variance warnings and worst-case resource footprints.
- **Host-side Rust:** a separate [fleet coordinator](tools/pqcp_fleet_coordinator)
  uses SQLite/WAL, Tokio/Axum, CLI/REST/SSE interfaces, CBOR artifacts and
  encrypted local signing storage. It is an evaluation component, not a
  production custody service; its current signing dependency is separate
  from the firmware's native backend contract.

## Architecture and scope

![Public engineering overview](figures/architecture_diagram.svg)

The public code covers firmware integration, measurement, a deployment advisor
and an independently reviewable host coordinator. The larger private project
also includes executable crypto scheduling, key lifecycle management, protected
channel recovery and durable metadata recovery. Those implementations and
their full evidence packs are not copied into this repository.

The public TLS path is a crypto/protocol self-test with mbedTLS/PSA integration
points, **not a live standardized PQC TLS handshake**. The host coordinator is
not an end-to-end public fleet deployment. [Architecture boundaries](docs/ARCHITECTURE.md)
separate what is present here from the wider work.

## Retained results

[results_summary.csv](results/summaries/results_summary.csv) contains 18 paired
primitive summaries across all six parameter sets on `qemu_x86_64`. For example,
ML-KEM-768 decapsulation records 83,700 cycles against 165,700 for the retained
baseline. ML-KEM-512 encapsulation is slower in this run (+5.11%); the dataset
keeps that result too. These are QEMU regression measurements, not silicon claims.

- [Trusted source CSV](results/final/validated_primitive_benchmarks_qemu.csv)
- [Provenance sidecar](results/final/benchmark_provenance.json)
- [Artifact hash and byte manifest](results/summaries/included_results_manifest.csv)

## Quick checks

From the repository root, Python 3.12+ and a C compiler are enough for these checks:

```bash
python3 scripts/verify_public_artifacts.py
bash scripts/check_host_c.sh
SANITIZE=1 bash scripts/check_host_c.sh
```

These C checks cover campaign-to-advisor integration, failed/missing observations,
capacity bounds and malformed state, plus AddressSanitizer/UBSan. Campaign inputs
in the host tests are **synthetic fixtures**, not new performance results.
Quantiles use floor indexing on sorted samples; campaign stability alone is not
independent cross-build reproducibility. Enable `CONFIG_PQCP_DEPLOYMENT_CAMPAIGN`
for the firmware component; it consumes observations, rather than measuring crypto.

## Build a Zephyr target

Install west and the toolchain required by the pinned Zephyr revision in
[west.yml](west.yml). From a checkout outside an existing west workspace:

```bash
west init -l .
west update
west zephyr-export
./scripts/build.sh tests/ztest_primitive qemu_x86_64 build-ztest-primitive
west build -d build-ztest-primitive -t run
```

`qemu-system-x86_64` is required to run that target. In a configured workspace,
`./scripts/run_benchmark.sh` generates new results under `results/local/`;
it does not replace the curated results. Rust is needed only for the host
coordinator. Its [local checks](tools/pqcp_fleet_coordinator/README.md) run separately.

## Limits and terms

Retained Nucleo rows are build-only footprint evidence. Physical-board timing
and energy are not claimed where measurements are absent. Hashes detect
artifact changes; they do not establish who produced the evidence. KAT and
ACVP-style tests do not constitute NIST certification.

This repository is public for review under the proprietary evaluation
[license](LICENSE), not open source. See [SECURITY.md](SECURITY.md) for reporting
and [CONTRIBUTING.md](CONTRIBUTING.md) for contribution terms.
