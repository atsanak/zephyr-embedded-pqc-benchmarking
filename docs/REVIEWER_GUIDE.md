# Engineering reviewer guide

This route is designed for a focused technical review. Every claim below links
to source, tests, or retained evidence in this repository.

## Five-minute route

1. Read the module boundary in
   [`CMakeLists.txt`](../CMakeLists.txt) and
   [`Kconfig`](../Kconfig).
2. Inspect the allocation-free decision engine in
   [`deployment_advisor.c`](../src/deployment_advisor.c) and its public API in
   [`deployment_advisor.h`](../include/pqcp_zephyr/deployment_advisor.h).
3. Open the host regression harness in
   [`tests/host_deployment_advisor`](../tests/host_deployment_advisor) and the
   full Zephyr ztest in
   [`tests/ztest_deployment_advisor`](../tests/ztest_deployment_advisor).
4. Scan the validated results in
   [`results_summary.csv`](../results/summaries/results_summary.csv) and the
   hash manifest in
   [`included_results_manifest.csv`](../results/summaries/included_results_manifest.csv).
5. Review the Rust control plane in
   [`tools/pqcp_fleet_coordinator`](../tools/pqcp_fleet_coordinator) and the
   QEMU plugin in [`tools/tcg_ct_plugin`](../tools/tcg_ct_plugin).

## What the code demonstrates

| Engineering area | Inspectable evidence |
|---|---|
| Embedded C and Zephyr | Out-of-tree module registration, Kconfig feature gates, QEMU/board targets, ztests, caller-owned workspaces |
| Applied PQC | ML-KEM-512/768/1024 and ML-DSA-44/65/87 wrappers, deterministic KAT paths, ACVP-style serial flows |
| Reproducible measurement | Stable metric rows, paired baseline comparison, provenance sidecar, SHA-256 artifact manifest |
| Decision systems | Deterministic feasibility/ranking engine with explicit blockers, evidence gaps, and next-experiment planning |
| Security validation | Negative serial cases, KAT fixtures, timing smoke tests, QEMU instruction/load/store instrumentation |
| Systems engineering in Rust | SQLite/WAL inventory, encrypted signing root, canonical CBOR/ML-DSA artifacts, deterministic canaries, CLI/REST/SSE |
| Engineering judgement | Clear separation of measured facts, derived decisions, and claims that remain out of scope |

## Reproduce the fast checks

The public CI intentionally includes a toolchain-light path:

```bash
python3 scripts/verify_public_artifacts.py

cc -std=c11 -O2 -Wall -Wextra -Werror \
  -Iinclude -Itests/host_deployment_advisor/shim \
  src/deployment_advisor.c tests/host_deployment_advisor/main.c \
  -o /tmp/pqcp-advisor-test
/tmp/pqcp-advisor-test
```

With Rust installed:

```bash
cargo test --locked --all-targets \
  --manifest-path tools/pqcp_fleet_coordinator/Cargo.toml
```

With a configured Zephyr workspace:

```bash
west build -p always -b qemu_x86_64 \
  samples/pqcp_deployment_advisor \
  -d build-deployment-advisor
west build -d build-deployment-advisor -t run
```

## Scope discipline

This public cut is intentionally reviewable rather than exhaustive. Generated
build trees, raw logs, local environments, duplicated result exports, private
secure-world measurements, and unpublished planning material are excluded.
QEMU results support regression and methodology review; they are not presented
as silicon performance. The repository is not a certification claim.
