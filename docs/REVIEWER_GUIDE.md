# Technical review route

For a quick review, follow the code rather than the wider project description:

1. [CMake](../CMakeLists.txt), [Kconfig](../Kconfig) and [west.yml](../west.yml):
   Zephyr module integration and native dependency pins.
2. [ML-KEM wrapper](../src/mlkem_zephyr.c) and
   [ML-DSA wrapper](../src/mldsa_zephyr.c): firmware crypto integration.
3. [ACVP negatives](../tests/ztest_acvp_serial_negative) and
   [KAT fixtures](../tests/ztest_acvp_kat): command recovery and expected outputs.
4. [Advisor](../src/deployment_advisor.c) and
   [host tests](../tests/host_deployment_advisor): bounded decisions and deterministic ranking.
5. [Result summary](../results/summaries/results_summary.csv),
   [provenance](../results/final/benchmark_provenance.json) and
   [verifier](../scripts/verify_public_artifacts.py): retained measurements and integrity checks.
6. [TCG plugin](../tools/tcg_ct_plugin) and
   [Rust coordinator](../tools/pqcp_fleet_coordinator): guest instrumentation and host-side systems work.

The [README quick checks](../README.md#quick-checks) need no Zephyr installation.
The [architecture boundaries](ARCHITECTURE.md) explain the public TLS self-test,
separate host signing provider and private implementations not shipped here.

Public CI checks result integrity, the host C advisor and the Rust component.
It is not a full Zephyr firmware matrix, physical-board validation or crypto
certification. Read the retained slower results alongside the faster ones.
