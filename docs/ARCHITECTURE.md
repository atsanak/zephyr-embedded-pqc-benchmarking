# Architecture boundaries

The [overview figure](../figures/architecture_diagram.svg) shows the engineering
areas represented by this public cut. It is not a claim that a complete fleet
deployment is packaged here.

## Firmware

[CMake](../CMakeLists.txt), [Kconfig](../Kconfig) and [west](../west.yml) wire the
Zephyr module to pinned native algorithm packages. The module owns the C APIs,
entropy abstraction, PSA shims, samples and serial metric markers. The public
TLS sample performs a self-test, not a live TLS socket handshake.

The [deployment advisor](../src/deployment_advisor.c) consumes caller-provided
measurements and evidence flags. It performs no cryptography or heap allocation.
Budget violations remain rejected candidates; missing evidence is reported
separately. It does not establish that the input measurements are trustworthy.

## Measurement

Device markers feed the [CSV exporter](../scripts/export_results.py). The
[artifact verifier](../scripts/verify_public_artifacts.py) checks retained
hashes, byte counts, row counts and algorithm coverage. The
[TCG plugin](../tools/tcg_ct_plugin) counts guest instructions, loads and stores
inside marked ELF regions; access counts are not memory-address traces or a
constant-time proof.

## Host coordinator

The [Rust component](../tools/pqcp_fleet_coordinator) provides local state,
artifact issuance and rollout logic through a shared service used by CLI and
REST interfaces. Its signing provider is a separate evaluation dependency,
not the firmware's `mldsa-native` wrapper. The full device-side fleet protocol
and production key custody are outside this public cut.

The larger private runtime and protected-channel implementation are not
published here. No private release pack is required for the public fast checks.
