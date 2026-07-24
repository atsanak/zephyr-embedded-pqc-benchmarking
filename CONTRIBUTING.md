# Contributing

This repository is public for engineering review under the terms in
[`LICENSE`](LICENSE). Issues that improve reproducibility, portability,
documentation, or validation are welcome.

Before proposing a change:

1. Keep generated build directories, raw logs, local environments, and key
   material out of the repository.
2. Preserve the distinction between QEMU regression evidence, build-only
   footprint evidence, and physical-board measurements.
3. Add or update a focused test for behavior changes.
4. Run:

   ```bash
   python3 scripts/verify_public_artifacts.py
   cc -std=c11 -O2 -Wall -Wextra -Werror \
     -Iinclude -Itests/host_deployment_advisor/shim \
     src/deployment_advisor.c tests/host_deployment_advisor/main.c \
     -o /tmp/pqcp-advisor-test
   /tmp/pqcp-advisor-test
   ```

Contributions do not change the proprietary evaluation license. Do not submit
third-party or employer-owned material unless you have the right to do so.
