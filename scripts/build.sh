#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation

set -euo pipefail

APP_PATH="${1:-tests/ztest_primitive}"
BOARD="${2:-qemu_x86_64}"
BUILD_DIR="${3:-build}"

if ! command -v west >/dev/null 2>&1; then
  echo "error: west is required; install Zephyr west tooling first" >&2
  exit 2
fi

exec west build -p always -b "${BOARD}" "${APP_PATH}" -d "${BUILD_DIR}"
