#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/results/local"
mkdir -p "${OUT_DIR}"

python3 "${ROOT_DIR}/scripts/export_results.py" \
  --output "${OUT_DIR}/benchmark_results.csv" \
  --provenance-output "${OUT_DIR}/benchmark_provenance.json" \
  --platform qemu_x86_64 \
  "$@"
