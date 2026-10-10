#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
flags=(-std=c11 -O2 -Wall -Wextra -Werror)
if [[ "${SANITIZE:-0}" == 1 ]]; then
  flags+=(-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer)
fi
for harness in advisor campaign; do
  sources=("$root/src/deployment_advisor.c")
  if [[ "$harness" == campaign ]]; then
    sources+=("$root/src/deployment_campaign.c")
  fi
  "${CC:-cc}" "${flags[@]}" -I"$root/include" \
    -I"$root/tests/host_deployment_advisor/shim" \
    "${sources[@]}" "$root/tests/host_deployment_$harness/main.c" \
    -o "$out/$harness"
  "$out/$harness"
done
