#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  echo "Usage: ./scripts/smokee2e.sh"
  echo "Runs backend baseline smoke and gateway pre-call/mirroring smoke."
  echo "Optional env: SKIP_GATEWAY_PRECALL_MIRROR_SMOKE=1"
  exit 0
fi

echo "[smoke] Running baseline backend smoke..."
bash "$ROOT_DIR/backend/scripts/smokee2e.sh"

if [[ "${SKIP_GATEWAY_PRECALL_MIRROR_SMOKE:-0}" == "1" ]]; then
  echo "[smoke] Skipping gateway pre-call/mirroring smoke (SKIP_GATEWAY_PRECALL_MIRROR_SMOKE=1)."
  exit 0
fi

echo "[smoke] Running gateway pre-call/mirroring smoke..."
bash "$ROOT_DIR/scripts/smoke_gateway_precall_mirroring.sh"

echo "[smoke] All smoke suites passed."
