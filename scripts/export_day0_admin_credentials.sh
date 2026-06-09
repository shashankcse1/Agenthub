#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${ROOT_DIR}/.runtime"
META_FILE="${DAY0_ADMIN_META_FILE:-${RUNTIME_DIR}/day0_admin_credentials_meta.env}"
FORMAT="exports"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/export_day0_admin_credentials.sh [--format=exports|json|basic]

Reads Day 0 admin metadata and retrieves password from macOS Keychain.
EOF
}

for arg in "$@"; do
  case "$arg" in
    --format=*)
      FORMAT="${arg#*=}"
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unsupported option: $arg"
      usage
      exit 1
      ;;
  esac
done

if [[ ! -f "$META_FILE" ]]; then
  echo "Missing metadata file: $META_FILE" >&2
  echo "Run ./scripts/bootstrap_day0_admin_credentials.sh first." >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$META_FILE"

if [[ -z "${DAY0_ADMIN_USERNAME:-}" || -z "${DAY0_ADMIN_KEYCHAIN_SERVICE:-}" ]]; then
  echo "Invalid metadata file: $META_FILE" >&2
  exit 1
fi

if ! command -v security >/dev/null 2>&1; then
  echo "macOS 'security' command is required." >&2
  exit 1
fi

DAY0_ADMIN_PASSWORD="$(security find-generic-password -s "$DAY0_ADMIN_KEYCHAIN_SERVICE" -a "$DAY0_ADMIN_USERNAME" -w)"

case "$FORMAT" in
  exports)
    printf 'export DAY0_ADMIN_USERNAME=%q\n' "$DAY0_ADMIN_USERNAME"
    printf 'export DAY0_ADMIN_PASSWORD=%q\n' "$DAY0_ADMIN_PASSWORD"
    ;;
  json)
    python3 - <<'PY' "$DAY0_ADMIN_USERNAME" "$DAY0_ADMIN_PASSWORD"
import json
import sys
print(json.dumps({"username": sys.argv[1], "password": sys.argv[2]}))
PY
    ;;
  basic)
    python3 - <<'PY' "$DAY0_ADMIN_USERNAME" "$DAY0_ADMIN_PASSWORD"
import base64
import sys
raw = f"{sys.argv[1]}:{sys.argv[2]}".encode("utf-8")
print("Basic " + base64.b64encode(raw).decode("ascii"))
PY
    ;;
  *)
    echo "Unsupported format: $FORMAT" >&2
    exit 1
    ;;
esac
