#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${ROOT_DIR}/.runtime"
SERVICE_NAME="${DAY0_ADMIN_KEYCHAIN_SERVICE:-agenthub.day0.admin}"
ACCOUNT_NAME="${DAY0_ADMIN_USERNAME:-admin}"
META_FILE="${DAY0_ADMIN_META_FILE:-${RUNTIME_DIR}/day0_admin_credentials_meta.env}"
ROTATE="false"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/bootstrap_day0_admin_credentials.sh [--rotate]

Generates Day 0 admin credentials when missing and stores the password in macOS Keychain.
Writes non-sensitive metadata to .runtime/day0_admin_credentials_meta.env with mode 600.
EOF
}

for arg in "$@"; do
  case "$arg" in
    --rotate)
      ROTATE="true"
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

if ! command -v security >/dev/null 2>&1; then
  echo "macOS 'security' command is required for secure Day 0 credential storage." >&2
  exit 1
fi

mkdir -p "$RUNTIME_DIR"
umask 077

credential_exists() {
  security find-generic-password -s "$SERVICE_NAME" -a "$ACCOUNT_NAME" -w >/dev/null 2>&1
}

generate_password() {
  python3 - <<'PY'
import secrets
import string

upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
lower = "abcdefghijkmnopqrstuvwxyz"
digits = "23456789"
symbols = "!@#$%^&*()-_=+[]{}:,.?"
all_chars = upper + lower + digits + symbols
length = 32

while True:
    pw = "".join(secrets.choice(all_chars) for _ in range(length))
    if (
        any(c in upper for c in pw)
        and any(c in lower for c in pw)
        and any(c in digits for c in pw)
        and any(c in symbols for c in pw)
    ):
        print(pw)
        break
PY
}

if [[ "$ROTATE" == "true" ]]; then
  security delete-generic-password -s "$SERVICE_NAME" -a "$ACCOUNT_NAME" >/dev/null 2>&1 || true
fi

CREATED="false"
if ! credential_exists; then
  GENERATED_PASSWORD="$(generate_password)"
  security add-generic-password -U -s "$SERVICE_NAME" -a "$ACCOUNT_NAME" -w "$GENERATED_PASSWORD" >/dev/null
  CREATED="true"
fi

GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
cat > "$META_FILE" <<EOF
DAY0_ADMIN_USERNAME=${ACCOUNT_NAME}
DAY0_ADMIN_KEYCHAIN_SERVICE=${SERVICE_NAME}
DAY0_ADMIN_STORED_IN=macos-keychain
DAY0_ADMIN_LAST_BOOTSTRAP_UTC=${GENERATED_AT}
EOF
chmod 600 "$META_FILE"

if [[ "$CREATED" == "true" ]]; then
  echo "Created Day 0 admin credential in macOS Keychain (service=${SERVICE_NAME}, account=${ACCOUNT_NAME})."
else
  echo "Day 0 admin credential already exists in macOS Keychain (service=${SERVICE_NAME}, account=${ACCOUNT_NAME})."
fi
echo "Metadata written to ${META_FILE}."
