#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

info() { echo "[INFO] $1"; }
pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; exit 1; }

active_dev_dir="$(xcode-select -p 2>/dev/null || true)"

find_xcode_dev_dir() {
  local app
  for app in /Applications/Xcode.app /Applications/Xcode-beta.app; do
    if [[ -d "$app/Contents/Developer" ]]; then
      echo "$app/Contents/Developer"
      return 0
    fi
  done
  return 1
}

info "Active developer directory: ${active_dev_dir:-unknown}"

if xcrun --find safari-web-extension-converter >/dev/null 2>&1; then
  converter_path="$(xcrun --find safari-web-extension-converter)"
  pass "Safari converter already available: $converter_path"
  exit 0
fi

if ! target_dev_dir="$(find_xcode_dev_dir)"; then
  fail "Xcode.app not found in /Applications. Install full Xcode first."
fi

info "Detected Xcode developer directory: $target_dev_dir"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  info "Root privileges required to switch developer directory."
  echo
  echo "Run the following command:"
  echo "  sudo xcode-select --switch '$target_dev_dir'"
  echo
  echo "Then verify:"
  echo "  xcrun --find safari-web-extension-converter"
  exit 1
fi

xcode-select --switch "$target_dev_dir"

if xcrun --find safari-web-extension-converter >/dev/null 2>&1; then
  converter_path="$(xcrun --find safari-web-extension-converter)"
  pass "Safari converter enabled: $converter_path"
  exit 0
fi

fail "Developer directory switched, but safari-web-extension-converter is still unavailable"
