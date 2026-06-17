#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
EXT_DIR="$ROOT_DIR/extensions/guardbridge"
OUT_BASE="$ROOT_DIR/artifacts/extensions"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
VERSION=""
OUT_DIR=""

usage() {
  cat <<'EOF'
Usage: bash scripts/package_guardbridge_extension.sh [--version <semver>] [--out-dir <path>]

Builds browser extension artifacts for GuardBridge:
- Chromium package (MV3)
- Firefox package (manifest variant)

Outputs zip artifacts and checksum manifest.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

[[ -d "$EXT_DIR" ]] || { echo "Missing extension directory: $EXT_DIR"; exit 1; }

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="$OUT_BASE/guardbridge_$TIMESTAMP"
fi

mkdir -p "$OUT_DIR"
STAGE_DIR="$OUT_DIR/stage"
mkdir -p "$STAGE_DIR"

validate_json() {
  local file="$1"
  python3 -m json.tool "$file" >/dev/null
}

zip_dir() {
  local src_dir="$1"
  local out_file="$2"
  if command -v zip >/dev/null 2>&1; then
    (cd "$src_dir" && zip -qr "$out_file" .)
  else
    ditto -c -k --sequesterRsrc --keepParent "$src_dir" "$out_file"
  fi
}

require_file() {
  [[ -f "$1" ]] || { echo "Missing file: $1"; exit 1; }
}

require_file "$EXT_DIR/manifest.json"
require_file "$EXT_DIR/manifests/chromium/manifest.json"
require_file "$EXT_DIR/manifests/firefox/manifest.json"
require_file "$EXT_DIR/src/background.js"
require_file "$EXT_DIR/src/content.js"
require_file "$EXT_DIR/src/common.js"

validate_json "$EXT_DIR/manifest.json"
validate_json "$EXT_DIR/manifests/chromium/manifest.json"
validate_json "$EXT_DIR/manifests/firefox/manifest.json"

if [[ -n "$VERSION" ]]; then
  python3 - "$EXT_DIR/manifest.json" "$VERSION" <<'PY'
import json
import sys
path, version = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
data["version"] = version
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
fi

# Chromium package
CHROMIUM_STAGE="$STAGE_DIR/guardbridge-chromium"
mkdir -p "$CHROMIUM_STAGE/src"
cp "$EXT_DIR/manifest.json" "$CHROMIUM_STAGE/manifest.json"
cp "$EXT_DIR/src/"*.js "$CHROMIUM_STAGE/src/"

# Firefox package
FIREFOX_STAGE="$STAGE_DIR/guardbridge-firefox"
mkdir -p "$FIREFOX_STAGE/src"
cp "$EXT_DIR/manifests/firefox/manifest.json" "$FIREFOX_STAGE/manifest.json"
cp "$EXT_DIR/src/"*.js "$FIREFOX_STAGE/src/"

CHROMIUM_ZIP="$OUT_DIR/guardbridge-chromium.zip"
FIREFOX_ZIP="$OUT_DIR/guardbridge-firefox.zip"

zip_dir "$CHROMIUM_STAGE" "$CHROMIUM_ZIP"
zip_dir "$FIREFOX_STAGE" "$FIREFOX_ZIP"

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$CHROMIUM_ZIP" "$FIREFOX_ZIP" > "$OUT_DIR/SHA256SUMS"
fi

cat > "$OUT_DIR/manifest.txt" <<EOF
GuardBridge Extension Package Manifest
Generated: $TIMESTAMP
Source: $EXT_DIR
Output: $OUT_DIR

Artifacts:
- guardbridge-chromium.zip
- guardbridge-firefox.zip
- SHA256SUMS
EOF

echo "[PASS] GuardBridge extension packages created at: $OUT_DIR"
