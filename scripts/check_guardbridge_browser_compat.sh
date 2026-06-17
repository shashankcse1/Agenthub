#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
EXT_DIR="$ROOT_DIR/extensions/guardbridge"
REPORT_DIR="$ROOT_DIR/artifacts/extensions"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
REPORT_FILE="$REPORT_DIR/guardbridge_browser_compat_$TIMESTAMP.txt"
STRICT_SAFARI=0
STRICT_FIREFOX_LINT=0

usage() {
  cat <<'EOF'
Usage: bash scripts/check_guardbridge_browser_compat.sh [--strict-safari]

Options:
  --strict-safari   Fail if Safari converter tooling is unavailable.
  --strict-firefox-lint  Fail if web-ext lint tooling is unavailable.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --strict-safari)
      STRICT_SAFARI=1
      shift
      ;;
    --strict-firefox-lint)
      STRICT_FIREFOX_LINT=1
      shift
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

mkdir -p "$REPORT_DIR"

pass() { echo "[PASS] $1" | tee -a "$REPORT_FILE"; }
fail() { echo "[FAIL] $1" | tee -a "$REPORT_FILE"; exit 1; }
info() { echo "[INFO] $1" | tee -a "$REPORT_FILE"; }

run_web_ext_lint() {
  local lint_dir
  lint_dir="$(mktemp -d)"
  mkdir -p "$lint_dir/src"
  cp "$EXT_DIR/manifests/firefox/manifest.json" "$lint_dir/manifest.json"
  cp "$EXT_DIR/src/"*.js "$lint_dir/src/"

  if command -v web-ext >/dev/null 2>&1; then
    web-ext lint --source-dir "$lint_dir" >/dev/null 2>&1
    local rc=$?
    rm -rf "$lint_dir"
    return $rc
  fi
  if command -v npx >/dev/null 2>&1; then
    npx --yes web-ext lint --source-dir "$lint_dir" >/dev/null 2>&1
    local rc=$?
    rm -rf "$lint_dir"
    return $rc
  fi
  rm -rf "$lint_dir"
  return 127
}

require_file() {
  [[ -f "$1" ]] || fail "Missing file: $1"
}

json_get() {
  local file="$1"
  local expr="$2"
  python3 - "$file" "$expr" <<'PY'
import json
import sys
path, expr = sys.argv[1], sys.argv[2]
with open(path, 'r', encoding='utf-8') as f:
    data = json.load(f)
cur = data
for part in expr.split('.'):
    if not part:
      continue
    if isinstance(cur, dict):
      cur = cur.get(part)
    else:
      cur = None
      break
if isinstance(cur, (dict, list)):
    print(json.dumps(cur))
elif cur is None:
    print("")
else:
    print(str(cur))
PY
}

json_has_value() {
  local file="$1"
  local expr="$2"
  local expected="$3"
  python3 - "$file" "$expr" "$expected" <<'PY'
import json
import sys
path, expr, expected = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, 'r', encoding='utf-8') as f:
    data = json.load(f)
cur = data
for part in expr.split('.'):
    if not part:
      continue
    if isinstance(cur, dict):
      cur = cur.get(part)
    else:
      print('false')
      raise SystemExit(0)
if isinstance(cur, list):
    print('true' if expected in [str(v) for v in cur] else 'false')
else:
    print('true' if str(cur) == expected else 'false')
PY
}

: > "$REPORT_FILE"
info "GuardBridge Browser Compatibility Report"
info "Generated: $TIMESTAMP"

require_file "$EXT_DIR/manifest.json"
require_file "$EXT_DIR/manifests/firefox/manifest.json"
require_file "$EXT_DIR/manifests/chromium/manifest.json"
require_file "$EXT_DIR/src/background.js"
require_file "$EXT_DIR/src/content.js"
require_file "$EXT_DIR/src/common.js"
pass "Required extension files present"

python3 -m json.tool "$EXT_DIR/manifest.json" >/dev/null
python3 -m json.tool "$EXT_DIR/manifests/chromium/manifest.json" >/dev/null
python3 -m json.tool "$EXT_DIR/manifests/firefox/manifest.json" >/dev/null
pass "All extension manifests are valid JSON"

[[ "$(json_get "$EXT_DIR/manifest.json" manifest_version)" == "3" ]] || fail "Root manifest must be MV3"
[[ "$(json_get "$EXT_DIR/manifests/chromium/manifest.json" manifest_version)" == "3" ]] || fail "Chromium manifest must be MV3"
[[ "$(json_get "$EXT_DIR/manifests/firefox/manifest.json" manifest_version)" == "2" ]] || fail "Firefox manifest must be MV2"
pass "Manifest version strategy is valid (MV3 Chromium + MV2 Firefox)"

[[ "$(json_get "$EXT_DIR/manifest.json" background.service_worker)" == "src/background.js" ]] || fail "Root manifest service worker path invalid"
[[ "$(json_get "$EXT_DIR/manifests/chromium/manifest.json" background.service_worker)" == "src/background.js" ]] || fail "Chromium manifest service worker path invalid"
[[ "$(json_get "$EXT_DIR/manifests/firefox/manifest.json" background.scripts)" == "[\"src/background.js\"]" ]] || fail "Firefox background script path invalid"
pass "Background script paths resolve in packaged root layout"

[[ "$(json_has_value "$EXT_DIR/manifest.json" host_permissions "https://*/*")" == "true" ]] || fail "Root manifest missing https host permissions"
[[ "$(json_has_value "$EXT_DIR/manifests/firefox/manifest.json" permissions "https://*/*")" == "true" ]] || fail "Firefox manifest missing https permissions"
pass "Host permissions present for extension matching"

if command -v node >/dev/null 2>&1; then
  node --check "$EXT_DIR/src/common.js"
  node --check "$EXT_DIR/src/background.js"
  node --check "$EXT_DIR/src/content.js"
  pass "Extension JavaScript syntax valid"
else
  info "Node not found; skipped JS syntax checks"
fi

if command -v xcrun >/dev/null 2>&1; then
  SAFARI_CONVERTER_PATH="$(xcrun --find safari-web-extension-converter 2>/dev/null || true)"
  if [[ -n "$SAFARI_CONVERTER_PATH" && -x "$SAFARI_CONVERTER_PATH" ]]; then
    pass "Safari converter tooling available ($SAFARI_CONVERTER_PATH)"
  else
    if [[ "$STRICT_SAFARI" -eq 1 ]]; then
      ACTIVE_DEV_DIR="$(xcode-select -p 2>/dev/null || echo unknown)"
      info "Active developer directory: $ACTIVE_DEV_DIR"
      info "Remediation: install full Xcode.app and run: sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer"
      info "Then verify: xcrun --find safari-web-extension-converter"
      info "Helper: bash scripts/configure_xcode_for_safari_converter.sh"
      fail "Safari converter tooling unavailable while strict mode is enabled"
    else
      info "xcrun available but safari-web-extension-converter check failed"
    fi
  fi
else
  if [[ "$STRICT_SAFARI" -eq 1 ]]; then
    info "Remediation: install Xcode command-line tools and full Xcode.app"
    fail "xcrun not available; Safari conversion requires Xcode command-line tools"
  else
    info "xcrun not available; Safari conversion requires Xcode command-line tools"
  fi
fi

if command -v web-ext >/dev/null 2>&1 || command -v npx >/dev/null 2>&1; then
  if run_web_ext_lint; then
    pass "web-ext lint passed for Firefox workflow"
  else
    if [[ "$STRICT_FIREFOX_LINT" -eq 1 ]]; then
      fail "web-ext lint failed while strict Firefox lint is enabled"
    else
      info "web-ext available but lint check failed"
    fi
  fi
else
  if [[ "$STRICT_FIREFOX_LINT" -eq 1 ]]; then
    fail "web-ext not installed while strict Firefox lint is enabled"
  else
    info "web-ext not installed; Firefox lint/sign checks skipped"
  fi
fi

bash "$ROOT_DIR/scripts/package_guardbridge_extension.sh" >/dev/null
LATEST_PACKAGE_DIR="$(ls -1dt "$ROOT_DIR"/artifacts/extensions/guardbridge_* 2>/dev/null | head -n1 || true)"
[[ -n "$LATEST_PACKAGE_DIR" ]] || fail "Package output directory not found"
[[ -f "$LATEST_PACKAGE_DIR/guardbridge-chromium.zip" ]] || fail "Chromium package not found"
[[ -f "$LATEST_PACKAGE_DIR/guardbridge-firefox.zip" ]] || fail "Firefox package not found"
pass "Packaging artifacts generated for Chromium and Firefox"

info "Supported browser matrix target: chrome, edge, firefox, safari, opera, brave, arc, vivaldi, samsung"
pass "Cross-browser compatibility checks completed"

echo "Report written to: $REPORT_FILE"
