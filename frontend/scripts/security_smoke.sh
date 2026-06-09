#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INDEX_FILE="$ROOT_DIR/index.html"
APP_FILE="$ROOT_DIR/app.js"
ERROR_404_FILE="$ROOT_DIR/404.html"
ERROR_500_FILE="$ROOT_DIR/500.html"
ACCESSIBILITY_REPORT_FILE="$ROOT_DIR/accessibility-conformance-wcag22aa.md"

fail() {
  echo "[FAIL] $1"
  exit 1
}

pass() {
  echo "[PASS] $1"
}

[[ -f "$INDEX_FILE" ]] || fail "Missing index.html"
[[ -f "$APP_FILE" ]] || fail "Missing app.js"
[[ -f "$ERROR_404_FILE" ]] || fail "Missing 404.html"
[[ -f "$ERROR_500_FILE" ]] || fail "Missing 500.html"
pass "Default error pages are present"

[[ -f "$ACCESSIBILITY_REPORT_FILE" ]] || fail "Missing accessibility conformance report"
for token in "Standard: WCAG 2.2 AA" "Last Reviewed:" "Overall Status:" "Criteria Evidence"; do
  grep -F "$token" "$ACCESSIBILITY_REPORT_FILE" >/dev/null || fail "Accessibility report missing token: $token"
done
pass "Accessibility conformance report baseline is present"

if grep -qi "fonts.googleapis.com\|fonts.gstatic.com" "$INDEX_FILE"; then
  fail "External font providers found in index.html"
fi
pass "No external font provider references"

CSP_LINE="$(grep -i "content-security-policy" "$INDEX_FILE" || true)"
[[ -n "$CSP_LINE" ]] || fail "CSP meta tag missing"

for token in "default-src 'self'" "script-src 'self'" "object-src 'none'" "frame-ancestors 'none'" "base-uri 'none'"; do
  echo "$CSP_LINE" | grep -F "$token" >/dev/null || fail "CSP missing token: $token"
done
pass "CSP includes baseline hardening directives"

if grep -n "innerHTML" "$APP_FILE" >/dev/null; then
  fail "Unsafe innerHTML usage detected in app.js"
fi
pass "No innerHTML sinks in app.js"

grep -F 'class="skip-link"' "$INDEX_FILE" >/dev/null || fail "Skip link missing in index.html"
grep -F ':focus-visible' "$ROOT_DIR/styles.css" >/dev/null || fail "Focus-visible style missing in styles.css"
grep -F 'class="sr-only"' "$INDEX_FILE" >/dev/null || fail "Screen-reader table captions missing"
pass "Accessibility baseline elements are present"

grep -F "function parseApiBaseOrThrow" "$APP_FILE" >/dev/null || fail "API base validation helper missing"
pass "API base validation helper present"

grep -F "window.confirm(" "$APP_FILE" >/dev/null || fail "Production write confirmation guard missing"
pass "Production confirmation guard present"

grep -F "setTableMessage" "$APP_FILE" >/dev/null || fail "Safe table message renderer missing"
grep -F "appendTableRow" "$APP_FILE" >/dev/null || fail "Safe table row renderer missing"
pass "Safe DOM table rendering helpers present"

echo "Security smoke checks completed successfully."
