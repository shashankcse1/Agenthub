#!/usr/bin/env bash
# Functional smoke: API health always; UI same-origin proxy when UI_BASE is up.
set -euo pipefail

UI_BASE="${UI_BASE:-http://127.0.0.1:4173}"
API_BASE="${API_BASE:-http://127.0.0.1:8000}"
REQUIRE_UI="${REQUIRE_UI:-0}"

echo "Checking API health at ${API_BASE}/health…"
curl -fsS --max-time 5 "${API_BASE}/health" | head -c 120 >/dev/null
echo " API ok"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
echo "Checking community docs are present…"
for f in README.md CONTRIBUTING.md SECURITY.md CODE_OF_CONDUCT.md LICENSE docs/EXPLORING.md; do
  [[ -f "${ROOT}/${f}" ]] || { echo "Missing ${f}"; exit 1; }
done

ui_up=0
if curl -s --max-time 2 -o /dev/null -w "%{http_code}" "${UI_BASE}/" | grep -q '^200$'; then
  ui_up=1
fi

if [[ "$ui_up" -eq 1 ]]; then
  echo "Checking login.html…"
  code="$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${UI_BASE}/login.html")"
  [[ "$code" == "200" ]] || { echo "login.html returned ${code}"; exit 1; }
  echo "Checking same-origin proxied /health via UI…"
  proxied="$(curl -fsS --max-time 5 "${UI_BASE}/health")"
  echo "$proxied" | grep -q '"status"' || { echo "Proxied /health missing status: $proxied"; exit 1; }
  echo "UI proxy smoke ok."
elif [[ "$REQUIRE_UI" == "1" ]]; then
  echo "UI not reachable at ${UI_BASE} and REQUIRE_UI=1"
  exit 1
else
  echo "UI not running at ${UI_BASE} — skipped proxy checks (set REQUIRE_UI=1 to require)."
fi

echo "Functional console smoke passed."
