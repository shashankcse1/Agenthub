#!/usr/bin/env bash
# Enforce ≥99% line coverage on the critical console-auth path modules.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/Library/Python/3.9/bin:${PATH:-}"

if ! python3 -c "import coverage, pytest_cov" >/dev/null 2>&1; then
  python3 -m pip install -q 'pytest-cov>=4.0' 'coverage>=7.0'
fi

echo "Running critical-path coverage gate (fail_under=99)…"
python3 -m pytest -q \
  tests/test_session_cookies_unit.py \
  tests/test_runtime_env_unit.py \
  tests/test_csrf_protection_unit.py \
  tests/test_security_hardening_wave4.py \
  tests/test_security_hardening_wave5.py \
  tests/test_functional_e2e_console.py \
  --cov=app.services.session_cookies \
  --cov=app.services.csrf_protection \
  --cov=app.services.runtime_env \
  --cov-config=.coveragerc.critical \
  --cov-report=term-missing \
  --cov-report=xml:coverage-critical.xml \
  --cov-fail-under=99 \
  --tb=short

echo "Critical-path coverage gate passed (≥99%)."