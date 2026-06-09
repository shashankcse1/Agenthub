#!/usr/bin/env bash
set -u

# Multi-lens review script for local codebases you own.
# Lenses covered:
# - Ethical hacker (safe pattern checks and misconfiguration detection)
# - Vulnerability expert (SAST/dependency scanners when available)
# - UI frontend expert (resilience, accessibility, and fallback checks)
# - Python expert (syntax, test hooks, and security linting)
#
# This script is non-invasive and does not perform active exploitation.

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"

# Ensure common local binary locations are discoverable in non-login shells.
export PATH="/opt/homebrew/bin:$HOME/Library/Python/3.9/bin:$PATH"

PYTHON_BIN="${PYTHON_BIN:-}"
PIP_AUDIT_IGNORE_IDS="${PIP_AUDIT_IGNORE_IDS:-GHSA-6w46-j5rx-g56g,PYSEC-2026-141,GHSA-pq67-6m6q-mj2v,GHSA-gm62-xv2j-4w53,GHSA-2xpw-w6gg-jr37,GHSA-38jv-5279-wg99,PYSEC-2026-161}"

DEEP_MODE=0
STRICT_MODE=0

for arg in "$@"; do
  case "$arg" in
    --deep)
      DEEP_MODE=1
      ;;
    --strict)
      STRICT_MODE=1
      ;;
    --help|-h)
      cat <<'EOF'
Usage: bash scripts/full_stack_expert_review.sh [--deep] [--strict]

Options:
  --deep    Run heavier checks (pytest, optional scanners over full trees)
  --strict  Exit non-zero when any non-optional finding appears

Notes:
  - Run this only against code and environments you are authorized to test.
  - This script performs defensive review checks, not active exploitation.
EOF
      exit 0
      ;;
    *)
      echo "[WARN] Unknown argument: $arg"
      ;;
  esac
done

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

print_section() {
  echo
  echo "============================================================"
  echo "$1"
  echo "============================================================"
}

record_pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "[PASS] $1"
}

record_warn() {
  WARN_COUNT=$((WARN_COUNT + 1))
  echo "[WARN] $1"
}

record_fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "[FAIL] $1"
}

record_info() {
  echo "[INFO] $1"
}

run_required() {
  local label="$1"
  shift
  if "$@"; then
    record_pass "$label"
  else
    record_fail "$label"
  fi
}

run_optional() {
  local label="$1"
  shift
  if "$@"; then
    record_pass "$label"
  else
    record_warn "$label"
  fi
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

resolve_python() {
  if [[ -n "$PYTHON_BIN" ]] && "$PYTHON_BIN" -c "import fastapi, pytest" >/dev/null 2>&1; then
    return 0
  fi

  local candidates=(
    "$BACKEND_DIR/.venv/bin/python"
    "python3"
    "/usr/bin/python3"
    "$HOME/.pyenv/shims/python3"
  )

  local py
  for py in "${candidates[@]}"; do
    if [[ -x "$py" ]] || command -v "$py" >/dev/null 2>&1; then
      if "$py" -c "import fastapi, pytest" >/dev/null 2>&1; then
        PYTHON_BIN="$py"
        export PYTHON_BIN
        return 0
      fi
    fi
  done

  # Fallback to any python3 for non-import checks, even if deps are incomplete.
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
    export PYTHON_BIN
    return 0
  fi

  return 1
}

grep_check() {
  local label="$1"
  local pattern="$2"
  local path="$3"
  if has_cmd rg; then
    if rg -n --hidden --glob '!.git' "$pattern" "$path" >/tmp/review_search_output.txt 2>/dev/null; then
      echo "[DETAIL] Potential hits for $label:"
      cat /tmp/review_search_output.txt
      return 1
    fi
  else
    if grep -RInE --exclude-dir=.git "$pattern" "$path" >/tmp/review_search_output.txt 2>/dev/null; then
      echo "[DETAIL] Potential hits for $label:"
      cat /tmp/review_search_output.txt
      return 1
    fi
  fi
  return 0
}

print_section "Preflight"

if [[ ! -d "$BACKEND_DIR" ]]; then
  record_fail "Backend directory missing at $BACKEND_DIR"
fi
if [[ ! -d "$FRONTEND_DIR" ]]; then
  record_fail "Frontend directory missing at $FRONTEND_DIR"
fi
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  echo "[STOP] Missing required directories."
  exit 1
fi

if has_cmd rg; then
  record_pass "ripgrep available"
else
  record_warn "ripgrep not found; falling back to grep (slower)"
fi

if resolve_python; then
  record_pass "Python runtime selected: $PYTHON_BIN"
else
  record_fail "No usable Python runtime found"
fi

print_section "UI Frontend Expert Review"

if [[ -f "$FRONTEND_DIR/scripts/security_smoke.sh" ]]; then
  run_required "Frontend security smoke checks" bash "$FRONTEND_DIR/scripts/security_smoke.sh"
else
  record_fail "Missing frontend/scripts/security_smoke.sh"
fi

run_required "Default 404 page present" test -f "$FRONTEND_DIR/404.html"
run_required "Default 500 page present" test -f "$FRONTEND_DIR/500.html"
run_required "Accessibility conformance report present" test -f "$FRONTEND_DIR/accessibility-conformance-wcag22aa.md"

run_required "Skip link exists" grep -Fq 'class="skip-link"' "$FRONTEND_DIR/index.html"
run_required "Focus-visible styles exist" grep -Fq ':focus-visible' "$FRONTEND_DIR/styles.css"
run_required "Live region semantics exist" sh -c "grep -Eq 'aria-live=\"(polite|assertive)\"' '$FRONTEND_DIR/index.html'"

print_section "Ethical Hacker Review (Safe Pattern Checks)"

run_required "No frontend innerHTML sinks" grep_check "innerHTML" "innerHTML" "$FRONTEND_DIR/app.js"
run_required "No frontend eval usage" grep_check "eval" "\\beval\\s*\\(" "$FRONTEND_DIR"
run_optional "No frontend document.write usage" grep_check "document.write" "document\\.write\\s*\\(" "$FRONTEND_DIR"
run_optional "No JS Function constructor usage" grep_check "new Function" "new\\s+Function\\s*\\(" "$FRONTEND_DIR"

run_optional "No Python eval usage" grep_check "python eval" "\\beval\\s*\\(" "$BACKEND_DIR/app"
run_optional "No Python exec usage" grep_check "python exec" "\\bexec\\s*\\(" "$BACKEND_DIR/app"
run_optional "No shell=True subprocess in backend" grep_check "subprocess shell=True" "subprocess\\.[A-Za-z_]+\\([^\\)]*shell\\s*=\\s*True" "$BACKEND_DIR/app"
run_optional "No unsafe yaml.load" grep_check "yaml.load" "yaml\\.load\\s*\\(" "$BACKEND_DIR/app"

run_optional "No obvious hardcoded private key blocks" grep_check "private key" "BEGIN (RSA|EC|OPENSSH) PRIVATE KEY" "$ROOT_DIR"
run_optional "No obvious hardcoded cloud secret tokens" grep_check "cloud secret token" "(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z\\-_]{35})" "$ROOT_DIR"

print_section "Python Expert Review"

if [[ -n "$PYTHON_BIN" ]]; then
  run_required "Python syntax compile check" "$PYTHON_BIN" -m compileall -q "$BACKEND_DIR/app"
else
  record_fail "python3 not available"
fi

if [[ "$DEEP_MODE" -eq 1 ]]; then
  run_optional "Backend pytest suite (deep mode)" sh -c "cd '$BACKEND_DIR' && '$PYTHON_BIN' -m pytest -q"
else
  record_info "Skipped backend pytest (use --deep to enable)"
fi

if has_cmd bandit; then
  run_optional "Bandit security scan" sh -c "cd '$BACKEND_DIR' && bandit -q -r app -s B105"
else
  record_warn "bandit not installed (optional)"
fi

if has_cmd pip-audit; then
  if [[ "$DEEP_MODE" -eq 1 ]]; then
    PIP_AUDIT_IGNORE_FLAGS=""
    IFS=',' read -r -a _audit_ids <<< "$PIP_AUDIT_IGNORE_IDS"
    for _id in "${_audit_ids[@]}"; do
      if [[ -n "$_id" ]]; then
        PIP_AUDIT_IGNORE_FLAGS+=" --ignore-vuln $_id"
      fi
    done
    run_optional "Dependency vulnerability audit" sh -c "cd '$BACKEND_DIR' && pip-audit -r requirements.txt $PIP_AUDIT_IGNORE_FLAGS"
  else
    record_info "Skipped dependency vulnerability audit (use --deep to enable)"
  fi
else
  record_warn "pip-audit not installed (optional)"
fi

if has_cmd semgrep; then
  if [[ "$DEEP_MODE" -eq 1 ]]; then
    run_optional "Semgrep OWASP Top 10 scan" sh -c "cd '$ROOT_DIR' && semgrep --quiet --error --config p/owasp-top-ten backend/app frontend"
  else
    record_info "Skipped semgrep scan (use --deep to enable)"
  fi
else
  record_warn "semgrep not installed (optional)"
fi

print_section "Vulnerability Expert Review"

run_optional "CSP present in frontend index" sh -c "grep -iq 'content-security-policy' '$FRONTEND_DIR/index.html'"
run_optional "Referrer policy present" sh -c "grep -iq 'meta name=\"referrer\"' '$FRONTEND_DIR/index.html'"
run_optional "No wildcard CORS policy literals in backend app" grep_check "CORS wildcard" "allow_origins\\s*=\\s*\\[[^]]*\\*|Access-Control-Allow-Origin[^\n]*\\*" "$BACKEND_DIR/app"

if [[ -f "$BACKEND_DIR/scripts/check_control_coverage.py" ]]; then
  if [[ "$DEEP_MODE" -eq 1 ]]; then
    run_optional "Control coverage checker" sh -c "cd '$BACKEND_DIR' && '$PYTHON_BIN' scripts/check_control_coverage.py"
  else
    record_info "Skipped control coverage checker (use --deep to enable)"
  fi
else
  record_warn "control coverage script missing"
fi

print_section "PAM Review (Privilege Access Management)"

run_required "Session secret non-dev validation present" sh -c "grep -Fq 'validate_session_secret_configuration' '$BACKEND_DIR/app/security.py'"
run_required "Day-0 validator checks SESSION_TOKEN_SECRET" sh -c "grep -Fq 'SESSION_TOKEN_SECRET' '$BACKEND_DIR/scripts/validate_day0_secrets.sh'"
run_required "Session issuance policy enforcement present" sh -c "grep -Eq '_enforce_session_issue_policy\(payload, ctx(, policy)?\)' '$BACKEND_DIR/app/routers/auth.py'"
run_required "Cross-actor session issuance requires dual approval" sh -c "grep -Fq 'payload.actor_id != ctx.actor_id' '$BACKEND_DIR/app/routers/auth.py' && grep -Fq 'require_dual_approval(ctx)' '$BACKEND_DIR/app/routers/auth.py'"
run_required "Agent Owner registration scope check present" sh -c "grep -Fq 'payload.owner_id != ctx.actor_id' '$BACKEND_DIR/app/routers/agents.py'"
run_required "Module operations enforce Agent Owner scope" sh -c "grep -Fq '_enforce_agent_owner_scope(agent_id, ctx, db)' '$BACKEND_DIR/app/routers/modules.py'"
run_required "Discovery endpoints restricted from Agent Owner global read" sh -c "! grep -Fq '{\"Platform Admin\", \"Agent Owner\", \"Auditor\"}' '$BACKEND_DIR/app/routers/discovery.py'"
run_required "Cost live endpoint has owner scoping logic" sh -c "grep -Eq 'if ctx.actor_role == (\"Agent Owner\"|ROLE_AGENT_OWNER)' '$BACKEND_DIR/app/routers/cost.py' && grep -Fq '_owned_agent_ids' '$BACKEND_DIR/app/routers/cost.py'"
run_required "Compliance evidence endpoints restricted to admin/auditor" sh -c "! grep -Fq 'require_role(ctx, {\"Platform Admin\", \"Auditor\", \"Agent Owner\"})' '$BACKEND_DIR/app/routers/compliance.py'"

print_section "Summary"

echo "Passes : $PASS_COUNT"
echo "Warnings: $WARN_COUNT"
echo "Fails  : $FAIL_COUNT"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  echo "Result: REVIEW FAILED"
  exit 1
fi

if [[ "$STRICT_MODE" -eq 1 && "$WARN_COUNT" -gt 0 ]]; then
  echo "Result: REVIEW WARNING-FAIL (strict mode)"
  exit 2
fi

echo "Result: REVIEW PASSED"
exit 0
