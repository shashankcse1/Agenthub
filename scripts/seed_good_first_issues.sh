#!/usr/bin/env bash
# Create GitHub issues from docs/GOOD_FIRST_ISSUES.md (requires gh auth).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI not found. Install GitHub CLI, then run: gh auth login" >&2
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "Not authenticated. Run: gh auth login" >&2
  exit 1
fi

REPO="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)}"
if [[ -z "${REPO}" ]]; then
  REPO="shashankcse1/Agenthub"
fi

echo "Seeding good-first issues on ${REPO}…"

create_issue() {
  local title="$1"
  local body="$2"
  shift 2
  local labels=("$@")
  local args=(issue create --repo "$REPO" --title "$title" --body "$body")
  local label
  for label in "${labels[@]}"; do
    args+=(--label "$label")
  done
  if gh "${args[@]}"; then
    echo "Created: $title"
  else
    echo "Skipped or failed (label missing?): $title" >&2
    # Retry without labels if label creation failed
    gh issue create --repo "$REPO" --title "$title" --body "$body" || true
  fi
}

# Ensure common labels exist (best-effort)
for label in "good first issue" "help wanted" docs frontend backend; do
  gh label create "$label" --repo "$REPO" --force >/dev/null 2>&1 || true
done

create_issue \
  "good-first: Add Overview screenshot to README" \
  "$(cat <<'EOF'
## Task
Capture Overview after local login and embed it in the root README.

## Acceptance
- Store image under `docs/assets/overview.png` (or `.webp`)
- Embed in root `README.md`
- No secrets / tokens / customer data in the capture

See `docs/GOOD_FIRST_ISSUES.md` item 1.
EOF
)" \
  "good first issue" "help wanted" "docs" "frontend"

create_issue \
  "good-first: Broken-link sweep on community docs" \
  "$(cat <<'EOF'
## Task
Fix dead links in README, CONTRIBUTING, SECURITY, and docs/EXPLORING.md.

## Acceptance
- All checked links resolve or are intentionally updated
- PR lists any remaining external gaps

See `docs/GOOD_FIRST_ISSUES.md` item 2.
EOF
)" \
  "good first issue" "help wanted" "docs"

create_issue \
  "good-first: SDK hello-chat sample" \
  "$(cat <<'EOF'
## Task
Add a minimal chat example to sdk/python and/or sdk/js READMEs (no hardcoded secrets).

## Acceptance
- Local base URL example
- Linked from root README SDKs section

See `docs/GOOD_FIRST_ISSUES.md` item 3.
EOF
)" \
  "good first issue" "help wanted" "docs"

create_issue \
  "good-first: Overview empty-state copy for spend cards" \
  "$(cat <<'EOF'
## Task
When Overview spend/audit counts are empty, show a clear next step (Playground or Cost).

## Acceptance
- Matches existing control-center style
- `node --check frontend/app.js`

See `docs/GOOD_FIRST_ISSUES.md` item 4.
EOF
)" \
  "good first issue" "help wanted" "frontend"

create_issue \
  "good-first: Document plane-split in EXPLORING tour" \
  "$(cat <<'EOF'
## Task
Extend docs/EXPLORING.md with a Plane Split subsection and link the plane-split runbook.

## Acceptance
- Clarifies same-origin :4173 vs :8001/:8002 Gateway API Base

See `docs/GOOD_FIRST_ISSUES.md` item 5.
EOF
)" \
  "good first issue" "help wanted" "docs"

echo "Done. Review issues on https://github.com/${REPO}/issues"