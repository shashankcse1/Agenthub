# Maintainer checklist — visibility & maturity

Use this after community-health files land on `main`.

## GitHub repository settings

- [ ] Repo is **Public**
- [ ] **About**: short description + homepage URL
- [ ] **Topics**: `ai-gateway`, `llm-proxy`, `openai-compatible`, `fastapi`, `governance`, `agent-orchestration`, `llm-ops`
- [ ] **Issues** enabled
- [ ] **Discussions** enabled (Q&A + Show and tell)
- [ ] **Security → Private vulnerability reporting** enabled
- [ ] Default branch `main` protected (PR + status checks when CI is stable)
- [ ] Pin this repo on the owner/org profile

## Community cadence

- [ ] Seed issues from [GOOD_FIRST_ISSUES.md](./GOOD_FIRST_ISSUES.md) (`./scripts/seed_good_first_issues.sh`)
- [ ] Label triage: `bug`, `enhancement`, `docs`, `frontend`, `backend`, `good first issue`, `help wanted`, `security`
- [ ] Respond to first-time PRs within a few days when possible
- [ ] Keep CI green on `main` ([backend-ci](../.github/workflows/backend-ci.yml))

## Content that converts visitors

- [ ] README screenshot/GIF (`docs/assets/`)
- [ ] Short LinkedIn / blog / Show HN post linking the Exploring tour
- [ ] Keep root README free of deep governance walls — link out instead

## Do not

- [ ] Claim “fully secure” / “zero vulnerabilities”
- [ ] Lead newcomers into 100+ governance markdown files before a working login
- [ ] Commit `.env`, Day-0 passwords, or extension private material
