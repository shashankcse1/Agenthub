# Changelog

Notable changes for operators and contributors. Dates are UTC-oriented delivery days. For full history see `git log`.

## 2026-08-14 — Functional E2E + critical-path 99% coverage gate

- `tests/test_functional_e2e_console.py` — login → cookie Overview APIs → CSRF mutation → logout + idle re-auth
- Unit packs for `session_cookies`, `csrf_protection`, `runtime_env` (critical spine **100%** lines)
- `scripts/check_critical_coverage.sh` + CI step (`fail_under=99`)
- `frontend/scripts/functional_console_e2e_smoke.sh`
- Strategy doc: [docs/COVERAGE.md](./docs/COVERAGE.md)

## 2026-08-09 — Community explorer pack

- Added [docs/EXPLORING.md](./docs/EXPLORING.md) 30-minute guided tour
- Added [docs/GOOD_FIRST_ISSUES.md](./docs/GOOD_FIRST_ISSUES.md) seed pack + `scripts/seed_good_first_issues.sh`
- Added [docs/GLOSSARY.md](./docs/GLOSSARY.md) and [docs/MAINTAINER_CHECKLIST.md](./docs/MAINTAINER_CHECKLIST.md)
- Root README: architecture sketch, TOC, explorer/contributor entry points

## 2026-08-08 — Community front door

- Root `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`
- Apache-2.0 `LICENSE` + `NOTICE`
- GitHub issue templates + pull request template
- Local same-origin UI→API proxy for cookie sessions; idle-session login bounce
- Gateway runtime risk policy (CC-048 deepen; default disabled)
- Merged Flow Orchestration / leadership / NHI coexistence work onto `main`

## Earlier

See product completion and architecture sync notes:

- [backend/docs/governance/product-completion-status.md](./backend/docs/governance/product-completion-status.md)
- [architecture-document.md](./architecture-document.md) §0
