# AgentHub

**Governed AI gateway and control plane** for routing, budgets, virtual keys, Flow Studio workflows, and operator evidence — OpenAI-compatible inference with institutional guardrails.

[![Backend CI](https://github.com/shashankcse1/Agenthub/actions/workflows/backend-ci.yml/badge.svg)](https://github.com/shashankcse1/Agenthub/actions/workflows/backend-ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](./CONTRIBUTING.md)

> AgentHub is an **inference / AI gateway control plane**. It coexists with enterprise identity tools; it does **not** crawl SaaS OAuth estates or replace full IGA/ISPM products.

## Why AgentHub

| You get | Instead of |
|---------|------------|
| One operator plane for routes, keys, JIT, cost, audit, Flow Studio | Spreadsheet + ad-hoc proxy configs |
| OpenAI-compatible `/v1/*` with policy, risk, and dual-approval rails | Ungoverned direct provider calls |
| Same-origin local console with session cookies + CSRF | Fragile cross-origin demo logins |
| Explicit non-goals and honesty gates for leadership claims | Overstated “fully secure / #1” marketing |

## Quick start (local)

**Prereqs:** Docker (PostgreSQL), Python 3.11+, Node not required for the static UI.

```bash
# From repo root
./scripts/startlocal_detached.sh
```

1. Open **http://127.0.0.1:4173/login.html**
2. Keep **API Base** as `http://127.0.0.1:4173` (same-origin UI→API proxy)
3. Sign in with the Day-0 `admin` user (see [Day-0 hardening](./backend/docs/security/day0-password-and-secrets-hardening.md); on macOS the password may be in Keychain service `agenthub.day0.admin`)

Health checks:

```bash
curl -sS http://127.0.0.1:4173/health | head -c 200
curl -sS http://127.0.0.1:8000/health | head -c 200
```

More runbooks: [operations-quickstart.md](./operations-quickstart.md) · [frontend/README.md](./frontend/README.md) · [DEPLOYMENT.md](./DEPLOYMENT.md)

## Explore the console

Priority operator surfaces (nav order):

1. **Playground** — governed prompts and runs  
2. **Benchmark & Scan** — evaluation history  
3. **Routing & Gateway** — routes, keys, JIT, NHI, runtime risk, Cursor gateway ops  
4. **Flow Studio** — design → govern → run multi-step workflows  
5. **Compliance / Observability / Cost** — evidence and spend  

## Repository map

```text
backend/     FastAPI control + data plane, tests, governance docs
frontend/    Operator console (static UI + same-origin API proxy)
sdk/         Python + JS helpers
extensions/  GuardBridge browser extension scaffolds
scripts/     Local/prod stack helpers
blog/        Program / “governed velocity” narrative packs (optional reading)
```

Canonical status & design:

- [Product completion status](./backend/docs/governance/product-completion-status.md)
- [Architecture](./architecture-document.md)
- [API inventory & UI map](./backend/docs/governance/api-inventory-and-ui-map.md)
- [Coverage map](./backend/docs/governance/ui-api-design-coverage-map.md)
- [Documentation source of truth](./backend/docs/governance/documentation-source-of-truth.md)
- [Agent delivery guide](./AGENTS.md)

## SDKs

- Python: [`sdk/python`](./sdk/python)
- JavaScript: [`sdk/js`](./sdk/js)
- Publish notes: [`sdk/PUBLISH.md`](./sdk/PUBLISH.md)

## Contributing

We want this project to mature with community help — docs, tests, UI polish, and carefully scoped gateway features.

- Start here: **[CONTRIBUTING.md](./CONTRIBUTING.md)**
- Security reports: **[SECURITY.md](./SECURITY.md)**
- Code of conduct: **[CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)**
- Good first areas: docs clarity, `frontend/` smoke checks, inventory/coverage sync, SDK examples, unit tests under `backend/tests/`

Please open an issue before large architecture changes. Privileged and security-sensitive paths must follow [backend/AGENTS.md](./backend/AGENTS.md).

## Visibility & community

If AgentHub helps you:

1. ⭐ Star the repo  
2. Open a “Show and tell” Discussion or Issue with your use case  
3. File bugs with repro steps (local ports, API Base, role)  
4. Share a short demo clip of Flow Studio or Routing & Gateway  

Maintainers: keep Issues enabled, label `good first issue` / `help wanted`, and reply to first-time PRs within a few days when possible.

## License

Apache License 2.0 — see [LICENSE](./LICENSE).

## Disclaimer

This software is provided as-is for operators and builders. Do **not** treat any build as “fully secure” or free of residual risk. See the [residual and accepted risk register](./backend/docs/security/residual-and-accepted-risk-register.md).
