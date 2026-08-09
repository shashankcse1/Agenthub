# Contributing guidelines

Thanks for helping AgentHub mature. This guide explains how to propose changes, run the project locally, and get a pull request reviewed.

## Table of contents

- [Code of conduct](#code-of-conduct)
- [Ways to contribute](#ways-to-contribute)
- [Good first issues](#good-first-issues)
- [Development setup](#development-setup)
- [Making changes](#making-changes)
- [Pull request process](#pull-request-process)
- [Documentation expectations](#documentation-expectations)
- [Design boundaries](#design-boundaries)
- [Security](#security)
- [License](#license)

## Code of conduct

Participation is governed by our [Code of Conduct](./CODE_OF_CONDUCT.md). Be respectful and constructive.

## Ways to contribute

| Kind | Examples |
| ---- | -------- |
| Docs | Root README clarity, broken links, screenshots/GIFs, operator runbooks |
| Frontend | Empty states, a11y, copy, console polish (`frontend/`) |
| Backend / tests | Narrow `pytest` coverage, bug fixes with repro |
| SDK | Samples and typings in `sdk/python`, `sdk/js` |
| Community | Triage issues, improve templates, write good-first tasks |

Open an **issue** before large architecture or new-console work so scope stays reviewable.

## Good first issues

Look for labels:

- `good first issue`
- `help wanted`
- `docs`

You can also propose a small task with the **Good first issue suggestion** issue template.

## Development setup

**Prereqs:** Docker (PostgreSQL), Python 3.11+.

```bash
git clone https://github.com/shashankcse1/Agenthub.git
cd Agenthub
./scripts/startlocal_detached.sh
```

1. Open http://127.0.0.1:4173/login.html  
2. Keep **API Base** as `http://127.0.0.1:4173` (same-origin UI→API proxy)  
3. Sign in with the Day-0 `admin` user — see [Day-0 hardening](./backend/docs/security/day0-password-and-secrets-hardening.md)

More detail: [README.md](./README.md) · [operations-quickstart.md](./operations-quickstart.md)

### Useful checks

```bash
# Backend (narrowest useful path)
cd backend && python3 -m pytest -q path/to/test_file.py

# Frontend JS syntax after editing app.js
node --check frontend/app.js
```

## Making changes

1. Fork (or branch from `main`)
2. Create a topic branch: `git checkout -b fix/short-description`
3. Keep diffs focused — one concern per PR when possible
4. Match existing style; avoid drive-by refactors
5. For UI/API work, align with:
   - [api-inventory-and-ui-map.md](./backend/docs/governance/api-inventory-and-ui-map.md)
   - [ui-api-design-coverage-map.md](./backend/docs/governance/ui-api-design-coverage-map.md)
   - [backend/AGENTS.md](./backend/AGENTS.md) for security/role constraints

Do **not** invent operator consoles without an inventory row.

## Pull request process

1. Fill out the PR template (summary, test plan, risk notes)
2. Link the related issue (`Fixes #123`)
3. Ensure CI is green when workflows apply
4. Request review; respond to feedback with new commits (prefer not force-pushing shared review branches unless asked)

### PR title style

Short imperative summary of the outcome:

- `Fix same-origin login bounce on local console`
- `Add pytest coverage for runtime risk deny path`
- `Clarify Flow Studio variable-map docs`

### Review checklist (authors)

- [ ] Explains **why** the change exists  
- [ ] Docs updated when operator-facing behavior changes  
- [ ] No secrets committed  
- [ ] Privileged paths keep least-privilege / dual-approval behavior  
- [ ] Tests or a clear manual smoke path for the touched slice  

## Documentation expectations

When you change a workflow:

- Update `frontend/README.md` if the operator surface changed  
- Update inventory + coverage map when API/UI coverage changes  
- Record substantial slices in `backend/docs/governance/documentation-source-of-truth.md` (delta register)  

Agent-oriented delivery notes live in [AGENTS.md](./AGENTS.md); humans should still start at the root README.

## Design boundaries

**In scope:** governed inference, routes/keys/JIT, Flow Studio, operator evidence, gateway-scoped NHI coexistence, OpenAI-compatible surfaces already inventoried.

**Out of scope by design:**

- Enterprise SaaS OAuth / identity crawlers  
- Full IARA into arbitrary non-gateway apps  
- Competitor product branding in the operator UI  
- Claims of “zero vulnerabilities” or “fully secure”  

## Security

Report vulnerabilities privately — see [SECURITY.md](./SECURITY.md).  
Do not file public issues for exploitable findings.

## License

By contributing, you agree that your contributions are licensed under the Apache License 2.0 — see [LICENSE](./LICENSE).
