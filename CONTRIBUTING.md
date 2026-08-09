# Contributing to AgentHub

Thanks for helping mature this project. Contributions are welcome for docs, tests, UI clarity, SDKs, and scoped gateway features that stay aligned with the designed product lane.

## Before you start

1. Read the root [README.md](./README.md) and run the local quickstart.
2. Skim [backend/AGENTS.md](./backend/AGENTS.md) if you touch auth, routing, privileged actions, or inference.
3. For UI work, check [api-inventory-and-ui-map.md](./backend/docs/governance/api-inventory-and-ui-map.md) and [ui-api-design-coverage-map.md](./backend/docs/governance/ui-api-design-coverage-map.md). Do not invent consoles without inventory rows.
4. Open an **issue** for anything larger than a small fix so scope stays reviewable.

## Good first contributions

| Area | Examples |
|------|----------|
| Docs | Clarify quickstart, fix broken links, add screenshots/GIFs to README |
| Frontend | Accessibility, empty states, copy, `node --check frontend/app.js` after JS edits |
| Tests | Narrow pytest coverage for an existing endpoint or bug |
| SDK | Examples, typings, README samples in `sdk/python` / `sdk/js` |
| DX | Script help text, error messages, issue/PR template tweaks |

Label ideas for maintainers: `good first issue`, `help wanted`, `docs`, `frontend`, `backend`, `security`.

## Development loop

```bash
./scripts/startlocal_detached.sh
# UI: http://127.0.0.1:4173/login.html  (API Base = same origin)
```

Backend tests (from `backend/` with local env loaded as needed):

```bash
cd backend
python3 -m pytest -q path/to/test_file.py
```

Frontend syntax check after JS edits:

```bash
node --check frontend/app.js
```

Prefer the **narrowest** useful validation for your change.

## Pull request checklist

- [ ] Describes **why** the change exists (not only what files moved)
- [ ] Linked issue (when applicable)
- [ ] Docs updated when operator-facing behavior changes (`frontend/README.md`, inventory/coverage, SoT delta for substantial slices)
- [ ] No secrets committed (`.env`, Keychain dumps, API keys, extension private keys)
- [ ] Security / least-privilege preserved for auth and privileged routes
- [ ] Tests or a clear manual smoke path for the touched slice

### PR title style

Follow recent history: short imperative summary focused on outcome.

Examples:

- `Fix same-origin login bounce on local console`
- `Add pytest coverage for runtime risk evaluate deny path`
- `Clarify Flow Studio variable-map docs for contributors`

## Design boundaries (please respect)

**In scope:** governed inference, routes/keys/JIT, Flow Studio, operator evidence, gateway-scoped NHI coexistence APIs, OpenAI-compatible surfaces already in inventory.

**Out of scope by design:** enterprise SaaS OAuth crawlers, full IARA into arbitrary apps, competitor product branding in the UI, claims of “zero vulnerabilities” / “fully secure.”

## Security-sensitive changes

Report vulnerabilities privately via [SECURITY.md](./SECURITY.md).  
For code changes that affect auth, dual-approval, cookies/CSRF, SSRF, or inference allow/deny: include abuse-case tests and update the residual risk register when risk posture changes.

## Community norms

Be kind and precise. Assume good intent. See [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions are licensed under the Apache License 2.0 ([LICENSE](./LICENSE)).
