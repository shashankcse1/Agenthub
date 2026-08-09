# Gateway Competitor SDLC — Reference (TARGET_REPO)

This repo is **TARGET_REPO**. Canonical env var tables and artifact layout live in the orchestrator repo:

[`../../../../gateway-enhancement-agent/.cursor/skills/gateway-competitor-sdlc/reference.md`](../../../../gateway-enhancement-agent/.cursor/skills/gateway-competitor-sdlc/reference.md)

Implementer skill: [SKILL.md](SKILL.md) · Workspace guide: [AGENTS.md](../../AGENTS.md)

---

## Key environment variables (agent side)

Set these in **gateway-enhancement-agent** `.env` when validating this checkout:

| Variable | Purpose |
|----------|---------|
| `TARGET_REPO` | Absolute path to **this** gateway platform repo |
| `GATEWAY_PYTHON` | Optional: `backend/.venv/bin/python` for pytest gates |
| `VALIDATION_GATES_CONFIG` | Override gate list (default in agent `config/validation_gates.json`) |
| `AGENT_SKIP_TARGET_VALIDATION` | Agent self-tests only (during `run`) |
| `DELIVERY_MODE` | Agent implement profile: `full` or `tests_first` |

This repo does not define enhancement-agent env vars; do not commit agent `.env` here.

---

## Gap ID reference (agent-implemented)

| Prefix | Source | TARGET_REPO touch points |
|--------|--------|--------------------------|
| `inv-*` | `api-inventory-and-ui-map.md` | Routers, tests, UI, governance |
| `cmp-*` | Competitor capability matrix | Often governance-only; route-backed like `inv-*` Gap |
| `opt-*` | Agent optimization themes | Disabled unless agent enables `allow_optimization_themes` |
| `sec-*` | `security_audit` | Tests, risk register, optional router authz |

---

## Validation behavior (agent `gateway-agent validate`)

Two tiers:

1. Agent pytest (`gateway-enhancement-agent/tests/`)
2. Subprocess gates in this repo (see agent `config/validation_gates.json`)

### Default TARGET_REPO gates

| Gate ID | Command (from repo root) |
|---------|--------------------------|
| `frontend_syntax` | `cd frontend && node --check app.js` |
| `security_smoke` | `cd frontend && bash scripts/security_smoke.sh` |
| `control_coverage` | `cd backend && python3 scripts/check_control_coverage.py` |
| `gateway_pytest` | Focused `tests/test_gateway_*.py` subset |

### Governance-only skip

When the agent implement phase changed **only** paths under `backend/docs/governance/`:

| Gate | Result |
|------|--------|
| `gateway_pytest` | Skipped (pass) |
| `control_coverage` | Skipped (pass) |
| `frontend_syntax` | Skipped if no `frontend/` files |
| `security_smoke` | Skipped if no `frontend/` files |

If you also changed routers, tests, or UI in the same cycle, all applicable gates run.

---

## Operator smoke (this repo, manual)

After UI or gateway changes (also good pre-flight before agent validate):

```bash
node --check frontend/app.js
bash frontend/scripts/security_smoke.sh
bash frontend/scripts/console_surface_smoke.sh
```

With API running:

```bash
RUN_API_CHECKS=1 API_BASE=http://127.0.0.1:8000 bash frontend/scripts/gateway_governance_evidence_smoke.sh
```

See [frontend/README.md](../../frontend/README.md) for the full smoke list.

---

## Work order and artifact paths

| Location | Path |
|----------|------|
| Foreground agent runs | `../gateway-enhancement-agent/artifacts/cycle-XXXX/agent_work_order.md` |
| LaunchAgent runs | `~/Library/Application Support/gateway-enhancement-agent/artifacts/cycle-XXXX/` |
| Doc sync checklist | Same cycle dir: `doc_sync_checklist.md` |
| Validation report | Same cycle dir: `validation_report.md` |

After editing governance in this repo, ask the operator to run `gateway-agent sync-mirror` from the agent checkout so background cycles see fresh inventory.

---

## Troubleshooting (TARGET_REPO perspective)

| Symptom | Action |
|---------|--------|
| Agent picks wrong gap | Sync mirror; verify inventory Partial/Gap rows |
| Validate fails on doc-only PR | Ensure diff is only under `backend/docs/governance/` |
| Validate fails pytest | Read agent `validation_report.md` stderr tail; fix cited test file |
| Work order references missing route | Update inventory first — do not invent endpoints |
| cmp-* governance-only | Do not add router code without inventory entry |
| UI priority conflict | Follow [AGENTS.md](../../AGENTS.md) console order unless user names a console |

Full agent troubleshooting matrix: orchestrator [`../../../../gateway-enhancement-agent/.cursor/skills/gateway-competitor-sdlc/reference.md`](../../../../gateway-enhancement-agent/.cursor/skills/gateway-competitor-sdlc/reference.md).

---

## Cross-repo doc index

| Document | Repo |
|----------|------|
| [docs/USAGE.md](../../../../gateway-enhancement-agent/docs/USAGE.md) | Agent commands, LaunchAgent |
| [docs/DESIGN.md](../../../../gateway-enhancement-agent/docs/DESIGN.md) | Gap flow, empty inventory |
| [documentation-source-of-truth.md](../../backend/docs/governance/documentation-source-of-truth.md) | Governance hierarchy |
| [operations-quickstart.md](../../operations-quickstart.md) | Stack start + agent ops section |
