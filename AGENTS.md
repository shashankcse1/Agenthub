# Agent Delivery Guide

Human visitors and new contributors should start at the root [README.md](README.md) and [CONTRIBUTING.md](CONTRIBUTING.md). This file remains the workspace-wide entry point for **agent** delivery work. The backend-specific role and security contract lives in [backend/AGENTS.md](backend/AGENTS.md) and remains mandatory.

When implementing work orders from **gateway-enhancement-agent** (autonomous cycles or manual SDLC), read and follow **[.cursor/skills/gateway-competitor-sdlc/SKILL.md](.cursor/skills/gateway-competitor-sdlc/SKILL.md)**.

The orchestrator repo is a **sibling checkout** (not embedded here):

- Agent overview: [`../gateway-enhancement-agent/README.md`](../gateway-enhancement-agent/README.md)
- Agent operator guide: [`../gateway-enhancement-agent/docs/USAGE.md`](../gateway-enhancement-agent/docs/USAGE.md)
- Agent Cursor skill: [`../gateway-enhancement-agent/.cursor/skills/gateway-competitor-sdlc/SKILL.md`](../gateway-enhancement-agent/.cursor/skills/gateway-competitor-sdlc/SKILL.md)

Work orders land in `../gateway-enhancement-agent/artifacts/cycle-XXXX/agent_work_order.md` (or Application Support when the agent runs under LaunchAgent).

## Enhancement agent relationship

| This repo (TARGET_REPO) | gateway-enhancement-agent |
|-------------------------|---------------------------|
| Routers, tests, frontend, governance docs | Gap matrix, cycles, Ollama implement, validate subprocess |
| You implement `agent_work_order.md` here | It reads inventory and emits artifacts; optional autonomous git merge |

## Gap types (implemented in agent)

| ID prefix | Meaning | Your delivery focus |
|-----------|---------|---------------------|
| `inv-*` | API inventory Partial/Gap | Backend and/or UI + governance per coverage column |
| `cmp-*` | Competitor capability gap | Governance-only if no route; else same as `inv-*` Gap |
| `opt-*` | Optimization theme | **Not scheduled by default** in agent config |
| `sec-*` | Security audit gap | Abuse-case tests + risk register updates; review never skipped |

Agent discovers `sec-*` via `security_gap_discovery.py` and optional `security_auditor` LLM pass. Also follow [backend/AGENTS.md](backend/AGENTS.md) role lenses and agent **security guardrails + review subagents** at implement time.

After agent or manual changes, validate from the agent checkout:

```bash
cd "../gateway-enhancement-agent"
TARGET_REPO="/Users/sk/Desktop/untitled folder/new design" gateway-agent validate
```

**Governance-only** diffs (all files under `backend/docs/governance/`) skip `gateway_pytest` and `control_coverage` in agent validation; frontend gates skip when no `frontend/` files changed.

Before beginning any task, confirm that [backend/AGENTS.md](backend/AGENTS.md) and the governance documents listed under Primary Sources of Truth are present in your context. If any are missing, halt and notify the user. Do not proceed on the assumption that their contents are known.

## Primary Sources of Truth

- [backend/docs/governance/documentation-source-of-truth.md](backend/docs/governance/documentation-source-of-truth.md)
- [backend/docs/governance/api-inventory-and-ui-map.md](backend/docs/governance/api-inventory-and-ui-map.md)
- [backend/docs/governance/ui-api-design-coverage-map.md](backend/docs/governance/ui-api-design-coverage-map.md)
- [backend/docs/governance/product-completion-status.md](backend/docs/governance/product-completion-status.md) (designed-lane completion + non-goals)
- [architecture-document.md](architecture-document.md) §0 (architecture delivery sync)
- [backend/docs/governance/enterprise-ai-identity-competitive-positioning.md](backend/docs/governance/enterprise-ai-identity-competitive-positioning.md) (IGA vs inference plane; no competitor UI branding)
- [backend/AGENTS.md](backend/AGENTS.md)

## Current UI Priorities

Follow this order unless the user explicitly names a different console to work on first. A general question about a lower-priority console does not constitute a reordering request.

If the user requests a console that is not in the priority list and has no API inventory entry, do not implement it. Instead, ask the user to add it to the API inventory and governance docs first.

1. Playground
2. Benchmark and Scan
3. Routing and Gateway
4. Route Drafts
5. Compliance

## Expected Agent Behavior

- Build real UI flows when all endpoints required for the minimal operator workflow (list, create, run, approve, or promote) are present in the API inventory. If only some endpoints exist, implement only the supported operations and note the gaps in the coverage map.
- Keep each console aligned to the API inventory and coverage map before editing frontend code. If a required governance document is missing or contains no entry for the target console, halt and report the gap to the user before writing any frontend code. Do not create or populate governance documents speculatively.
- If the API inventory is stale for the target console, update it before writing any frontend code. Security contract constraints from [backend/AGENTS.md](backend/AGENTS.md) override UI convenience decisions. Documentation updates are required before marking a console complete, not optional post-steps.
- Preserve security, audit, and least-privilege behavior from the backend contract.
- Update documentation whenever a UI gap is closed or a workflow changes.
- Validate frontend syntax, backend tests, and browser smoke paths for the touched slice.

## UI Implementation Pattern

For each new console:

- Add a visible nav entry and matching view section.
- Implement only the operations that have a corresponding, non-stub endpoint in the API inventory. Do not render UI controls for operations whose endpoints are absent or marked draft.
- Surface request success and failure states in the UI.
- Keep forms and tables consistent with the existing control-center style.
- Avoid introducing duplicate console patterns when a shared control or reusable table can be extended.

## Documentation Discipline

When a workflow is added or expanded:

- Update the API inventory and UI coverage map.
- Update the frontend README if the visible operator surface changes. When in doubt about whether the operator surface changed, update the frontend README. Omitting the update requires an explicit justification comment in the PR description.
- Update `documentation-source-of-truth.md` delta register for substantial slices.
- Update `architecture-document.md` §0 when component architecture or cross-cutting operator experience changes.
- Update risk or governance docs when the change affects auth, routing, or privileged actions.

## Validation Expectations

Prefer the narrowest useful checks first:

If any validation step fails, stop further changes, report the exact failure output to the user, and do not proceed to the next console or documentation update until the failure is resolved.

- `python3 -m pytest` for backend changes.
- `node --check frontend/app.js` for frontend JavaScript edits.
- Browser smoke checks for the affected UI view.

If `python3 -m pytest` exits with a collection error or environment error rather than a test failure, report the environment issue to the user and do not treat it as a passing validation.

