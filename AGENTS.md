# Agent Delivery Guide

This repository uses an agent-first delivery model. Use this file as the workspace-wide entry point for agent work. The backend-specific role and security contract lives in [backend/AGENTS.md](backend/AGENTS.md) and remains mandatory.

## Primary Sources of Truth

- [backend/docs/governance/documentation-source-of-truth.md](backend/docs/governance/documentation-source-of-truth.md)
- [backend/docs/governance/api-inventory-and-ui-map.md](backend/docs/governance/api-inventory-and-ui-map.md)
- [backend/docs/governance/ui-api-design-coverage-map.md](backend/docs/governance/ui-api-design-coverage-map.md)
- [backend/AGENTS.md](backend/AGENTS.md)

## Current UI Priorities

Implement missing operator consoles in this order unless the user asks otherwise:

1. Playground
2. Benchmark and Scan
3. Routing and Gateway
4. Route Drafts
5. Compliance

## Expected Agent Behavior

- Build real UI flows, not placeholder links, when a backend endpoint set already exists.
- Keep each console aligned to the API inventory and coverage map before editing frontend code.
- Preserve security, audit, and least-privilege behavior from the backend contract.
- Update documentation whenever a UI gap is closed or a workflow changes.
- Validate frontend syntax, backend tests, and browser smoke paths for the touched slice.

## UI Implementation Pattern

For each new console:

- Add a visible nav entry and matching view section.
- Provide a minimal operator workflow: list, create, run, approve, or promote as the API supports.
- Surface request success and failure states in the UI.
- Keep forms and tables consistent with the existing control-center style.
- Avoid introducing duplicate console patterns when a shared control or reusable table can be extended.

## Documentation Discipline

When a workflow is added or expanded:

- Update the API inventory and UI coverage map.
- Update the frontend README if the visible operator surface changes.
- Update risk or governance docs when the change affects auth, routing, or privileged actions.

## Validation Expectations

Prefer the narrowest useful checks first:

- `python3 -m pytest` for backend changes.
- `node --check frontend/app.js` for frontend JavaScript edits.
- Browser smoke checks for the affected UI view.

