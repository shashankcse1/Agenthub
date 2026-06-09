---
description: "Implement a missing operator console from the API inventory"
agent: "agent"
argument-hint: "Console name, API prefixes, and target files"
---
Implement the selected missing operator console using the repository's API inventory and UI coverage map as the source of truth.

Use these references first:
- [backend/docs/governance/api-inventory-and-ui-map.md](../../backend/docs/governance/api-inventory-and-ui-map.md)
- [backend/docs/governance/ui-api-design-coverage-map.md](../../backend/docs/governance/ui-api-design-coverage-map.md)
- [backend/AGENTS.md](../../backend/AGENTS.md)

Requirements:
- Build a real operator workflow for the selected console; do not leave placeholder links or empty nav items.
- Match the existing control-center style in [frontend/index.html](../../frontend/index.html) and [frontend/app.js](../../frontend/app.js).
- Preserve security, audit, least-privilege, and existing role/MFA behavior.
- Update the API coverage map and frontend README when the visible UI surface changes.
- Validate the touched slice with the narrowest useful checks, then run a browser smoke test for the new console.

Expected output:
- Files changed
- UI workflow added
- API endpoints covered
- Tests and validation run
- Remaining gaps or follow-up work
