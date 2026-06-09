---
description: "Review an API domain against the current UI and report gaps"
agent: "agent"
argument-hint: "Router, module, or UI domain to review"
---
Review the selected API domain against the current frontend UI and produce a focused gap assessment.

Use these references first:
- [backend/docs/governance/api-inventory-and-ui-map.md](../../backend/docs/governance/api-inventory-and-ui-map.md)
- [backend/docs/governance/ui-api-design-coverage-map.md](../../backend/docs/governance/ui-api-design-coverage-map.md)
- [backend/AGENTS.md](../../backend/AGENTS.md)

What to check:
- Which endpoints are fully covered, partially covered, or missing in the UI.
- Whether security, audit, and role controls are reflected in the visible workflow.
- Whether the UI exposes the minimum viable operator actions for the API domain.
- Whether docs, README files, or risk registers need updates.

Expected output:
- Coverage summary
- Missing or partial UI workflows
- Risk or audit concerns
- Recommended next implementation slice
