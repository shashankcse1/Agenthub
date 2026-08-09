# Product Completion Status — AgentHub

**Date:** 2026-08-08  
**Verdict:** **Fully done for the designed product lane** (governed inference control plane).

## Design summary

AgentHub is an **inference / AI gateway control plane**: routes, budgets, virtual keys, JIT, plane isolation, prompt/MCP/RAG guards, and gateway-scoped NHI hygiene. It **coexists** with enterprise AI-identity / IGA tools via export, deny signals, and correlation — it does **not** replace them and does **not** crawl SaaS OAuth estates.

| Plane | This product | Adjacent (not this product) |
|-------|--------------|-----------------------------|
| Inference | Models, routes, VK/JIT, CPLI, LRS honesty | — |
| Gateway NHI | Agents & Access, access policies, shadow triage, intent/deny gates | — |
| Enterprise AI identity / ISPM | Optional IGA export/deny/correlation only | Full SaaS discovery / IARA into arbitrary apps |

Canonical design pointers:

- Architecture sync: [`architecture-document.md`](../../../architecture-document.md) §0  
- Identity design: [`ai-gateway-identity-security-design.md`](ai-gateway-identity-security-design.md)  
- Competitor positioning (governance only): [`enterprise-ai-identity-competitive-positioning.md`](enterprise-ai-identity-competitive-positioning.md)  
- SoT hierarchy: [`documentation-source-of-truth.md`](documentation-source-of-truth.md)

## Closed in-repo

| Area | Evidence |
|------|----------|
| Leader Readiness Score | **40/40** · `PROG-LRS-2026-08-06` · sustain `2026-08-08` |
| Engineering loops L1–L10 | `leadership-loop-state.json` all `done` |
| Core UI/API consoles | Coverage map **Full** for core operator workflows |
| NHI / Agents & Access / IGA coexistence | Gateway-plane four panels; revoke/load intent; HMAC probes; click-to-fill; **no SaaS crawler** |
| Routing polish | Route Draft recommend + status-aware actions; Canary × auto-route explain; VK auto-route policies |
| Overview leadership bootstrap | Enhance CPLI + Probe peer selects on Raise Leadership Score |
| Plane-split contract | `scripts/verify_plane_split_compose.py` + `plane-split-runbook.md` |
| SDK publish path | Dry-run CI + secrets-gated `sdk-publish.yml` |
| Auth explain what-if | Security matrix + single-action explain → coverage **Full** |

## Operator design (as shipped)

Routing & Gateway is the home for gateway NHI (four panels + HMAC probes + click-to-fill), entitlements, JIT, route drafts (status-aware + Recommend Auto-Route), canary (Explain × Auto-Route), and VK auto-route policies. Overview owns readiness chips and **Raise Leadership Score** (Enhance CPLI / Probe peer). Security owns auth explain. Naming stays gateway/IGA — never competitor product brands in the console. Plane-split and SDK publish paths are documented for ops; live deploy/publish remain org actions.

## Explicit non-goals (by design)

- Enterprise SaaS OAuth / identity crawler  
- Full IARA into arbitrary non-gateway apps  
- Competitor product name branding in the operator UI  

## Outside agent forgeability (ops / org)

These do not block “product complete”; they are deployment or org actions:

| Item | How to finish |
|------|----------------|
| Live plane-split processes | `docker compose … --profile plane-split up -d` per runbook |
| Registry publish | Add `NPM_TOKEN` / Twine secrets; run `sdk-publish.yml` |
| Distinct L6 role holders | Fill `role-holder-roster.md` with real people |
| Quarterly drills | Next window ≥ 2026-09-06 via program drill runner |

## Claims

External leadership claims remain gated by QBR `honesty.leader_claim_allowed` and must stay ≤ LRS attestation. No competitor “#1” language unless Honesty separately allows.
