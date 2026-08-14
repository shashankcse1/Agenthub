# Documentation Source of Truth

## Purpose

This document defines the canonical documentation hierarchy for implementation status, security controls, and UI/API coverage. Use it before updating frontend or backend surfaces.

## Canonical Order of Authority

1. `backend/docs/governance/documentation-source-of-truth.md` (this file): governance hierarchy and sync rules.
2. `backend/docs/governance/api-inventory-and-ui-map.md`: endpoint-level truth for route coverage status.
3. `backend/docs/governance/ui-api-design-coverage-map.md`: domain-level product intent and gap status.
4. `backend/docs/governance/ai-gateway-litellm-parity-gap-analysis.md`: LiteLLM/proxy parity gap analysis (roadmap/impact slice docs folded here; dedicated litellm-* impact files removed).
5. `backend/docs/governance/ai-gateway-market-best-practices-2026.md` (GOV-AI-MARKET-001): market best-practices checklist and posture surfaces (also listed as 14a).
6. Reserved — former LiteLLM cache/RAG/assistants impact paths removed; assistants/fine-tuning/passthrough operator notes live in inventory + coverage map + frontend README.
7. `backend/AGENTS.md`: security and role contract that implementation must preserve.
8. `backend/docs/governance/agent-delivery-checklist.md`: feature/fix-level implementation evidence template across all architecture lenses.
9. `backend/docs/security/residual-and-accepted-risk-register.md`: accepted risk and compensating controls.
10. `backend/docs/governance/security-risk-closure-plan.md`: owner-assigned closure tracker for residual risk and release-gate follow-through.
11. `backend/docs/governance/multi-lens-security-architecture-review.md`: required cross-discipline review template (Security Architect, Cloud Architect, Browser Architect, Cloud Security, AI Security, PAM, IAM Governance).
12. `frontend/README.md`: operator-facing UI capabilities and run instructions.
13. `backend/docs/governance/ai-gateway-identity-security-design.md`: AI Gateway target-state design and phased implementation plan.
14. `backend/docs/governance/ai-gateway-litellm-parity-gap-analysis.md`: competitive parity gap analysis focused on AI-gateway and LiteLLM-relevant features.
14a. `backend/docs/governance/ai-gateway-market-best-practices-2026.md` (GOV-AI-MARKET-001): 2026 market trends, buyer archetypes, best-practices checklist, and posture/fallback-suggest surface.
14b. `backend/docs/governance/enterprise-ai-identity-competitive-positioning.md` (GOV-AI-IDSEC-NHI-001…008): competitor positioning (IGA plane) vs this gateway; coexistence APIs; **operator UI must not use competitor product brands**.
14c. `backend/docs/governance/product-completion-status.md`: designed-lane completion verdict, non-goals, and ops/org residual checklist.
14d. `backend/docs/governance/plane-split-runbook.md` + `backend/scripts/verify_plane_split_compose.py`: control/data plane deploy contract.
14e. `backend/docs/governance/leader-readiness-score-current.md` + `leader-readiness-attestation.json`: LRS 40/40 attestation (Honesty gate for external claims).
15. `docs/agentic-browser-security-design-and-product-review.md`: target-state design and product landscape review for secure agentic browser operations integrated with AI Gateway.
16. `backend/docs/governance/unified-secret-provider-ciso-gap-analysis.md`: unified secret provider gap analysis, control mapping, test matrix, and CISO review checklist for Cursor credential consolidation.
17. `backend/docs/governance/generic-provider-configuration-review-and-impact-analysis.md`: **Final v1.1 (GOV-GPC-FINAL-001)** — complete classification register, cross-console UI review, consolidated gap register (GAP-GPC + GAP-USP), **full impact analysis (Part 5 §5.1–§5.17)**, multi-lens review, P1 credential bindings design, and operator reference for all cloud AI provider configuration.
18. `backend/docs/governance/flow-orchestration-notification-impact-analysis.md`: Phase 1 notification channel registry (`gateway.notification_channels_json`), Flow Orchestration `email_send`/`sms_send` nodes, CISO go/no-go for stub vs live send (GOV-FLOW-NOTIFY-001).
19. `backend/docs/governance/flow-orchestration-iga-impact-analysis.md`: Advanced IGA for orchestration (SoD, staged approval, JIT, certification, entitlement bridge, approval events, explain/posture) (GOV-FLOW-IGA-001).
20. **Enhancement agent artifacts** (sibling repo `gateway-enhancement-agent`, not committed here): cycle outputs under `artifacts/cycle-XXXX/` or Application Support — `agent_work_order.md`, `doc_sync_checklist.md`, `gap_matrix.json`. Treat work orders as **implementation prompts**, not canonical governance. Inventory and coverage maps in this repo remain authoritative.

If two docs conflict, higher-ranked docs win and lower-ranked docs must be corrected in the same change.

## Enhancement agent and doc sync

The **gateway-enhancement-agent** orchestrator reads this repo as **TARGET_REPO**. It does not replace governance docs here.

| Artifact (agent repo) | Sync expectation |
|-----------------------|------------------|
| `agent_work_order.md` | Human/agent implements in TARGET_REPO; close checklist items in same change |
| `doc_sync_checklist.md` | Must match updates to items 2–3 above when coverage or UI changes |
| `gap_matrix.json` / `cmp-*` reports | Informational; fix inventory rows (item 2) when closing a gap |
| Autonomous merge commits | Same PR rules: inventory + coverage map + frontend README when operator surface changes |

When agent or operator closes an `inv-*` or `cmp-*` gap:

1. Update `api-inventory-and-ui-map.md` coverage column (`Gap` → `Partial` / `Full`).
2. Update `ui-api-design-coverage-map.md` if UI workflow changed.
3. Update `frontend/README.md` when nav or console behavior changed.
4. Run `gateway-agent sync-mirror` from agent checkout so background cycles read fresh inventory.
5. Record substantial slices in this file's delta register below.

**Governance-only** agent changes (paths only under `backend/docs/governance/`) skip gateway pytest in agent validation — still update delta register when parity status changes.

Gap prefixes: `inv-*` (inventory), `cmp-*` (competitor), `opt-*` (optional; disabled by default), `sec-*` (security audit — abuse-case tests + residual register; review never skipped). See root `AGENTS.md` Gap types table.

Agent docs: [`../../../../gateway-enhancement-agent/docs/USAGE.md`](../../../../gateway-enhancement-agent/docs/USAGE.md) · TARGET_REPO skill: [`../../../.cursor/skills/gateway-competitor-sdlc/SKILL.md`](../../../.cursor/skills/gateway-competitor-sdlc/SKILL.md)

## Synchronization Rules

- Update endpoint inventory and domain coverage map in the same PR whenever UI workflows change.
- Complete the agent delivery checklist in the same PR whenever behavior, controls, or runtime posture changes.
- Mark status conservatively:
  - `Full`: primary operator path exists end-to-end in UI.
  - `Partial`: workflow exists but is subset/read-only or missing key actions.
  - `Gap`: no UI workflow.
- When a `Gap` moves to `Partial` or `Full`, update:
  - governance inventory,
  - coverage map,
  - frontend README surface notes,
  - security docs when privileged actions or runtime-sensitive controls change.

## Delta Register (Current)

Implemented in current state:

- Enterprise AI identity competitive positioning (GOV-AI-IDSEC-NHI-001): governance analysis in `enterprise-ai-identity-competitive-positioning.md` — IGA/ISPM as identity/NHI plane (not LLM gateway); matrix vs Astrix/Oasis/Aembit/this platform; PoC checklist; complementary stance (no `cmp-*` full-parity chase).
- NHI IGA export coexistence (GOV-AI-IDSEC-NHI-002): `POST /gateway/nhi/export` + `/gateway/nhi/iga-export/config|test-delivery`; `iga_correlation` SCIM-shaped bundle + HMAC webhook; Routing & Gateway UI; Python/JS SDK helpers; dual-approval on config/live deliver; tests `test_gateway_nhi_iga_export.py`.
- NHI IGA inbound deny gate (GOV-AI-IDSEC-NHI-003): `POST /gateway/nhi/iga-deny/ingest` (HMAC) + manual ingest/revoke/evaluate/config; modes `off|warn|block` enforced on `/v1/chat/completions` and `/v1/responses`; VK rows in NHI sync; UI + SDK; tests `test_gateway_nhi_iga_deny.py`.
- NHI Insights + lifecycle + intent-check (GOV-AI-IDSEC-NHI-004): `GET /gateway/nhi/insights|…/access-map|…/timeline`; owner/lifecycle/intents; governance intent_mode; `POST /gateway/nhi/intent-check` + optional `declared_intent` on chat/responses; MCP servers synced into NHI; Python/JS SDK helpers; tests `test_gateway_nhi_insights.py`. Anti-duplication: shared hygiene builder; VK owner/lifecycle mirrors Key Lifecycle (no sync clobber); Intent Mode ≠ IGA Deny Gate.
- NHI orphans + IGA correlation + deny events (GOV-AI-IDSEC-NHI-005): `GET/POST /gateway/nhi/orphans*`; `PUT …/correlation`; `GET /gateway/nhi/iga-deny/events`; export correlation keys; UI sub-panels; tests `test_gateway_nhi_idsec_005.py`.
- NHI evidence + correlation ingest + owner-scoped intent (GOV-AI-IDSEC-NHI-006): `POST /gateway/nhi/evidence/export`; `POST /gateway/nhi/correlation/ingest`; intent resolve without VK; tests `test_gateway_nhi_idsec_006.py`.
- Gateway-native agents/access/shadow (GOV-AI-IDSEC-NHI-007): `GET /gateway/nhi/agents`; access config/authorize; shadow-action; Discovery+Shadow sync into NHI; UI **Agents & Access** (no competitor branding); tests `test_gateway_nhi_idsec_007.py`.
- Native gate hardening (GOV-AI-IDSEC-NHI-008): private-IP SSRF guard on NHI export; IGA ingest timestamp/nonce; fail-closed unbound intent/access on inference; empty access policy deny-all in block; gate-events ring + UI; tests `test_gateway_nhi_idsec_008.py`.
- Program Leader Readiness (LRS ≥ 32 → **40/40**): Authority board `2026-08-06-AI-01`, AI-CTRL-001 + AI-RISK-001 signed, OACP freeze exercised, dated Clock/RT/Tabletop + QBR evidence, L6 Approve (Program Owner consolidated), AR-001/002 Retired, RSK-002 Mitigated; machine attestation `gateway.leadership.lrs_attestation_json` gates QBR `honesty.leader_claim_allowed`; runner `scripts/run_program_lrs_phase2_drills.py` (UTC date-aware); Phase 5 sustain 2026-08-08 + `evidence/qbr-transparency-note-2026-08-08.md`; docs `program-leader-readiness-execution.md` / `program-lrs-phase5-sustain.md`.
- Product completion (designed lane, 2026-08-08): `product-completion-status.md`; architecture §0 sync; plane-split verify + runbook; SDK publish workflow; role roster template; Auth coverage → Full; leadership-loop-state `PRODUCT_COMPLETE=done`.
- NHI UI operator closure (2026-08-08): Routing & Gateway **Revoke Deny** (`POST /gateway/nhi/iga-deny/{deny_id}/revoke`) + **Load Intent Mode** (`GET /gateway/nhi/governance/config`); Load Deny Config prefills first active deny_id.
- NHI UI deepen (2026-08-08): click-to-fill inventory/orphans/agents/deny/gate tables; **Probe HMAC Deny Ingest** + **Test Correlation Ingest**; Overview Raise Leadership Score Enhance CPLI / Probe peer options.
- Routing polish (2026-08-08): Route Draft **Recommend Auto-Route** + status-aware actions; Canary **Explain × Auto-Route**; Governance **VK Auto-Route Policies** list/upsert.
- Architecture / design documentation sync (2026-08-08): `architecture-document.md` §0 operator UX; `ai-gateway-identity-security-design.md` UI theme table; `product-completion-status.md` operator design; coverage map Route Drafts Full gap closed; residual register refreshed.
- Documentation authority repair (2026-08-08): restored LiteLLM roadmap/cache/assistants impact docs; recreated `enterprise-ai-identity-competitive-positioning.md`; SoT hierarchy wording (closed parity, not pending); aligned `sec-*` gap prefix with root `AGENTS.md`; scrubbed inventory competitor-branded operator phrasing.
- Documentation enhance pass (2026-08-08): identity design Rollout/PR blueprint + Open Decisions marked shipped/historical; inventory Auth Partial vs coverage Full clarified; Summary of Gaps rewritten for designed-lane complete; sustain/loop-state SaaS-crawler wording neutralized; `operations-quickstart.md` + architecture §0.2 `sec-*` aligned; residual register date refreshed; root `AGENTS.md` Primary Sources includes competitive positioning; SDK NHI Insights docstrings de-branded.
- Governance ID rename (2026-08-08): `GOV-AI-IDSEC-ZUMA-*` → `GOV-AI-IDSEC-NHI-*`; positioning doc → `enterprise-ai-identity-competitive-positioning.md`; module `gateway_nhi_native_access.py`; tests `test_gateway_nhi_idsec_005`…`008`.
- IGA source/target token rename (2026-08-08): API enum `saviynt_zuma` → `external_iga` (deny allowlist, export target, UI selects, defaults); legacy alias accepted and canonicalized on ingest/config normalize.
- NHI/IGA security hardening (2026-08-08, CC-043): ingest HMAC binds timestamp+nonce; prod env alias `production`; block-mode requires `declared_intent`; deny subject resolve; correlation anti-replay; export sign fail-closed; residual register + `test_gateway_nhi_security_hardening.py`.
- Security wave-2 (2026-08-08, CC-044): shared `runtime_env`; JIT/escalation/callback/vector SSRF guards; prod webhook signing force; providers/memory `production` dual-approval; directory-bound approver co-sign in prod; `test_security_hardening_wave2.py`.
- Security wave-3 (2026-08-08, CC-045): VK `vkh1` at-rest hashing + legacy migrate; rate-limit defaults merge; one-time JIT confirm nonce; route-draft/VK MFA `production` alias; `test_security_hardening_wave3.py`.
- Security wave-4 (2026-08-08, CC-046): httpOnly `gb_session` + Bearer fallback; `POST /auth/approver-session` second-session prod co-sign; console stops localStorage bearer persistence; `test_security_hardening_wave4.py`.
- Security wave-5 (2026-08-08, CC-047): CSRF double-submit (`gb_csrf`/`X-CSRF-Token`); IP-pinned outbound HTTP for webhook/probe paths; `test_security_hardening_wave5.py`.
- Local console cookie-session UX (2026-08-08, CC-046 deepen): UI `serve_static.py` same-origin API proxy (`API_UPSTREAM`); login/shell default API Base to UI origin; migrate stale `:8000` bases; idle/expired/auth-required clear markers + `login.html?reason=…`; `500.html` loopback health probe + Sign in / `./` links; `startlocal_detached.sh`; frontend README + operations-quickstart + coverage Auth notes.
- Community front door (2026-08-08): root `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, Apache-2.0 `LICENSE`, GitHub issue/PR templates — contributor onboarding without leading visitors into deep governance first.
- Community profile refresh (2026-08-08): expanded Covenant enforcement guidelines; SECURITY supported-versions + private reporting; CONTRIBUTING TOC/PR process; `.github/{SECURITY,CONTRIBUTING,CODE_OF_CONDUCT}.md` pointers; richer PR template — aligns with GitHub community health checklist.
- Community explorer pack (2026-08-09): `docs/EXPLORING.md`, `docs/GOOD_FIRST_ISSUES.md`, `docs/GLOSSARY.md`, `docs/MAINTAINER_CHECKLIST.md`, root `CHANGELOG.md`, README architecture mermaid + audience table, `scripts/seed_good_first_issues.sh`.
- Functional E2E + critical coverage (2026-08-14): console login→Overview→logout E2E; `session_cookies`/`csrf_protection`/`runtime_env` at **100%** with CI `fail_under=99`; `docs/COVERAGE.md` documents pack expansion toward broader monorepo coverage (not a false claim of whole-`app/` 99% yet).
- Gateway runtime risk (2026-08-08, GOV-GW-RISK-001 / CC-048 deepen): `gateway.runtime_risk_json` policy; `GET/PUT /gateway/runtime-risk/config` (dual-approval + MFA) + `POST /gateway/runtime-risk/evaluate`; pre-upstream enforce on chat/responses/embeddings/audio/images/rerank/messages/a2a/realtime; enriched scoring (endpoint family, agent scope, large input); prod fail-closed on corrupt config; rate limits on `/gateway/runtime-risk/*`; Policies UI; `test_gateway_runtime_risk.py`. Default disabled.
- Best-practices leadership bootstrap (GOV-AI-MARKET-001 deepen): `POST /gateway/best-practices/leadership-bootstrap` idempotently seeds ordered fallback + health-check route + cache policy; Overview **Raise Leadership Score**; `apply-ranked-fallback` writes canonical `provider_priority` (fixes posture miss). Live credential readiness still requires real env/bindings.
- CPLI + posture raise deepen: bootstrap also seeds VK/budget; default `enhance_cpli` runs reconcile+attest; inference readiness credits active secret/workload bindings (not only env keys); CPLI fail-closed awards 2/3 on combined when plane-split compose is available.
- CPLI isolation + fail-closed max: Raise Leadership Score arms `plane.fail_closed_mode=drift` + isolation contract attestation (3/3 each on combined when plane-split compose exists); data-plane compose default fail-closed=drift.
- Program leader enhance (CPLI eng band): split-ready isolation credit (plane-split compose → 2/3), fresh-reconcile active-reconcile credit, QBR `program_leadership` unified LRS+CPLI block, Overview LRS/Unified chips, `scripts/run_program_leader_enhance.py` + transparency QBR note; CPLI reaches **leader_ready_engineering** (≥16) after reconcile on combined plane.
- Leadership quality harden: LRS attestation normalize/clamp + future-date reject; outside-pytest hydrate from governance file when runtime_config cleared; shared `build_program_leadership_summary`; Cost/Overview shared chip renderer with tone + tooltips; drill form UTC default/max + future-date guard; CPLI dimension row null-safety.
- Gateway JIT short-lived credentials (GOV-JIT-VK-001): `POST /gateway/jit-requests` accepts `owner_scope_type`/`owner_scope_id`/`mint_virtual_key`; approve mints an expiring `VirtualKey` linked via `jit_request_id`, returns one-time `issued_virtual_key_token`, audits `gateway.jit.virtual_key.mint` / `.revoke`, and auto-blocks on expiry during inference; **list/get/revoke/expire-tick** APIs + JIT Request Queue UI; Routing & Gateway JIT UI + Key Lifecycle JIT column; Python/JS SDK mint/owner/list/revoke/expire helpers; tests in `test_phase0_phase1.py` (mint, skip, deny, bearer inference, revoke, expire-tick).
- Gateway JIT email + external REST decisions (GOV-JIT-NOTIFY-001): runtime `gateway.jit.decision_notify_json`; `GET/PUT /gateway/jit-decision-notify/config` (dual-approval save); create/notify sends reviewer emails with HMAC-signed approve/deny links (`GET|POST /gateway/jit-actions/{token}`, no session) and POSTs to selected external callbacks and/or custom `external_rest_url` (+ optional credential binding); prod email approve gated by `allow_prod_email_approve` (default false); Access Reviews & JIT **Email & External REST Decisions** UI + queue **Notify**; tests for config dual-approval, email approve/deny, prod gate, replay 409.
- Gateway JIT decision notify deepen (GOV-JIT-NOTIFY-002): webhook HMAC (`X-Gateway-Jit-Signature`), jti replay store (`gateway.jit.action_jti_used_json`), hide VK on email action by default + optional email to `decision_recipient_emails`, `POST .../test-delivery`, `POST .../preview-action-links`, notify-on-decide, include action links in webhooks option, JS/Python SDK helpers, UI Test Delivery + Preview Links.
- Gateway JIT email action confirm (GOV-JIT-NOTIFY-003): GET `/gateway/jit-actions/{token}` is confirm-only (anti email-scanner prefetch); POST requires `confirm` + HMAC `confirm_nonce` (+ optional decision reason); `last_notify` summary persisted on JIT rows and shown in queue; rate limits on action routes.
- Gateway JIT notify history/reminder/retry (GOV-JIT-NOTIFY-004): `notify_history_json` + `GET .../notify-history`; notify cooldown (`min_notify_interval_minutes`, 429 `JIT_NOTIFY_COOLDOWN`, `force=true`); reminder events (`reminder=true` → `gateway.jit.request.reminder`); `POST .../notify-retry` for failed webhooks; delivery ids + `X-Gateway-Delivery-Id`/`Idempotency-Key`; compact webhook payload style; queue Remind/History/Retry Hooks + SDK helpers.
- Gateway JIT notify SLA tick + escalation (GOV-JIT-NOTIFY-005): config `auto_reminder_after_minutes` / `escalate_after_minutes` / `escalation_reviewer_emails` / `max_auto_reminders` / `auto_retry_failed_webhooks_on_tick`; `POST /gateway/jit-requests/notify-tick`; `GET /gateway/jit-decision-notify/pending-summary`; manual `escalate=true` notify; queue Notify Tick / Pending Summary / Escalate.
- Providers trending AI pack (GOV-AI-TREND-001): gateway OpenAI-compatible invoke now includes Google Gemini, xAI, DeepSeek, Together, Fireworks, Perplexity (plus existing OpenAI/Anthropic/Groq/Mistral/Cohere/Azure/Cursor); model-id inference for `gemini-*` / `grok-*` / `deepseek-*` / `sonar*`; `POST /providers/models/seed-trending` + Providers Models **Seed trending models**; DeepSeek + `azure-openai` provider ids in UI. Residual: AWS Bedrock remains catalog/credential-oriented (not OpenAI-compat invoke without a custom base URL).
- Providers cloud hyperscaler packs (GOV-AI-CLOUD-001): expanded seed packs for **AWS Bedrock**, **Azure OpenAI/Foundry**, and **GCP Gemini + Vertex** (`packs=bedrock|azure|gcp|all`); Bedrock chat via boto3 `converse`; Azure classic deployment URLs + api-version; Vertex OpenAI-compat base from `VERTEX_PROJECT`/`VERTEX_LOCATION`; Providers UI seed buttons per pack. Residual: private fine-tunes / unpublished regional SKUs still require manual catalog rows; Bedrock image/embedding-only IDs are cataloged but chat-oriented.
- Providers live cloud model sync (GOV-AI-CLOUD-002): `POST /providers/models/discover-cloud` + `POST /providers/models/sync-cloud` list/upsert live Bedrock foundation+inference-profile IDs, Azure deployments, Gemini API models, and Vertex publisher models; Bedrock Titan/Cohere embeddings via `invoke_model`; Azure embeddings deployment URL support; Providers UI Discover/Sync actions. Residual: discover needs cloud credentials in the API runtime env; targets without creds return per-target errors without failing the whole request.
- Providers inference readiness (GOV-AI-READY-001): `GET /providers/models/inference-readiness` scorecard (catalog counts + live/env/endpoint readiness); Playground credential banner uses selected-model provider inference; Providers Models tab readiness table; gateway model dropdowns grouped by provider optgroup. Residual: readiness reflects runtime env/default-chain signals, not every tenant binding.
- Playground / Gateway ops model UX (GOV-AI-READY-002): provider filter selects + chips, prefer-live-ready ranking, live/needs-creds option labels, Gateway Ops readiness strip, expanded cloud secret-path templates. Residual: filter is client-side over the platform available-models register.
- AI gateway market best practices (GOV-AI-MARKET-001): competitive/best-practices analysis in `ai-gateway-market-best-practices-2026.md`; `GET /gateway/best-practices/posture` weighted scorecard; `POST /gateway/best-practices/fallback-suggest` readiness-aware multi-provider chain; Routing & Gateway Route Priority posture strip + **Suggest Live-Ready Chain**. Residual: classifier auto-router and deeper intended→actual model attribution remain optimization tracks.
- AI gateway auto-router + model attribution (GOV-AI-MARKET-002): heuristic complexity auto-router (`POST /gateway/best-practices/auto-route`); chat `model=auto` / `auto_route=true` with `intended_model`/`actual_model`/`model_switched` (+ auto_route tier metadata); execute-fallback intended→actual fields; Routing & Gateway auto-router preview + chat checkbox. Residual: heuristic classifier only; long-window attribution analytics still expandable.
- AI gateway leadership index (GOV-AI-MARKET-003): `GET /gateway/best-practices/leadership-index` + `GET /gateway/best-practices/attribution-analytics`; CostEvent attribution persistence; auto-router `strategy=cost|quality|balanced` + richer signals; Routing & Gateway leadership/attribution strips. Residual: LLM-judge classifier and Helicone-class SDK auto-instrumentation remain optional expansions.
- AI gateway leadership ops pack (GOV-AI-MARKET-005): strategy compare, batch classify, savings estimate, circuit-breaker recommendations, ranked fallback suggest, SDK presets, evidence export, snapshot/history/alerts, exclude-warmup analytics, Playground auto-route, rankings/attribution JSON download.
- AI gateway leadership Pack 10 (GOV-AI-MARKET-010): allowlisted alert delivery, traffic-light/healthz, adversarial+PII enforcement in auto-route, runtime judge/ranking weights, mutate ranked fallback apply, warmup rate-limit, SLA burn-rate, chaos cleanup, evidence diff, OpenAPI fragment, scorecard digest, credential warnings, strategy resolve, sim judge transcript, ops activity timeline.
- AI gateway leadership Pack 11 (GOV-AI-MARKET-011): decision-cache + strategy-policy resolve on auto-route/chat/Responses; enforcement flags; model allow/deny; dashboard summary/sparkline/runbook; alert retries; failover verify; latency histogram; history archive; budget↔auto-route correlation; canary promote gate; weekly ops report; circuit-breaker annotate; Playground traffic-light; Route Priority apply-ranked-fallback.
- AI gateway leadership Pack 12 (GOV-AI-MARKET-012): decision-cache invalidate/stats; alert retry enqueue on failed delivery; model-policy + alert-retry + history-archive ops UI; empty-catalog denylist reason; traffic-light floors; readiness Δ; budget warn; canary+annotate combo; posture digest; dashboard strip auto-load; runbook markdown download.
- AI gateway leadership Pack 13 (GOV-AI-MARKET-013): auto-route explain + strategy shadow compare; score-trend decline alert; model-policy reset/clear-denylist; posture export; multi-window summary; route health; operator checklist; latency estimate; pack registry; on-demand snapshot; flags diff; warmup eligibility; strategy policy list; Overview posture chip; Playground auto-route meta; structured 422 when policy empties catalog.
- AI gateway leadership Pack 14 (GOV-AI-MARKET-014): auto-route decision audit trail; leadership incidents open/close; floor gate; pack-registry markdown; cost estimate; provider diversity; score-trend mute; flags rollback; route-health batch; day rollup; checklist gate; cache inventory; nightly+trend report; chat/Responses explain_snippet meta; Playground RED warn; Overview trend chip.
- AI gateway leadership Pack 15 (GOV-AI-MARKET-015): composite go/no-go; unmute trend; audit summary/purge/export; incident escalate/bulk-close; floor-gate auto-incident; RED probe; preferred-model soft bias; day-rollup markdown; strategy policy delete; digest webhook dry-run; Routing health banner; Benchmark floor/composite gates.
- AI gateway leadership Pack 16 (GOV-AI-MARKET-016): executive brief + scorecard delta; shadow traffic controller + soft decision metadata; canary auto-rollback; attribution anomalies; warmup/latency budgets; Pareto frontier; failover simulation; model-card freshness; composite+evidence; incident timeline MD; ops activity export; cross-env sync dry-run; Overview go/no-go chips; Playground diagnose; Pack 16 ops strip.
- AI gateway leadership Packs 8–9 (GOV-AI-MARKET-008/009): deprecation/shadow/PII/residency/cost-correlation, why-model card, replay/CSV, nightly snapshot, warmup retention/purge, ranking/judge config, route/tag strategies, owner/tenant rankings, model cards, outage overlay, ranking apply proposals, snapshot diff, signed evidence, auditor share links, browser extension preset, CI/release gates, chaos drill, board one-pager, competitive scorecard refresh.
- AI gateway leadership Pack 7 (GOV-AI-MARKET-007): prompt/VK auto-route policies, route-draft recommend, canary/mirror/cache metrics, team leaderboards, env-diff score, prod dual-approval warmup, alert channels/dispatch, QBR/compliance embeds, SDK auto-route helpers, OTel attributes, Prometheus/Grafana/Datadog exports.
- AI gateway leadership Pack 6 (GOV-AI-MARKET-006): gated live-judge refine, OpenRouter liquidity import, binding readiness inventory, attribution timeseries, auto-route A/B experiments, fallback quality gate, provider health scores, budget/latency/region/tool/multimodal explain, stream frames, Responses API auto-route parity, modality advisors.
- AI gateway leadership feedback loop (GOV-AI-MARKET-004): telemetry `GET /gateway/best-practices/model-rankings` steers auto-route; heuristic judge refine; `POST /gateway/best-practices/leadership-warmup`; chat Helicone session/user/properties fields; leadership index includes ranking component. Residual: live LLM judge and external marketplace liquidity import remain optional.
- Prompt-injection mediation (GOV-PI-001 / GOV-PI-002): heuristic detector (`backend/app/services/prompt_injection_guard.py`) with classic + indirect/tool-exfil patterns; route `prompt_injection_mode` on input-data-policy; platform default `gateway.prompt_injection.default_mode=warn`; live enforcement on `/v1/chat/completions` and `/v1/responses` before entitlement; **RAG ingest/query**, **MCP tool arguments**, and **gateway memory create** screened via shared `evaluate_prompt_injection_text`; retrieved RAG/memory warn hits wrapped as `<<UNTRUSTED_RETRIEVED_CONTENT>>`; Playground/Gateway UI surfaces `content_guard_*`; audits `gateway.prompt_injection.enforce`; tests in `backend/tests/test_prompt_injection_guard.py`. Residual: heuristics are not ML classifiers; novel paraphrases and multi-hop indirect injection remain accepted-bounded.
- Frontend typography system (GOV-UI-TYPE-001): canonical stacks and modular rem scale in `frontend/fonts.css`; role mapping in `frontend/styles/type-system.css`; login/404/500 aligned to the same tokens; body default 16px; display/body/mono faces self-hosted with `font-display: swap`; spacing rhythm tokens; view-loader skeleton + retry on console fetch failure; nav/tabs consistency in `frontend/styles/nav-tabs.css` (keyboard menus, unified tab chrome, pin/recent strips, redundant gap removal); overall console page polish in `frontend/styles/pages.css` including keyboard shortcuts, go-chords, recent-console search, shell progress, offline banner, silent view prefetch, governed confirm dialog, session-persisted console tabs, copyable operator results, and progressive disclosure (`operator-guide`) with shortened hero copy on Playground, Benchmark & Scan, Routing & Gateway, Flow Studio, and Compliance.
- Control / data plane isolation foundation: `APP_PLANE=all|control|data` path middleware (`PLANE_ROUTE_REJECTED`), control schedulers gated to control/combined, `GET /health.plane`, `GET /platform/control-plane` with on-plane coverage, Overview Control Plane card, and docker-compose profile `plane-split` (`api-control` / `api-gateway`).
- Control plane reconcile deepen: policy-generation fingerprint (routes/keys/cache), peer probe via `DATA_PLANE_PEER_URL` / `CONTROL_PLANE_PEER_URL`, drift_status on posture, throttled audit `platform.plane.route_rejected`, UI dual base (`gatewayApiBase` + Plane Split profile).
- Control plane active reconcile: `POST /platform/control-plane/reconcile`, `GET /platform/control-plane/drift-events`, background `PLANE_DRIFT_WATCHER_*`, optional `PLANE_FAIL_CLOSED_MODE` inference gate (503 `PLANE_FAIL_CLOSED`), QBR `plane_isolation`, Overview Force Reconcile + drift table.
- Control plane L3 deepen: durable `plane_drift_events` table, hot policy publish (`plane.policy_generation_json` + optional Redis), generation fencing / published_mismatch, plane SLO scorecard on posture (peer latency, generation freshness, on-plane %).
- Control Plane Leadership Index (CPLI): leadership scorecard/attest/verify; release-gate evaluate + history + CI go/no-go; **promotion readiness** (gate streak via `PLANE_RELEASE_GATE_STREAK_REQUIRED`); signed evidence pack GET/POST mint; reconcile ceremony; ops banner via `GET /platform/operational-status.control_plane`; Overview promotion chips + Mint Evidence Pack; Cost QBR promotion chip; marketing claims remain Honesty-gated.
- Control-plane best-practice contract (`plane-contract-v2`): desired vs observed, last-known-good, liveness (`/live`) vs readiness (`/ready`), env + audited runtime freeze (`POST .../freeze`), LKG rollback (`POST .../rollback-lkg`), peer ack (explicit; `acked` no longer aliases generation sync), snapshot export/mint/**apply**, Overview Freeze/Unfreeze/Rollback/Ack/Apply Snapshot.
- Route Drafts: submit/approve/reject/approve-change-window/promote/rollback actions are now exposed in Routing & Gateway.
- Gateway cache policies now expose exact/semantic mode and similarity-threshold controls in Routing & Gateway, with stats/health surfacing semantic-policy coverage.
- Providers: workload identity token exchange, trust validation with evidence drilldown, workload/secret health checks, secret lease renewal and inventory, and rotate-via-secret-provider key action are now exposed in Providers.
- Security: role-binding validation and explainability workflows are now exposed in Security.
- Modules: register/list/versions, agent validate/upgrade-plan, and deprecate workflows are now exposed in Modules.
- Agentic: readiness report, contract validation, certification run/list/latest/override/export, load-test run/latest, checkpoint create/list/resume, policy auto-tune/scheduled-optimize, and policy schedule create/list/summary/detail/update/status/approve/execute/history/enable/disable/delete workflows are now exposed in Agentic.
- Observability: trace lookup, deep log filtering/search, redact mode, schema health checks, and log-to-trace drilldown actions are now exposed in Observability.
- Routing & Gateway: route provider-priority timeline history is now exposed with limit/offset timeline controls and audit-backed events.
- Routing & Gateway: Route Priority and route create workflows now include a visual fallback-chain builder (ordered provider+model rows with up/down reorder, provider/model datalists, and backend schema validation) in addition to advanced JSON editing.
- Routing & Gateway: Memory & Context tab now exposes `/gateway/memory/*` overview and record CRUD workflows with short-term TTL, per-scope limits, 16 KiB content cap, Agent Owner scoping, and production long-term dual-approval on create/delete.
- Routing & Gateway: Memory & Context **Platform Configuration** tunes memory, semantic cache defaults, vector store registry (`/gateway/memory/config`, `gateway.vector_stores_json`) with secret-ref integration via Providers; **inference cache short-circuit** via `gateway.cache.inference_short_circuit_enabled` (default off, encrypted response store, dual-approval to enable in prod); **RAG data plane** via `POST /rag/ingest`, `POST /rag/query`, OpenAI-compatible `GET /v1/vector_stores*` (MCP bridge v1); **live probe** `gateway.vector_stores.live_probe_enabled`; **PII classification** `gateway.memory.pii_classification_enabled` (default off); impact analysis in `memory-context-vector-impact-analysis.md`, `litellm-cache-parity-impact-analysis.md`, and `litellm-rag-parity-impact-analysis.md`.
- Routing & Gateway: MCP server registry, tool list, and governed tool call workflows are now exposed in the console.
- Cost: budget policy lifecycle create/list/edit/delete workflows are now exposed in Cost.
- Cost: fine-grain hierarchy spend with closed-loop remediation — budget list/env hours/`soft_alert_active`/`temporary_increase_active`; one-click temp increase/clear + soft-alert acknowledge (suppresses soft anomalies for the budget window); policy/limits evaluate with environment + hours; anomalies include decision/hours and Evaluate/Temp+/Ack actions; Overview/Hierarchy/Budget tables share Edit+remediation handoffs that preserve environment.
- Routing & Gateway: gateway-governance PR-1 through PR-4 slices are now implemented (entitlements, NHI inventory/hygiene, access reviews + JIT, and least-privilege recommendations) with synchronized API/UI/docs coverage.
- Routing & Gateway: least-privilege recommendation apply flow now requires operator decision rationale in UI for stronger CISO/IAM evidence hygiene.
- Routing & Gateway: gateway governance evidence aggregation/export workflow is now exposed via `POST /gateway/governance/evidence/export`, producing filtered JSON bundles and action-level summaries for security/CISO review.
- Routing & Gateway: cache decision timeline readback is now exposed via `GET /gateway/cache/decisions` with trace/tenant/decision filters plus hit/miss/bypass explanation, semantic similarity score, request fingerprints, and source-request provenance details in the cache management console.
- Browser Security: GuardBridge console and `/browser/*` governance API surface are now exposed end-to-end, including sessions/events ingest and review, shadow AI inventory triage, risk policy CRUD, analytics breakdown, and incident evidence export with privacy-safe telemetry constraints.
- Routing & Gateway: OpenAI-compatible chat baseline endpoint is now exposed via `POST /v1/chat/completions` with role-gated and audit-backed behavior.
- Routing & Gateway: OpenAI-compatible embeddings baseline endpoint is now exposed via `POST /v1/embeddings` with role-gated and audit-backed behavior.
- Routing & Gateway: OpenAI-compatible responses baseline endpoint is now exposed via `POST /v1/responses` with role-gated and audit-backed behavior.
- Routing & Gateway: OpenAI-compatible responses lifecycle baseline now includes `GET /v1/responses`, `GET /v1/responses/{response_id}`, and `DELETE /v1/responses/{response_id}` with role-gated read, owner-or-admin delete semantics, and production dual-approval guardrails.
- Routing & Gateway: OpenAI-compatible files metadata baseline now includes `POST /v1/files`, `GET /v1/files`, `GET /v1/files/{file_id}`, and `DELETE /v1/files/{file_id}` with role-gated lifecycle behavior, owner-or-admin delete semantics, and production dual-approval guardrails.
- Routing & Gateway: dedicated OpenAI-Compatible Gateway Ops UI workflows are now exposed for `/v1/chat/completions`, `/v1/responses*`, and `/v1/files*`, with operator controls for lifecycle read/delete and optional production dual-approval headers; smoke coverage now includes `frontend/scripts/openai_gateway_ops_smoke.sh`.
- Routing & Gateway: explicit decision-trace evidence retrieval workflow is now exposed via `GET /gateway/decision-traces/{trace_id}` in Gateway Controls for audit/logging investigations.
- Routing & Gateway: OpenAI-compatible create responses now include risk-adaptive metadata (`risk_tier`, `risk_reasons`) for operator, AI-architect, and CISO posture review.
- Playground: prompt registry promotion governance endpoint is now exposed via `POST /playground/prompts/{prompt_registry_id}/promote`, with template render-preview validation and production dual-approval enforcement for release approvals.
- Playground: quality triage queue workflow is now exposed via `GET /playground/quality/triage`, enabling operator filtering and priority tagging for low-rating/low-quality feedback investigations.
- Playground: quality escalation lifecycle is now exposed via `POST /playground/quality/triage/{feedback_id}/escalate`, `GET /playground/quality/triage/escalations`, and escalation acknowledge/resolve actions with SLA tracking for trust-ops incident handling.
- Playground: quality escalation notifications are now exposed via `POST /playground/quality/triage/escalations/{escalation_id}/notify` with channel/destination metadata and audit-backed communication traceability.
- Playground: long-window quality analytics rollups are now exposed via `GET /playground/quality/analytics/rollups` with provider/route/model dimensional bucket views for trend analysis.
- Providers: supported-model catalog now includes explainability metadata (`recommendation_rationale`), explicit approval/rejection workflow (`POST /providers/models/{supported_model_id}/approve`), and metadata version progression for operator and security review traceability.
- Platform model availability: canonical UI register (`GET /providers/models/available`) unifies all operator model dropdowns; governed by `platform.ui_models.catalog_statuses`, `platform.ui_models.require_approval`, and `platform.ui_models.enforce_tenant_entitlements`. Impact analysis: `backend/docs/governance/model-availability-ui-impact-analysis.md` (GOV-MODEL-AVAIL-001).
- Routing & Gateway: external callback workflows now include sink-specific routing and correlation presets (`sink_type`, `sink_route_key`, `correlation_preset`) across create/update/test/export paths, with correlation-context preview and distribution metadata for CISO/audit evidence review.
- Routing & Gateway: realtime/media transport governance is now hardened with inline-binary stream policy controls (`stream_inline_max_event_bytes`, `stream_inline_allowed_event_types`, `stream_inline_require_correlation_id`) enforced during session event ingest in addition to existing prod dual-approval checks.
- OpenAPI/Swagger: high-risk mutation endpoints now include explicit summaries, governance-aware descriptions, and error response contracts across Auth, Gateway, and Providers (break-glass enable/disable, key block/unblock/rotate paths, route optimize/execute-fallback, cache invalidation, transform-request debug, authz explain, workload trust/test, and secret provider test/lease renew).
- OpenAPI/Swagger: **Platform** tag documents operational posture and operator feedback persistence (`POST /platform/feedback` → `operator_feedback`, audit `platform.feedback.*`) with request/response schemas and 403/404/422 contracts. **Governance** tag documents UI coverage gap inventory endpoints. Regenerate via `GET /openapi.json` or `/docs`.
- OpenAPI/Swagger: provider onboarding and gateway governance operations now also include explicit endpoint contracts (basic-auth config create, tenant catalog create/update, workload identity provider create, secret provider create, db secret value upsert/read/delete, gateway cursor secret binding, route create/provider-priority update, cache policy create, external callback create/test/export, and governance evidence export).
- Consolidated evidence artifact captured in `backend/docs/governance/agent-delivery-checklist-openai-gateway-consolidated.md` with role-lens validation, security checks, and regression outcomes.
- Discovery: dashboard posture and triage surface now includes healthy/stale source posture metrics, unified triage aggregation (conflicts/alerts/promote queue), and operator filter controls (`type`, `urgency`, `search`) with existing resolve/promote action paths.
- Discovery: source catalog includes 49 agent-scoped sources (platform internals plus well-known AI providers, dev platforms, cloud AI/infra across AWS/Azure/GCP/Oracle/CoreWeave, and agent-ops integrations). UI provides quick-connect presets (46 sources), live connection CRUD with edit/update, per-source and per-connection sync, cross-source duplicate triage with merge/dismiss workflows, and discovered-agent linkage via `promoted_to_agent_id`.
- Modules: AI Skills Registry is now exposed in Modules via `GET /modules/skills`, with skill inventory filtered to `ai_skill`/`skill` module types and operator UI readback.
- Modules: integration metadata and sync controls are now exposed for module inventory (`integration_provider`, `integration_reference`, `integration_sync_status`, `integration_last_synced_at`) with governed sync action via `POST /modules/{module_id}/integration/sync`.
- Routing & Gateway: baseline system-level instruction controls and scoped system-rules registry are now exposed via `GET/PUT /gateway/system-instructions` and `GET/PUT /gateway/system-rules`, with runtime application to OpenAI-compatible responses and scope classification aligned to existing owner/budget scope types plus agent scope.
- Providers: unified secret provider model now includes `db` provider type with encrypted value storage (`PUT/GET/DELETE /secrets/providers/{provider_id}/values*`), gateway cursor secret binding (`GET/PUT/DELETE /gateway/cursor-secret-binding`), and CISO gap analysis in `backend/docs/governance/unified-secret-provider-ciso-gap-analysis.md`. Legacy `/gateway/cursor-token` is deprecated.
- Governance: API UI coverage gap reporting is now exposed via `GET /governance/ui-coverage` and machine-readable inventory via `GET /governance/ui-coverage/inventory`, with Overview and Compliance operator surfaces plus frontend `Gap` endpoint gating.
- Frontend component modules: shared constants (`js/constants.js`), API client headers (`js/api-client.js`), boot-time GET dedupe (`js/api-cache.js`), and UI coverage component (`js/ui-coverage.js`) extracted from `app.js` with script load order before the main bundle.
- Platform operator experience: maintenance/downtime/slow-performance banners (`js/platform-status.js`), operator feedback persisted in PostgreSQL table `operator_feedback` via `POST /platform/feedback` (audited `platform.feedback.create`), analytics/triage via `/platform/feedback*`.
- Health: `GET /health` now exposes non-secret `runtime_config_cache` posture (`status`, `ttl_seconds`, `last_refresh`, backend mode, degraded flag) for cloud-operator diagnostics.
- Discovery UX: horizontal-scroll topology map, Agent Ops & Trace Sources card, functional agent-ops labels, Observability pivot from Discovery.
- Backend domain layer: `backend/app/domain_constants.py` for code defaults; `backend/app/services/platform_operational.py` for operational posture and feedback analytics; observability summary SQL aggregates in `backend/app/services/observability_summary.py`.
- Flow Orchestration: n8n-compatible flow definitions (`/orchestration/flows*`), node-type catalog, schema/security validation, prod dual-approval promotion, stub executor with run history, HTTP allowlist via `orchestration.http_allowed_hosts_json`, **email/SMS notification nodes** (`email_send`, `sms_send`) with channel registry (`gateway.notification_channels_json`, `GET /gateway/notification-channels*`), and operator console with step/chain builder (visual canvas Phase 2). Impact analysis: `flow-orchestration-impact-analysis.md` (GOV-FLOW-ORCH-001), `flow-orchestration-notification-impact-analysis.md` (GOV-FLOW-NOTIFY-001).
- **Assistants / fine-tuning / passthrough parity** (GOV-LITELLM-ASSISTANTS-001): OpenAI-compatible `/v1/assistants*`, `/v1/threads*`, `/v1/fine_tuning/jobs*`, and `POST /v1/passthrough` with owner scoping, prod dual-approval on delete/cancel/passthrough, path allowlist, CP-REF header sanitization, deny-path audit on authz failures, and `environment` on assistant/fine-tuning responses. Routing & Gateway Workspace cards: create/list/retrieve/delete assistants, thread/message/run workflow, fine-tuning create/list/retrieve/cancel, passthrough test with optional headers JSON. Auth explain: Security `POST /auth/authz/explain` (MFA); Gateway authz explain presets for `gateway.assistants.delete`, `gateway.fine_tuning.cancel`, `gateway.passthrough.execute`. Playground: `GET /playground/runs/{run_id}/detail` drill-down tabs. Compliance: `POST /compliance/evidence/export` with `investigation_context` embed and deny audit on missing control (no silent client fallback). Tests: `test_gateway_assistants.py`, `test_gateway_fine_tuning.py`, `test_gateway_passthrough.py`, `test_playground_run_detail.py`, `test_compliance_evidence_export.py` (29 cases). Impact analysis: `litellm-assistants-parity-impact-analysis.md`.

Remaining documented deltas:

1. Remote secret-provider key rotation execution (`POST /keys/{key_id}/rotate-via-secret-provider`) remains audit-delegated without full backend adapter execution.
2. Legacy `/gateway/cursor-token` API removal scheduled after operator migration window (see GAP-USP-R03 in unified secret provider CISO gap analysis).
3. Vector/RAG data plane Phase 4 implemented per `memory-context-vector-impact-analysis.md`, `litellm-rag-parity-impact-analysis.md`, and `litellm-cache-parity-impact-analysis.md` (MCP-first `/rag/*`, live probe flag, PII classification hook default off).
4. Assistants parity residual: live fine-tuning upstream wired (`gateway.fine_tuning.live_enabled`, default off — simulated completion when false; live OpenAI job create/sync/cancel when true). **Closed:** streaming assistant runs; thread/run retrieve UI; SIEM rules UI + dispatch (RSK-ASSIST-05); deferred console surfaces (cost timeseries Telemetry panel, orchestration test-query UI, console surface smoke) — see `deferred-console-parity-completion-plan.md`.

## REST API Observability Standards

All REST routers use shared helpers in `backend/app/api_errors.py` for operator-facing failures:

- `error_code`, `message`, `policy_version`, and `decision_trace_id` are required on structured errors.
- `AUTHZ_SCOPE_FORBIDDEN`, `RESOURCE_NOT_FOUND`, `VALIDATION_ERROR`, `RESOURCE_CONFLICT`, `AUTHN_INVALID_CREDENTIALS`, and `UPSTREAM_PROVIDER_ERROR` are the canonical codes.
- Request middleware in `backend/app/main.py` emits trace/info/error logs for every HTTP request.
- Mutating privileged flows must emit allow/deny audit evidence via `create_audit_event()` at request time when the decision is made (benchmark/scan cancel, agentic policy auto-tune apply, browser security mutations, platform feedback create/triage, **gateway assistant delete / fine-tuning cancel / passthrough execute dual-approval and scope denials**, **compliance evidence export missing-control deny**, and similar).

**Gateway Assistants / fine-tuning / passthrough — persistence and audit**

| Operation | API | Database | Audit `action_type` | Deny audit |
|---|---|---|---|---|
| Create assistant | `POST /v1/assistants` | `gateway_assistant_records` | `gateway.assistants.create` | — |
| Delete assistant | `DELETE /v1/assistants/{id}` | soft-delete status | `gateway.assistants.delete` | prod dual-approval + owner scope → `deny` |
| Thread message | `POST /v1/threads/{id}/messages` | `gateway_assistant_thread_message_records` | `gateway.threads.messages.create` | — |
| Thread run | `POST /v1/threads/{id}/runs` | `gateway_assistant_thread_run_records` | (via inference audit path) | 422 if no user message |
| Fine-tune cancel | `POST /v1/fine_tuning/jobs/{id}/cancel` | status → cancelled | `gateway.fine_tuning.cancel` | prod dual-approval + owner scope → `deny` |
| Passthrough | `POST /v1/passthrough` | none (proxy) | `gateway.passthrough.execute` | allowlist/scope/dual-approval → `deny` |
| Compliance export | `POST /compliance/evidence/export` | bundle read | `compliance.evidence.export` | missing control / bundle error → `deny` |

Models: `GatewayAssistant*`, `GatewayFineTuningJobRecord` in `backend/app/models.py`. Services: `gateway_assistants.py`, `gateway_fine_tuning.py`, `gateway_passthrough.py`. Schema bootstrap: `_upgrade_gateway_assistants_schema()` in `backend/app/main.py`.

**Platform operator feedback — persistence and audit (verified)**

| Operation | API | Database | Audit `action_type` |
|---|---|---|---|
| Submit feedback | `POST /platform/feedback` | Insert into `operator_feedback` | `platform.feedback.create` |
| Triage feedback | `POST /platform/feedback/{feedback_id}/actions` | Update `status`, `acted_by`, `acted_at`, `action_note` on `operator_feedback` | `platform.feedback.acknowledge`, `.resolve`, `.dismiss`, `.escalate` |
| List / analytics | `GET /platform/feedback`, `GET /platform/feedback/analytics` | Read-only SQL on `operator_feedback` | None (info logs only) |

Model: `OperatorFeedback` in `backend/app/models.py`. Schema bootstrap: `_upgrade_operator_feedback_schema()` in `backend/app/main.py`.

**Playground run feedback — persistence and audit (separate table)**

| Operation | API | Database | Audit `action_type` |
|---|---|---|---|
| Submit/update | `POST /playground/runs/{run_id}/feedback` | Upsert `playground_run_feedback` | `playground.run.feedback.create` / `.update` |
| List | `GET /playground/runs/{run_id}/feedback` | Read-only | None |

Intentional no-audit read/compute endpoints (non-mutating, no privileged decision):

- `GET /cost/pricing/calculate` — deterministic pricing math preview.
- `POST /discovery/connections/{connection_id}/test` — connectivity probe; failures are logged, not audited.
- `GET /observability/*` — diagnostic readback over existing audit/log data.
- `GET /governance/ui-coverage` and `GET /governance/ui-coverage/inventory` — read-only governance gap reports for CISO/compliance dashboards; structured info logs only (`governance_ui_coverage_*`), no audit spam.
- `GET /platform/operational-status` — read-only posture for maintenance/slow thresholds; no audit (banner driver only).
- `GET /platform/control-plane` — read-only plane isolation + on-plane coverage; structured info logs (`platform_control_plane_posture_served`).
- `POST /platform/control-plane/reconcile` — audited force reconcile (`platform.plane.reconcile`).
- `GET /platform/control-plane/drift-events` — read-only drift history; structured info logs (`platform_control_plane_drift_events_served`).
- `GET /platform/control-plane/contract` — versioned capabilities (`plane-contract-v2`); no audit.
- `GET /platform/control-plane/ready` — readiness probe (HTTP 503 when not ready); no audit.
- `GET /platform/control-plane/live` — unauthenticated liveness probe; no audit.
- `GET /platform/control-plane/snapshot` — GitOps/audit snapshot export; no audit on GET.
- `POST /platform/control-plane/snapshot` — audited mint (`platform.plane.snapshot`); blocked by control-plane freeze.
- `POST /platform/control-plane/snapshot/apply` — audited pin restore (`platform.plane.snapshot_apply`); hash required by default.
- `POST /platform/control-plane/freeze` — audited runtime freeze toggle (`platform.plane.freeze`).
- `POST /platform/control-plane/rollback-lkg` — audited LKG fence rollback (`platform.plane.rollback_lkg`).
- `GET /platform/control-plane/peer-ack` — read-only peer ack status.
- `POST /platform/control-plane/peer-ack` — audited peer ack (`platform.plane.peer_ack`).
- `GET /platform/feedback/analytics` — read-only aggregate for operator reports; structured info logs (`platform_feedback_analytics_served`).

## Change Checklist

Before merge, verify:

1. `node --check frontend/app.js` passes for frontend changes.
2. `python3 -m pytest` passes for backend changes.
3. Coverage status changes in docs match actual UI controls and API calls.
4. Security-sensitive runtime changes include audit and risk-register updates.
5. Architecture-lens conformance (Security, CISO, AWS, Cloud, AI Architect, UI Expert, IAM, and Clean Architecture) is explicitly reflected in `ai-gateway-identity-security-design.md` when governance workflows change.
6. Audit/logging conformance is explicit for changed privileged flows (allow + deny evidence, correlation trace fields, and evidence export/readback paths).
7. Agent-friendly delivery artifacts are captured: scope slice notes, repeatable validation commands, and verification outcomes.
8. Agent-only governance validator passes for release candidates: `bash scripts/validate_agent_delivery_gates.sh`.
