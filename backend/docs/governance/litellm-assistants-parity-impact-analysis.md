# LiteLLM Assistants Parity — Impact Analysis

**Document ID:** GOV-LITELLM-ASSISTANTS-001  
**Status:** Active  
**Last updated:** 2026-06-14  
**Related:** `litellm-rag-parity-impact-analysis.md`, `litellm-cache-parity-impact-analysis.md`, `api-inventory-and-ui-map.md`, `ui-api-design-coverage-map.md`, `generic-provider-configuration-review-and-impact-analysis.md`

## Purpose

Record Assistants / fine-tuning / passthrough proxy parity, auth explain, playground drill-down, and compliance evidence export implementation, security posture, duplication boundaries, advanced operator cases, and full impact analysis (Part 5).

## Implementation Status (2026-06-14)

| Component | Status | Notes |
|-----------|--------|-------|
| Assistants API (`/v1/assistants*`) | **Done** | CRUD + list; reuses gateway inference for thread runs |
| Threads / messages / runs | **Done** | `/v1/threads*`, message post/list, run execute via `gateway_assistants.py` |
| Fine-tuning jobs | **Done** | `/v1/fine_tuning/jobs*` with simulated completion when live flag off |
| Passthrough proxy | **Done** | `POST /v1/passthrough` with path allowlist + credential substitution + prod dual-approval |
| Auth explain | **Done** | `POST /gateway/authz/explain` and `/auth/authz/explain` with MFA + dual-approval context |
| Playground drill-down | **Done** | `GET /playground/runs/{run_id}/detail` aggregated run/feedback/assessment/audit |
| Compliance evidence export | **Done** | `POST /compliance/evidence/export` server bundle + audit event + investigation_context embed |
| Frontend (Routing & Gateway) | **Done** | Assistants (create/delete/list messages/table select), fine-tuning, passthrough, authz explain presets |
| Frontend (Playground) | **Done** | Drill-down tabs (run, feedback, assessment, audit, actions) |
| Frontend (Security) | **Done** | Auth explain form handler |
| Frontend (Compliance) | **Done** | Export posts to server endpoint with bundle filters |
| Tests | **Done** | 29 regression cases: core + advanced owner scope, prod dual-approval, deny audit, empty-thread 422, message list, authz explain, export embed, populated drill-down |

## CISO / Security Impact

| Control | Implementation |
|---------|----------------|
| Owner scoping | Agent Owner restricted to own assistants, threads, fine-tuning jobs, playground runs |
| Prod dual-approval | Assistant delete, fine-tuning cancel, and passthrough require `require_dual_approval` in prod environment; **deny audit** emitted on dual-approval and owner-scope failures |
| Passthrough path allowlist | Runtime key `gateway.passthrough.allowed_paths_json`; disallowed paths return 403 |
| No client credential passthrough | `BLOCKED_HEADER_NAMES` strips `Authorization`, `x-api-key`, and related headers; platform CP-REF credential substituted |
| Audit events | `gateway.assistants.*`, `gateway.threads.*`, `gateway.fine_tuning.*`, `gateway.passthrough.execute`, `compliance.evidence.export`, playground assess/route-draft actions |
| Auth explain | Read-only simulation; MFA and dual-approval requirements surfaced without mutating policy |
| Compliance export | Read-role gated; explicit allow/deny audit on export; investigation_context embedded in bundle |

## Duplication Risks — What Was NOT Duplicated

| Avoided | Rationale |
|---------|-----------|
| Second inference stack for assistants | Reuses `gateway_inference.execute_chat_completion` + CP-REF credential resolution |
| Parallel auth explain service | Reuses existing `/gateway/authz/explain` and `/auth/authz/explain` patterns |
| Duplicate playground run model | Drill-down aggregates existing run, feedback, audit, route-draft tables |
| Inline API keys in passthrough payloads | CP-REF secret model; client headers sanitized |
| Separate compliance bundle builder | Reuses `_build_compliance_evidence_bundle` for GET bundle and POST export |

---

## Part 5 — Full Impact Analysis (Comprehensive)

This section is the authoritative impact assessment for Assistants / fine-tuning / passthrough parity, auth explain extensions, playground drill-down, and compliance export advanced cases.

### 5.1 Change inventory

| Change ID | Component | Type | Shipped | Primary beneficiary |
|---|---|---|---|---|
| CHG-ASSIST-01 | `/v1/assistants*` CRUD + owner scope | API | Yes | Agent Owner / AI Ops |
| CHG-ASSIST-02 | `/v1/threads*` messages + runs via gateway inference | API | Yes | Playground / gateway operators |
| CHG-ASSIST-03 | `/v1/fine_tuning/jobs*` simulated + live cancel | API | Yes | Model ops |
| CHG-ASSIST-04 | `/v1/passthrough` allowlist + header strip + prod dual-approval | API | Yes | Platform / security |
| CHG-ASSIST-05 | `POST /gateway/authz/explain` assistant delete + fine-tuning cancel actions | API | Yes | Security / audit |
| CHG-ASSIST-06 | `GET /playground/runs/{id}/detail` aggregation | API | Yes | Playground operators |
| CHG-ASSIST-07 | `POST /compliance/evidence/export` investigation_context embed | API | Yes | Auditor / compliance |
| CHG-ASSIST-08 | Routing & Gateway Assistants card (create/delete/list messages/table select) | UI | Yes | Gateway operators |
| CHG-ASSIST-09 | Routing & Gateway fine-tuning + passthrough prod dual-approval fields | UI | Yes | Gateway operators |
| CHG-ASSIST-10 | Authz explain preset actions for assistants.delete / fine_tuning.cancel / passthrough.execute | UI | Yes | Security investigations |
| CHG-ASSIST-11 | Advanced regression tests (29 cases) | Tests | Yes | Security Engineer / CI |
| CHG-ASSIST-12 | Deny-path audit for dual-approval + scope failures | Backend | Yes | Audit Architect |
| CHG-ASSIST-13 | `environment` on assistant/fine-tuning API responses + UI columns | API + UI | Yes | Frontend / CISO |
| CHG-ASSIST-14 | Retrieve Assistant / Retrieve Job UI buttons | UI | Yes | Gateway operators |
| CHG-ASSIST-15 | Compliance export missing-control deny audit; no client fallback | API + UI | Yes | Auditor |

### 5.2 Architecture layers (presentation → infrastructure)

| Layer | Before | After | Residual impact |
|---|---|---|---|
| **Presentation** | No assistants/fine-tuning/passthrough consoles | Routing & Gateway cards with dual-approval fields, table row selection, message list, delete form | Playground drill-down still separate view; no bulk assistant delete |
| **Application** | Gateway inference only for chat completions | Assistants thread runs delegate to `execute_chat_completion`; passthrough proxies with sanitizer; fine-tuning job lifecycle | Live fine-tuning upstream not wired when flag off (simulated) |
| **Domain** | No assistant/thread/fine-tuning records | `GatewayAssistant*`, `GatewayFineTuningJobRecord` with owner_id + environment | No cross-tenant assistant sharing model |
| **Infrastructure** | CP-REF for inference | Passthrough substitutes platform credential; blocked client auth headers | Passthrough allowlist is runtime-config JSON (ops must maintain) |

### 5.3 Stakeholder matrix

| Stakeholder | Pre-change pain | Current state | Residual impact | Compensating control |
|---|---|---|---|---|
| **Platform Engineering** | LiteLLM assistants/fine-tune gaps | OpenAI-compatible surfaces wired to existing gateway stack | Live fine-tune flag off by default | Simulated completion + cancel tests |
| **Security Architect** | Ungoverned passthrough risk | Path allowlist, header strip, prod dual-approval on passthrough | Allowlist misconfiguration could block legit paths | Runtime config + deny audit events |
| **CISO** | Prod mutations without co-sign | Assistant delete, fine-tune cancel, passthrough prod gated | Residual: operator must supply approver headers in UI | Authz explain presets for pre-flight |
| **IGA** | Owner scope unclear for new resources | Agent Owner scoped on assistants, threads, jobs, playground runs | No IGA review UI for assistant ownership | Audit export + owner_id on records |
| **AI Ops** | No operator path for fine-tuning jobs | Create/list/cancel with table row select | Live upstream training deferred | Simulated succeeded status in dev |
| **Agent Owner** | Could not manage own assistants | CRUD + thread workflow within owner scope | Cannot access peer owner resources (by design) | 403 `AUTHZ_SCOPE_FORBIDDEN` |
| **Auditor** | Compliance export without investigation context | `investigation_context` embedded in export bundle | Manual SIEM rule wiring still required | Audit event on every export |

### 5.4 Console impact

| Console | Endpoints touched | UX change | Runtime behavior change | Risk if misconfigured |
|---|---|---|---|---|
| **Routing & Gateway → Assistants** | `/v1/assistants*`, `/v1/threads*` | Create, delete (prod dual-approval), list messages, table row click | Thread runs use gateway inference + CP-REF | Wrong environment on delete → dual-approval surprise |
| **Routing & Gateway → Fine-tuning** | `/v1/fine_tuning/jobs*` | Cancel with prod dual-approval fields; table row select | Simulated completion when live flag off | Cancel on terminal job → 409 |
| **Routing & Gateway → Passthrough** | `/v1/passthrough` | Prod dual-approval fields on form | Client Authorization stripped; platform key used | Disallowed path → 403 |
| **Routing & Gateway → Authz Explain** | `/gateway/authz/explain` | Preset actions for `gateway.assistants.delete`, `gateway.fine_tuning.cancel`, `gateway.passthrough.execute` | Read-only simulation | Unknown action → warn decision |
| **Playground** | `/playground/runs/{id}/detail`, feedback, assess | Drill-down tabs populated from aggregated endpoint | Assessment derived from feedback + assess audit | Empty run → empty feedback (expected) |
| **Security** | `/auth/authz/explain` | MFA verified field in explain matrix | Read-only | — |
| **Compliance** | `/compliance/evidence/export` | investigation_context JSON in export form | Context embedded in bundle payload | Missing control_id → 404 |

### 5.5 Security / compliance / audit cross-walk

| Control objective | Pre-change | Post-change | Evidence | Gap |
|---|---|---|---|---|
| Owner scoping (CC6) | Playground only | + assistants, threads, fine-tuning jobs | `AUTHZ_SCOPE_FORBIDDEN` tests | — |
| Prod dual-approval (CC6) | Route/key mutations | + assistant delete, fine-tune cancel, passthrough | Dual-approval tests + authz explain | UI relies on operator entering approver fields |
| No credential passthrough (CC6) | Gateway inference CP-REF | Passthrough header sanitizer | `test_gateway_passthrough_does_not_forward_client_authorization` | — |
| Path allowlist (CC6) | N/A | Runtime JSON allowlist | Disallowed path 403 test | Ops must update allowlist for new upstream paths |
| Audit completeness (CC7) | Partial gateway audit | + assistants, threads, fine-tuning, passthrough, compliance export | Audit list API assertions | SIEM rules auto-wired via observability catalog + audit dispatch |
| Evidence export traceability (CC7) | GET bundle only | POST export + investigation_context embed | Export audit event test | — |
| Auth explain (CC7) | Gateway route actions only | + assistants.delete, fine_tuning.cancel mappings | Authz explain tests | — |
| Playground quality loop (CC7) | Feedback only | Drill-down aggregates feedback + assessment | Populated detail test | — |

### 5.6 Duplication boundaries (reinforced)

| Surface | Reused component | NOT duplicated |
|---|---|---|
| Assistant thread run | `gateway_inference.execute_chat_completion` | Separate LLM client or LiteLLM assistant runtime |
| Passthrough credential | `resolve_inference_credential` + CP-REF | Per-request client API keys |
| Auth explain | `GATEWAY_AUTHZ_ACTION_ROLE_MAP` + prod dual-approval set | New policy engine |
| Playground detail | Existing run, feedback, audit, route-draft, escalation tables | New drill-down persistence layer |
| Compliance export | `_build_compliance_evidence_bundle` | Second bundle builder |
| Frontend dual-approval | `getGatewayDualApprovalHeaders` / `getProvidersSecurityMutationHeaders` | Per-console header builders |

### 5.7 Advanced cases register

**Core cases (initial parity):**

1. Agent Owner cannot retrieve or delete another owner's assistant (403 `AUTHZ_SCOPE_FORBIDDEN`).
2. Production assistant delete denied without dual-approval headers; succeeds with Security Approver headers.
3. Production fine-tuning job cancel requires dual approval when job environment is prod.
4. Passthrough strips client `Authorization` header; outbound request uses platform credential only.
5. Playground run detail returns aggregated payload: run, feedback list, latest assessment, audit trace, route draft, quality escalation.
6. Compliance evidence export emits `compliance.evidence.export` audit event with allow outcome.
7. Auth explain returns `mfa_missing` / `mfa_present` reasons when action requires MFA and `mfa_verified` is supplied.

**Advanced cases (2026-06-14):**

8. Passthrough prod environment requires dual approval; succeeds with Security Approver headers.
9. Agent Owner cannot read another owner's fine-tuning job (403 `AUTHZ_SCOPE_FORBIDDEN`).
10. Thread run on empty thread (no user message) returns 422.
11. `GET /v1/threads/{id}/messages` returns posted messages after `POST` message.
12. `POST /gateway/authz/explain` with `gateway.assistants.delete` in prod returns `requires_dual_approval` / deny without approver; allow with approver.
13. Compliance export with `investigation_context` JSON embeds context in bundle and top-level response.
14. Playground drill-down after feedback + assess returns non-empty `feedback` and populated `latest_assessment`.
15. Frontend: assistant delete form with prod dual-approval fields wired to `DELETE /v1/assistants/{id}`.
16. Frontend: List Messages button calls `GET /v1/threads/{id}/messages` and displays in payload panel.
17. Frontend: assistant table row click populates `assistant_id` on thread and delete forms.

**Gap-closure pass (2026-06-14):**

18. Deny audit on prod dual-approval failure for assistant delete, fine-tuning cancel, passthrough.
19. Deny audit on owner-scope 403 for assistant delete and fine-tuning cancel.
20. Deny audit on compliance export missing control (404).
21. `environment` field on assistant and fine-tuning API responses; UI env columns.
22. Retrieve Assistant / Retrieve Job buttons; passthrough Headers JSON in UI.
23. Compliance export fails closed (no silent client bundle fallback).
24. Fine-tuning list no longer mutates job state on read.

### 5.8 Deferred / residual risks

| Risk ID | Description | Severity | Mitigation | Owner |
|---|---|---|---|---|
| RSK-ASSIST-01 | Live fine-tuning upstream gated by runtime flag | Low | Wired to OpenAI-compatible upstream when `gateway.fine_tuning.live_enabled=true`; simulated completion when false (default) | AI Ops |
| RSK-ASSIST-02 | Passthrough allowlist drift vs provider API | Medium | Runtime config key + deny audit | Platform Eng |
| RSK-ASSIST-03 | Assistant list response omitted environment (delete used create-form fallback) | **Closed** | `environment` returned in assistant/fine-tuning API responses and table columns | Frontend |
| RSK-ASSIST-04 | No bulk assistant delete or thread archive | Low | Single-resource delete only | Product |
| RSK-ASSIST-05 | SIEM rules for new audit action types not wired | Medium | Audit API export + compliance bundle | Security Eng | **Closed** — `backend/app/services/siem_alert_rules.py` default catalog + runtime override (`observability.siem_rules_json`); audit dispatch hook; `GET/POST /observability/siem-rules*` API; gateway SIEM callbacks (`sink_type=siem`) route by `sink_route_key`. Tests: `test_siem_alert_rules.py`. |
| RSK-ASSIST-06 | Auth explain is simulation only (no live policy mutation) | Low | Documented; operators use explain before prod mutations | Security Arch |

### 5.9 Validation commands

```bash
cd backend && python3 -m pytest tests/test_gateway_assistants.py tests/test_gateway_fine_tuning.py tests/test_gateway_passthrough.py tests/test_playground_run_detail.py tests/test_compliance_evidence_export.py -q
node --check frontend/app.js
```

Expected: **29 passed** (as of 2026-06-14 gap-closure pass).

Browser smoke (manual):

1. Routing & Gateway → Assistants: create assistant, click table row, post message, list messages, run thread, delete (dev).
2. Routing & Gateway → Fine-tuning: create job, click row, cancel (dev).
3. Routing & Gateway → Passthrough: dev passthrough succeeds; prod without approver denied.
4. Routing & Gateway → Authz Explain: select `gateway.assistants.delete`, environment prod, verify deny/allow.
5. Playground: create run, post feedback, assess, open drill-down detail tabs.
6. Compliance: export evidence with investigation_context JSON; verify bundle embed.

## Sign-off

| Role | Status |
|------|--------|
| Platform Engineering | Implemented |
| Security Architecture | Owner scope, prod dual-approval, passthrough allowlist + header strip documented |
| CISO | CP-REF preserved; prod mutations gated; export auditable |
| IGA | Owner scoping on assistants, threads, fine-tuning, playground |
| AI Ops | Fine-tuning operator workflow with simulated/live modes |
| Agent Owner | Scoped CRUD and thread workflow |
| Auditor | Export with investigation_context embed |
| Frontend UI Expert | Control-center handlers aligned to existing gateway/compliance patterns |
