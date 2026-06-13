# Residual Risk and Accepted Risk Register

## Scope
This register captures current security residual risks, accepted risks, and compensating controls for the backend service.

- Service: Enterprise Multi-Agent Platform API
- Repository area: backend/app
- Last updated: 2026-06-12
- Prepared by: Engineering Security Review (Architecture, SecOps, Security Engineering, Vulnerability, CISO lenses)

## Risk Rating Model
- Impact: Low | Medium | High | Critical
- Likelihood: Low | Medium | High
- Residual Risk: derived qualitative rating after compensating controls

## Current Pending Residual Risks

| Risk ID | Risk Statement | Impact | Likelihood | Residual Risk | Owner | Target Date | Status |
|---|---|---|---|---|---|---|---|
| RSK-001 | Header-based actor identity mode can be enabled in local/test contexts and may be unintentionally used in non-production-like deployments if environment management is weak. | High | Medium | Medium | Platform Security | 2026-06-21 | Open |
| RSK-002 | MFA optional mode exists for operational flexibility; misuse can reduce assurance for privileged workflows. | High | Medium | Medium | IAM / App Security | 2026-06-21 | Open |
| RSK-003 | Workload identity response can include raw token only when explicit flag is enabled in local/test; operator misuse could expose sensitive token material. | Critical | Low | Low | Cloud Security | 2026-06-06 | Mitigated |
| RSK-004 | Session signing now supports versioned key ids and rollover validation, but formal rotation cadence automation and alerting still require operational enforcement. | High | Medium | Low | Security Engineering | 2026-06-20 | In Progress |
| RSK-005 | Sensitive endpoint abuse protection now supports distributed Redis-backed enforcement with safe fallback, but production rollout coverage and monitoring baselines are still being finalized. | High | Medium | Low | SecOps | 2026-06-20 | In Progress |
| RSK-006 | App-level transport hardening controls (explicit HTTPS/HSTS/CORS policy assertions) are still deployment-assumed and not fully codified in service middleware. | High | Medium | Low | Platform / SecOps | 2026-06-05 | Mitigated |
| RSK-007 | Password-login endpoint could face repeated credential guessing attempts if account lockout controls are absent or misconfigured. | High | Medium | Low | IAM Engineering | 2026-06-06 | Mitigated |
| RSK-008 | Least-privilege recommendation apply actions can cause operational disruption if downscoping/disablement is applied without sufficient review evidence in sensitive environments. | High | Medium | Medium | Security Architecture + Cloud Operations | 2026-06-30 | Open |
| RSK-009 | Gateway governance evidence exports may contain sensitive operational identifiers from audit records if exported bundles are retained or shared without classification controls. | High | Medium | Medium | Security Architecture + Compliance Operations | 2026-07-08 | Open |
| RSK-010 | Newly introduced OpenAI-compatible inference endpoints could broaden gateway invocation surface if role scope, usage controls, and provider-depth safeguards are not enforced consistently during rollout. | High | Medium | Medium | Security Architecture + Platform Engineering | 2026-07-12 | Mitigated |
| RSK-011 | Prompt release workflows could bypass required variable/render validation or production approval discipline when promoting registry prompts between environments. | High | Medium | Medium | AI Security + Platform Engineering | 2026-07-15 | Open |
| RSK-012 | Harmful or low-quality model outputs can persist longer in production if feedback signals are not triaged with consistent priority and investigation pathways. | High | Medium | Medium | AI Security + Trust Operations | 2026-07-18 | Open |
| RSK-013 | Supported-model recommendation metadata and approval decisions could drift from review intent without explicit ticketed approval, version traceability, and production dual-approval enforcement. | High | Medium | Medium | AI Security + Platform Engineering | 2026-07-22 | Open |
| RSK-014 | External callback deliveries can lose incident triage fidelity or route to the wrong downstream sink if sink routing metadata and correlation context policies are not governed consistently. | High | Medium | Medium | Security Architecture + Trust Operations | 2026-07-25 | Open |
| RSK-015 | Realtime inline-binary media transport can increase data-exposure and incident-trace gaps if event types, payload size, and correlation metadata are not tightly governed at ingest. | High | Medium | Medium | AI Security + Platform Engineering | 2026-07-28 | Open |
| RSK-016 | Gateway-managed Cursor token configuration could expose sensitive token material or allow unauthorized rotation/revocation if plaintext readback, weak approval controls, or incomplete audit evidence are introduced. | Critical | Medium | Medium | Security Architecture + IAM Governance + PAM Operations | 2026-07-30 | Open |
| RSK-017 | Operator-authored gateway memory records may retain PII or sensitive context beyond intended scope if content classification, retention, and production write controls are not enforced consistently. | High | Medium | Medium | AI Security + Platform Engineering | 2026-07-30 | Open |
| RSK-018 | Flow Orchestration Phase 1 uses stub/simulated execution for several node types; unattended prod automation or live outbound HTTP/MCP could exceed intended blast radius if operators treat stub runs as production-ready. | High | Medium | Medium | Security Architecture + Platform Engineering | 2026-08-15 | Open |
| RSK-019 | Flow Orchestration notification nodes (email_send/sms_send) may enable spam or misdirected alerts if Phase 2 live SendGrid/Twilio delivery ships without per-channel rate limits, recipient domain allowlist enforcement, and operator training. | High | Medium | Medium | Security Architecture + Trust Operations | 2026-08-30 | Open |

## Accepted Risks

| Acceptance ID | Accepted Risk | Business Rationale | Expiry Date | Approver | Review Cadence | Renewal Required |
|---|---|---|---|---|---|---|
| AR-001 | Keeping MFA optional flag for controlled environments. | Required for controlled operational continuity during integration/testing windows. | 2026-07-15 | CISO Delegate + Security Architect | Weekly | Yes |
| AR-002 | Keeping token exposure flag in codepath but constrained by runtime-config dual approval and environment guardrails. | Needed for local/test interoperability troubleshooting; disabled by default and force-disabled outside local/test. | 2026-07-15 | Cloud Security Lead + CISO Delegate | Weekly | Yes |

## Compensating Controls

| Control ID | Control Description | Mapped Risks | Control Type | Evidence |
|---|---|---|---|---|
| CC-001 | Non-dev guardrails force header-based identity off regardless of override attempts. | RSK-001 | Preventive | Config logic and startup behavior in security module; test coverage in security config warning tests |
| CC-002 | Startup warnings explicitly log insecure settings at boot for operator visibility. | RSK-001, RSK-002, RSK-003 | Detective | Startup logs containing insecure_configuration_detected |
| CC-003 | Non-dev session secret validation blocks default value and too-short secret lengths. | RSK-004 | Preventive | Startup validation and tests covering reject/allow cases |
| CC-004 | Bearer token parser hardened with structural checks before signature comparison. | RSK-004 | Preventive | Security module token parsing logic and regression tests |
| CC-005 | Sensitive endpoint rate limits added for exact and wildcard path classes. | RSK-005 | Preventive | Rate limiter rules and dedicated rate-limit regression tests |
| CC-006 | Audit events and sanitized logs across critical flows provide forensic traceability. | RSK-001, RSK-002, RSK-003, RSK-005 | Detective | Audit events endpoints and log redaction utilities |
| CC-007 | Primary integration suite and dedicated security regression suites pass consistently. | All | Corrective/Assurance | Test suites: phase0_phase1, security config warnings, rate limit rules |
| CC-008 | Response middleware now enforces baseline transport security headers and non-dev CORS wildcard guardrails. | RSK-006 | Preventive | Middleware enforcement in app/main.py and transport header regression test |
| CC-009 | Security operations runbook defines break-glass controls, rollback steps, and evidence requirements. | RSK-001, RSK-002, RSK-003, RSK-006 | Corrective/Operational | docs/security/security-operations-runbook.md |
| CC-010 | Session tokens now include signing key id with backward-compatible validation for rollover windows. | RSK-004 | Preventive | app/security.py key-ring signing and token rotation tests |
| CC-011 | Rate limiter supports optional Redis distributed backend with automatic fallback to in-memory mode and operational cutover checks. | RSK-005 | Preventive | app/services/rate_limit.py, tests/test_rate_limit_backend.py, scripts/rate_limit_cutover.sh |
| CC-012 | Password-login flow enforces failed-attempt lockout with runtime-configured bounds and admin unlock controls backed by audit evidence. | RSK-007 | Preventive/Detective | auth login lockout state fields, runtime-config validation keys, `auth.login.password` and `auth.directory.user.unlock` audit events |
| CC-013 | Workload identity token-exposure behavior is DB-governed via `workload_identity.expose_access_token` (dual approval required), environment fail-closed outside local/test, and runtime-config audit evidence on validate/read/update/delete/cache invalidation. | RSK-003 | Preventive/Detective | runtime-config validation/audit tests, providers token-exchange tests, runtime-config audit event actions |
| CC-014 | Role authorization remains strict and case-sensitive for all roles except canonicalized `Master Admin`, preventing non-canonical privilege escalation through lowercase role headers. | RSK-001, RSK-002 | Preventive | role-forbidden regression tests in phase0/phase1 and master-admin canonicalization edge test |
| CC-015 | MCP gateway integration is constrained by approved server registry, per-server tool allowlists/prefix constraints, prod dual-approval enforcement for tool calls, and allow/deny audit events for MCP list/call actions. | RSK-001, RSK-002, RSK-005 | Preventive/Detective | `/gateway/mcp/*` endpoint controls, runtime-config validation for `gateway.mcp.servers_json`, and MCP gateway regression tests |
| CC-016 | Least-privilege recommendation apply workflow is role-gated, production dual-approval guarded, audit-backed, and UI-enforced with mandatory operator decision rationale to reduce unsafe privilege-removal actions. | RSK-008 | Preventive/Detective | `/gateway/least-privilege/recommendations/*` controls, UI decision-reason gate, and gateway recommendation regression tests |
| CC-017 | Gateway governance evidence export is constrained by read-role authorization, fixed gateway action taxonomy, bounded per-action query limits, and explicit export audit events to support accountable handling and review. | RSK-009 | Preventive/Detective | `POST /gateway/governance/evidence/export` controls, `gateway.governance.evidence.export` audit events, and gateway evidence export regression tests |
| CC-018 | OpenAI-compatible chat baseline endpoint is role-gated (Platform Admin/AI Ops Approver/Agent Owner), deny/allow audit-backed (`gateway.chat.completions`), and regression-tested for contract + forbidden-role behavior. | RSK-010 | Preventive/Detective | `POST /v1/chat/completions` control path and phase0/phase1 gateway chat completion tests |
| CC-019 | OpenAI-compatible embeddings baseline endpoint is role-gated (Platform Admin/AI Ops Approver/Agent Owner), deny/allow audit-backed (`gateway.embeddings.create`), and regression-tested for contract + forbidden-role behavior. | RSK-010 | Preventive/Detective | `POST /v1/embeddings` control path and phase0/phase1 gateway embeddings tests |
| CC-020 | Prompt registry promotion is now role-gated, validates render-template variables before release, enforces production dual-approval, and emits explicit validation/promotion audit events for traceability. | RSK-011 | Preventive/Detective | `POST /playground/prompts/{prompt_registry_id}/promote`, `playground.prompt_registry.promote*` audit events, and prompt promotion regression tests |
| CC-021 | Playground quality triage queue exposes low-quality/low-rating feedback with operator filters, priority tags (`p0/p1/p2`), owner scoping, and audit-backed queue read actions to improve detection and response workflows. | RSK-012 | Detective/Corrective | `GET /playground/quality/triage`, `playground.feedback.triage.read` audit events, and playground triage regression tests |
| CC-022 | Playground quality escalation lifecycle provides SLA-tracked escalation create/list/acknowledge/resolve/notify workflows with owner-scope guardrails and audit evidence for trust-ops incident response traceability. | RSK-012 | Preventive/Detective/Corrective | `POST /playground/quality/triage/{feedback_id}/escalate`, `GET /playground/quality/triage/escalations`, escalation ack/resolve/notify endpoints, and `playground.feedback.triage.escalation.*` audit events |
| CC-023 | Supported-model governance now requires explainability rationale capture, records metadata version progression with immutable revision snapshots, enforces role-gated approval/rejection actions, and requires production dual approval for prod-targeted decisions. | RSK-013 | Preventive/Detective | `/providers/models*` governance controls, `supported_model.*` audit events, and supported-model approval/version regression tests |
| CC-024 | Gateway external callback governance now enforces sink-type and correlation-preset normalization, supports route-key based sink routing metadata, surfaces correlation-context preview during delivery tests, and exports sink/preset distributions for audit and CISO evidence review. | RSK-014 | Preventive/Detective | `/gateway/external-callbacks*` controls, `gateway.external_callback.*` audit events, and callback routing/correlation regression tests |
| CC-025 | Realtime session governance now enforces inline-binary event allowlists, dedicated inline byte caps, optional correlation-id requirements, and existing production dual-approval controls for inline transport operations. | RSK-015 | Preventive/Detective | `/v1/realtime*` stream-policy controls, `gateway.realtime.*` audit events, and realtime inline-policy regression tests |
| CC-026 | Unified secret provider model constrains Cursor credential handling via gateway admin/security role gates, MFA-backed db secret value mutations, dual-approval requirements for binding set/clear, encrypted-at-rest persistence in `secret_provider_stored_values` for `db` providers, provider-reference-only gateway binding (runtime_config v3), generic `provider_credential_bindings` CRUD with masked readback and `provider_credential_binding.*` audit events (P1), gateway cursor auto-sync from credential bindings, **agent runtime credential resolution at gateway inference** (`credential_resolution`, `_ensure_inference_credentials`), `secret_path_prefixes` guardrails, masked readback semantics (no plaintext token return), non-production header-asserted identity trust for operator workflows, browser CORS allow-listing for approver headers, explicit audit events for value and binding actions, and deprecated `/gateway/cursor-token` compatibility with migration to v3 binding. Residual: route consumer bindings not resolved at fallback runtime. | RSK-016 | Preventive/Detective | `/secrets/providers/{id}/values*`, `/providers/credential-bindings*`, `/agent-configs/{agent_key}/credential-status`, `/gateway/cursor-secret-binding`, deprecated `/gateway/cursor-token`, `secret_provider.value.*`, `gateway.cursor_secret_binding.*`, `agent_config.credential_status.read`, and `provider_credential_binding.*` audit events, `backend/tests/test_secret_provider_db_values.py`, `backend/tests/test_provider_credential_bindings.py`, `backend/tests/test_agent_credential_resolution.py`, and gateway token regression tests |
| CC-027 | Gateway provider-depth inference forwarding resolves credentials from agent/catalog/platform/env/cursor bindings before upstream calls, preserves simulation fallback when `GATEWAY_INFERENCE_SIMULATION=true`, and adds upstream contract tests in `backend/tests/test_gateway_inference.py`. | RSK-010 | Preventive/Detective | `app/services/gateway_inference.py`, `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`, `/v1/messages`, `/v1/images*`, `/v1/rerank` |
| CC-028 | Gateway memory store governance constrains operator memory via role gates (read/write/delete), Agent Owner object-level and overview count scoping, 16 KiB content cap (schema + service), per-scope active-record limits, short-term TTL auto-expiry, production long-term dual-approval on create/delete, optional PII classification hook (`gateway.memory.pii_classification_enabled`, default off) blocking pii/phi/secret classes with metadata tagging, and audit events for overview/list/create/read/delete allow/deny paths. Residual: heuristic classification only — not ML-based; edge cases may bypass without operator policy discipline. | RSK-017 | Preventive/Detective | `/gateway/memory/*` controls, `gateway.memory.*` audit events, runtime-config keys `gateway.memory.short_term_ttl_seconds`, `gateway.memory.max_records_per_scope`, `gateway.memory.pii_classification_enabled`, and `backend/tests/test_gateway_memory.py` |
| CC-029 | Inference cache short-circuit stores encrypted response bodies in `gateway_response_cache_entries`, defaults off via `gateway.cache.inference_short_circuit_enabled`, requires dual approval to enable in production, respects cache policy privacy_scope and non_cache_data_classes, records hit/miss/bypass audit events, and excludes streaming responses. Residual: cached responses may contain operator-visible model output — use policy data-class controls. | RSK-017, RSK-010 | Preventive/Detective | `gateway_response_cache.py`, `/v1/chat/completions`, `/v1/responses`, `/gateway/cache/entries`, `test_gateway_response_cache.py` |
| CC-030 | RAG data plane delegates to MCP bridge tools (`vector.search`, `vector.upsert`, `vector.delete`) with CP-REF credential resolution, role-gated `/rag/*` endpoints, read-only OpenAI vector store registry POST, default-off live probes (`gateway.vector_stores.live_probe_enabled`), and audit events for ingest/query. Residual: non-MCP vector providers unsupported in v1; MCP server must implement tool contract. | RSK-017 | Preventive/Detective | `gateway_rag.py`, `/rag/ingest`, `/rag/query`, `/v1/vector_stores*`, `test_gateway_rag.py`, `litellm-rag-parity-impact-analysis.md` |
| CC-031 | Flow Orchestration Phase 1 constrains workflows via role-gated CRUD/run/approve, inline-secret rejection, HTTP host allowlist default deny (`orchestration.http_allowed_hosts_json`), max node cap, prod approval gate, dual approval on prod approve and prod runs with human_approval nodes, rate limits on mutations, and audit events for allow/deny paths. Residual: stub executor — live runtime deferred to Phase 2 (RSK-018). | RSK-018 | Preventive/Detective | `/orchestration/*`, `orchestration.flow.*` audit events, `test_orchestration_flows.py`, `flow-orchestration-impact-analysis.md` |
| CC-032 | Flow Orchestration notification channels constrain email/SMS workflows via registry validation (`gateway.notification_channels_json`, no inline secrets, `credential_binding_id` required when enabled), sensitive-key dual approval on registry mutation, flow validation requiring enabled channel + binding, recipient template secret-pattern rejection, Phase 1 stub/simulated send only (no live provider HTTP), notification nodes counted toward max_nodes, and audit on channel context read. Residual: Phase 2 live delivery requires rate limits and domain allowlist runtime enforcement (RSK-019). | RSK-018, RSK-019 | Preventive/Detective | `GET /gateway/notification-channels*`, `email_send`/`sms_send` nodes, `gateway.notification_channel.context.read`, `test_gateway_notification_channels.py`, `flow-orchestration-notification-impact-analysis.md` (GOV-FLOW-NOTIFY-001) |

## CISO Review — Gateway Memory Store (2026-06-12)

**Scope:** `/gateway/memory/*` operator memory for Memory & Context selling-point workflows.

**Risk surface**

- Free-text memory content may include PII or sensitive operational context if operators paste unreviewed material.
- Global-scoped long-term records can affect multiple agents; production mutations require dual approval but read paths remain role-gated rather than data-classified.
- Short-term TTL and per-scope limits reduce unbounded retention; semantic cache and checkpoint/realtime counts in overview remain platform-wide for Agent Owner (accepted: non-memory aggregates only).

**Controls in place**

- Content capped at 16 KiB; scope types limited to session/conversation/agent/global with configurable max active records per scope.
- Short-term records auto-expire via runtime TTL; list path expires stale rows before readback.
- Production long-term create/delete require Security Approver dual approval with deny audit evidence.
- Agent Owner read/list/delete/overview active-record counts scoped to own `actor_id`.

**Residual / accepted**

- RSK-017 partially mitigated: opt-in `gateway.memory.pii_classification_enabled` (default off) blocks pii/phi/secret via heuristic classification; not ML-based.
- Accepted: Agent Owner overview still shows platform-wide checkpoint, realtime, response/file, and semantic-cache aggregates (not actor-owned memory records).

**Recommendation:** Conditional approve for operator beta; require data-handling training and periodic audit sampling of prod long-term memory creates.

## CISO Review — Flow Orchestration Notification Channels (2026-06-12)

**Scope:** `gateway.notification_channels_json` registry, `email_send`/`sms_send` orchestration nodes, `GET /gateway/notification-channels*`.

**Risk surface**

- Phase 2 live email/SMS from automated flows could amplify phishing/spam if templates or recipient lists are misconfigured.
- Registry stores binding refs only; compromise of flow JSON does not expose provider keys directly.
- Playground escalation notify remains a separate path — operators must not conflate the two.

**Controls in place**

- No inline API keys in registry or flow graph; `credential_binding_id` on enabled channels.
- Recipient templates reject inline secret/token patterns at validate time.
- Phase 1 executor returns `simulated: true` only — no SendGrid/Twilio HTTP from orchestration runs.
- Prod flow approval and max_nodes cap unchanged.

**Recommendation:** **Go** for Phase 1 stub registry and nodes. **No-go** for Phase 2 live send until rate limits, domain allowlist enforcement, and delivery audit events are implemented (RSK-019).

## Required Next Actions

1. Add automated rotation cadence and expiration alerting for session signing keys.
2. Finalize production rollout monitoring and alerting thresholds for Redis-backed rate limiting.
3. Validate HTTPS termination and HSTS compatibility at ingress/load balancer level in staging/prod.
4. Configure SIEM webhook destination and alert routing for `insecure_configuration_detected` startup events.
5. Add operational alerting for repeated `auth.directory.user.unlock` events per actor and per user to detect abuse patterns.
6. Add monitoring for `gateway.least_privilege.apply*` event volume and failed post-apply operations to detect over-restrictive recommendation application.
7. Add retention and classification policy checks for gateway governance evidence bundles (owner, retention window, approved sharing channels).
8. Add a dedicated UI workflow for prompt promotion approvals to reduce manual/API-only release operations.
9. Add outbound delivery adapters with retry/receipt tracking for notification destinations to harden reliability guarantees.

## Decision Log

| Date | Decision | Decision Owner | Notes |
|---|---|---|---|
| 2026-06-05 | Keep operational flags with strict environment guardrails and startup warnings. | Security Architect + Engineering Lead | Accepted with time-bound review |
| 2026-06-05 | Track remaining posture gaps as residual risk with compensating controls. | CISO Delegate | Register created |
| 2026-06-05 | Codified transport security headers and non-dev CORS wildcard guardrails in service middleware. | Platform Security + SecOps | RSK-006 moved to mitigated |
| 2026-06-05 | Implemented versioned session signing key support with rollover-compatible token validation. | Security Engineering | RSK-004 residual lowered to Low and moved to In Progress |
| 2026-06-05 | Implemented Redis-capable distributed rate limiting with safe fallback and cutover automation. | SecOps + Platform Security | RSK-005 residual lowered to Low and moved to In Progress |
| 2026-06-06 | Implemented password-login lockout controls and privileged unlock endpoint with audit evidence. | IAM Engineering + Security Architecture | RSK-007 moved to mitigated with CC-012 coverage |
| 2026-06-06 | Moved workload identity token exposure governance to DB runtime-config with dual-approval control, fail-closed non-local behavior, and runtime-config audit trail hardening. | Cloud Security + Platform Security | RSK-003 moved to mitigated with CC-013 coverage |
| 2026-06-06 | Restored strict role case semantics (except canonical Master Admin alias) and validated full backend suite. | Security Engineering | Canonical role-bypass regression closed with CC-014 evidence |
| 2026-06-06 | Added governed MCP gateway workflows with runtime-configured approved server registry, allowlist enforcement, production dual approval, and explicit MCP audit actions. | Security Architecture + Cloud Engineering | Added CC-015 compensating control for new MCP integration surface |
| 2026-06-08 | Added least-privilege recommendation governance controls, including production dual-approval and UI decision-rationale requirement for apply operations. | Security Architecture + IAM Engineering | Added RSK-008 and CC-016 for recommendation-application safety posture |
| 2026-06-08 | Added dedicated gateway governance evidence export endpoint and role-gated, audit-backed bundle generation workflow. | Security Architecture + Compliance Operations | Added RSK-009 and CC-017 for evidence-handling posture |
| 2026-06-08 | Added OpenAI-compatible chat baseline endpoint with role-gated access and deny/allow audit evidence. | Security Architecture + Platform Engineering | Added RSK-010 and CC-018 for new inference-surface control posture |
| 2026-06-08 | Added OpenAI-compatible embeddings baseline endpoint with role-gated access, tenant/model entitlement checks, and deny/allow audit evidence. | Security Architecture + Platform Engineering | Added CC-019 for new inference-surface control posture |
| 2026-06-09 | Added prompt registry promotion governance endpoint with render validation, production dual approval, and explicit audit evidence. | AI Security + Platform Engineering | Added RSK-011 and CC-020 to track prompt-release posture and compensating controls |
| 2026-06-09 | Added playground quality triage queue with priority tagging, owner scoping, and audit-backed read evidence for quality-issue investigations. | AI Security + Trust Operations | Added RSK-012 and CC-021 for detection/triage posture coverage |
| 2026-06-09 | Added playground quality escalation lifecycle with SLA-tracked escalation and acknowledge/resolve actions. | AI Security + Trust Operations | Added CC-022 and closed initial escalation-hook workflow gap for triage operations |
| 2026-06-09 | Added escalation notification hook (`/notify`) with channel/destination metadata and audit-backed evidence. | AI Security + Trust Operations | Extended CC-022 coverage to include communication handoff traceability |
| 2026-06-09 | Enhanced Discovery dashboard with posture metrics and unified triage filters/actions over existing governed discovery APIs. | Security Architecture + UI Engineering | No new residual risk accepted; improves operator triage speed while preserving existing role/audit controls |
| 2026-06-09 | Added modules integration metadata and governed sync workflow (`/modules/{module_id}/integration/sync`) with fail-closed provider validation and audit evidence. | Security Architecture + Platform Engineering | No new residual risk accepted; additive control-plane visibility and sync hygiene for module integrations |
| 2026-06-10 | Added supported-model explainability and approval/version governance controls with revision history and production dual-approval enforcement for prod decisions. | AI Security + Platform Engineering | Added RSK-013 and CC-023 for model-catalog recommendation and approval integrity posture |
| 2026-06-10 | Extended gateway external callback productization with sink routing metadata and correlation preset governance plus exportable sink/preset evidence distributions. | Security Architecture + Trust Operations | Added RSK-014 and CC-024 for downstream routing and incident-correlation integrity posture |
| 2026-06-10 | Hardened realtime/media inline-binary transport governance with event allowlist, inline byte cap, and correlation-id policy checks at ingest. | AI Security + Platform Engineering | Added RSK-015 and CC-025 for realtime transport exposure and traceability posture |
| 2026-06-10 | Added governed gateway cursor token configuration workflow with masked readback, dual-approval mutation controls, `db` and `external` storage mode support, and audit-backed traceability for UI-driven token management. | Security Architecture + Cloud Engineering + IAM Governance | Added RSK-016 and CC-026 for token handling, identity governance, and PAM posture |
| 2026-06-10 | Consolidated Cursor credential configuration into unified secret provider model (`db`, Vault, AWS, Azure) with encrypted db value storage, gateway secret binding, deprecated legacy cursor-token API, and CISO gap analysis (`unified-secret-provider-ciso-gap-analysis.md`). | Security Architecture + CISO Delegate + IAM Governance | Updated CC-026; residual gaps GAP-USP-R01–R05 tracked in CISO gap analysis |
| 2026-06-10 | Shipped P1 generic credential bindings (`provider_credential_bindings` API/UI, model credential metadata, agent binding picker); full impact analysis in GOV-GPC-FINAL-001 Part 5. | Security Architecture + Platform Engineering + IAM Governance | Extended CC-026 with binding audit path; RSK-016 likelihood reduced; agent runtime resolver deferred to P2 |
| 2026-06-12 | Added gateway memory store (`/gateway/memory/*`) with content cap, scope limits, short-term TTL, Agent Owner scoping, and production long-term dual-approval on create/delete. | AI Security + Platform Engineering + CISO Delegate | Added RSK-017 and CC-028; CISO review section documents PII-in-memory residual and accepted overview aggregate scoping |
| 2026-06-12 | Added Phase 4 RAG data plane (`/rag/*`, `/v1/vector_stores*`), live vector probe flag, and memory PII classification hook (default off). | AI Security + Platform Engineering + CISO Delegate | Added CC-030; updated CC-028/CC-029; partial RSK-017 closure via heuristic PII hook |
| 2026-06-12 | Added Flow Orchestration notification channel registry and email_send/sms_send stub nodes (GOV-FLOW-NOTIFY-001). | Security Architecture + Platform Engineering + CISO Delegate | Added RSK-019 and CC-032; Phase 1 go / Phase 2 live send no-go documented |

## Sign-off

- Security Architect: Pending
- SecOps Lead: Pending
- Security Engineering Lead: Pending
- Vulnerability Management Lead: Pending
- CISO / Delegate: Pending
