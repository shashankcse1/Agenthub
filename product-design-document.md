# Product Design Document

Date: 2026-06-09
Product: Enterprise Multi-Agent Platform

## 0. Current Capability Sync (2026-06-10)

This document now reflects completion of the previously tracked parity-depth backlog for gateway and operations governance:

1. Realtime/media binary governance depth is implemented with explicit inline policy controls (allowlisted event types, inline byte ceilings, and optional correlation-id requirements) enforced during realtime event ingest.
2. Prompt release governance depth is implemented with stronger promotion and validation workflow controls.
3. Operator-grade quality triage and escalation workflows are implemented, including lifecycle handling and audit-backed delivery tracing.
4. Long-window quality analytics rollups are implemented across provider/route/model dimensions.
5. Model catalog recommendation explainability plus approval/version controls are implemented in provider model governance workflows.
6. External observability sink productization depth is implemented with sink routing metadata and correlation preset controls.

## 1. Purpose

Create a unified platform to build, run, govern, and scale AI agents across the organization.

The platform must support:

1. Agent registration and ownership
2. Multi-source agent discovery
3. Secure multi-agent execution
4. Policy-governed tool and model access
5. Operational observability, evaluations, and release governance
6. Real-time cost evaluation and tracking across agents, tools, and model calls

## 2. Goals

1. Establish each agent as a first-class identity.
2. Preserve end-to-end provenance across delegated agent workflows.
3. Provide clear UI workflows for registration, ownership, and discovery.
4. Reduce unmanaged agent activity (shadow agents).
5. Improve reliability and quality with checkpoints, benchmarks, and scan reports.
6. Provide real-time cost visibility with proactive budget controls.

## 2.1 Design Principles for Fast Agent Development

1. Contract-first design:
All platform capabilities are exposed through stable contracts before implementation details.

2. Modular by default:
Every major capability is packaged as replaceable modules with clear boundaries.

3. Secure-by-default paths:
The default SDK and UI paths automatically apply identity, policy, audit, and cost controls.

4. Progressive complexity:
Teams can start with a minimal agent template and add modules incrementally.

5. Explainability in design:
Every module exposes intent, inputs, outputs, failure modes, and owner metadata.

6. Backward-compatible evolution:
Versioned contracts and compatibility gates reduce rework and integration risk.

## 3. Non-Goals

1. Building domain-specific business agents in this phase.
2. Replacing all existing IAM systems.
3. Creating a single custom LLM model.

## 4. Users

1. Platform engineers
2. Product engineers
3. Security and IAM teams
4. Operations and compliance teams
5. No-code builders and business analysts

## 4.1 Scale Targets

The platform must support staged growth from 10,000 to 100,000 users.

1. Scale tier 1:
Support 10,000 monthly active users with stable p95 experience and full governance controls.

2. Scale tier 2:
Support 50,000 monthly active users with no control-plane bottlenecks and no loss in observability coverage.

3. Scale tier 3:
Support 100,000 monthly active users with multi-region resilience, cost controls, and compliance evidence generation at steady state.

## 4.2 Capacity Planning Assumptions

These assumptions guide architecture and performance tests.

1. Peak concurrent active sessions: 2% to 5% of MAU.
2. Average requests per active session per hour: 6 to 20.
3. Multi-agent fan-out ratio per user request: 1 to 5 downstream calls.
4. Cost and audit event generation: 1 event per major workflow step.
5. Burst factor during incidents or launches: 3x normal traffic.

## 5. Pain Points Addressed

1. Fragmented agent identity and weak ownership accountability
2. Lost delegation lineage in multi-hop workflows
3. Inconsistent registration process across teams
4. Missing visibility of owner in operational UI
5. Difficult discovery across runtime, code, and telemetry systems
6. Duplicate identities and conflicting metadata across sources
7. Long-running workflow failures without resume support
8. Weak quality gates for non-deterministic agent behavior
9. High token and tool cost without value-based controls
10. Delayed cost reporting that prevents fast remediation

## 6. Product Scope

### 6.1 Core capabilities

1. Agent Registry
2. Owner Management
3. Multi-Source Discovery
4. Agent Runtime and Orchestration
5. Tool and Model Gateways
6. Evaluation and Scan Services
7. Observability and Audit Console
8. Real-Time Cost Intelligence

### 6.2 Key product surfaces

1. Agent Builder (no-code and low-code)
2. Agent Studio (operations and diagnostics)
3. API-first control plane

### 6.3 Modular capability model

Each agent is assembled from reusable modules.

1. Identity module
2. Planning and orchestration module
3. Tool integration module
4. Model interaction module
5. Memory and checkpoint module
6. Policy and guardrail module
7. Observability module
8. Cost-control module
9. Evaluation module

Each module must declare:

1. Module name and version
2. Required inputs and produced outputs
3. Security scope and permissions
4. Latency and cost profile
5. Failure and retry behavior

### 6.4 Agent-readable modular map

Use this map as the canonical module index for implementation agents.

1. MOD-REG: Agent registration and ownership
Scope: sections 7.1/7.2/7.13, UI 8.1/8.2/8.3/8.5/8.12, APIs 1-4 and 49-54.

2. MOD-DISC: Multi-source discovery
Scope: section 7.3, UI 8.4, APIs 5-9.

3. MOD-RUNTIME: Runtime governance
Scope: section 7.4, APIs 10-11 and runtime-related gateway APIs.

4. MOD-RELIABILITY: Quality and resilience
Scope: section 7.5, rollout section 12.

5. MOD-COST: Real-time cost intelligence
Scope: section 7.6, UI 8.6, APIs 12-17.

6. MOD-EXT: Module lifecycle and compatibility
Scope: section 7.7, UI 8.7, APIs 18-22.

7. MOD-GATEWAY: Gateway compatibility and key management
Scope: sections 7.8/7.11/7.12, UI 8.8/8.10/8.11, APIs 23-32 and 38-56.

8. MOD-OBS: Observability and logging
Scope: section 7.9, UI 8.9, APIs 33-35.

9. MOD-COMP: Compliance control model and evidence
Scope: section 7.10, APIs 36-37, data models 10.11-10.12.

### 6.5 Agent implementation contract

Any implementation agent should process this document in the following order.

1. Build module boundaries from section 6.4.
2. Implement functional requirements from section 7 in module order.
3. Bind UI requirements from section 8 to the same module IDs.
4. Implement APIs from section 9 and validate against section 10 data models.
5. Validate KPI/SLO and rollout gates from sections 11 and 12.
6. Validate risk controls from section 16.
7. Run coverage checks from sections 17, 18, and 19.

## 7. Functional Requirements

### 7.1 Agent registration

1. Register agent with required owner and team.
2. Attach risk tier, environment, workload bindings, tools, and model profile.
3. Record immutable registration metadata.

### 7.2 Agent owner lifecycle

1. Show owner in list and detail views.
2. Transfer owner with reason and approval controls.
3. Support backup owner and ownership history.
4. Trigger notifications and audit events on ownership changes.

### 7.3 Multi-source discovery

1. Ingest agent evidence from multiple systems.
2. Normalize into a common schema.
3. Resolve duplicates with confidence scoring.
4. Promote discovered agents into official registry.
5. Alert for unmanaged or high-risk discovered agents.

### 7.4 Runtime governance

1. Use short-lived per-hop credentials.
2. Preserve actor chain in every hop.
3. Enforce policy at tool and model gateways.
4. Capture complete trace and audit records.

### 7.5 Quality and reliability

1. Run benchmarks before release.
2. Generate scan reports for risk posture.
3. Support checkpoint and resume for long sessions.
4. Provide progressive rollout controls.

### 7.6 Real-time cost evaluation and tracking

1. Track inference, tool, and orchestration cost at request, session, agent, team, and environment levels.
2. Compute live estimated spend and variance against budgets.
3. Enforce budget policies with soft warnings and hard stops.
4. Trigger alerts for cost anomalies and runaway sessions.
5. Publish near-real-time cost events to dashboards and APIs.

### 7.7 Agent extension and module lifecycle

1. Support module registration with semantic versioning.
2. Allow agent templates to reference modules by compatibility range.
3. Enforce module policy checks before activation.
4. Validate module contract compatibility during upgrades.
5. Support module deprecation with migration guidance and timelines.

### 7.8 Gateway compatibility and feature parity requirements

1. Provide OpenAI-compatible gateway APIs for drop-in client migration.
2. Support endpoint families: chat completions, responses, embeddings, images, audio, batches, rerank, messages, A2A, and MCP gateway access.
3. Support provider routing, weighted load balancing, retries, and fallbacks.
4. Support virtual keys with per-user, per-team, and per-project policy scopes.
5. Support budget and rate-limit policies at key, team, project, and tenant levels.
6. Support centralized guardrails: safety checks, policy checks, and PII masking.
7. Support configurable caching with privacy-aware cache modes.
8. Support external observability callbacks and sinks.
9. Provide gateway debugging support, including request transformation visibility.
10. Support enterprise auth integration including SSO and SAML options.
11. Support pluggable workload identity federation for workload credentials and cross-account role assumption (including cloud STS where available).
12. Support pluggable secret provider integration for secret material, dynamic credentials, and key rotation workflows (including HashiCorp Vault where available).

### 7.9 End-to-end observability and logging requirements

1. Capture structured logs, traces, and metrics at every lifecycle step: registration, discovery, planning, tool use, model calls, policy checks, cost actions, and deployment actions.
2. Enforce a common telemetry schema with required correlation fields: request_id, trace_id, span_id, session_id, agent_id, owner_scope, environment, policy_version, and decision_outcome.
3. Emit immutable audit events for all control-plane mutations and high-risk runtime actions.
4. Support log levels and sampling policies by environment without losing audit-critical records.
5. Support privacy-aware logging: masking, tokenization, and redaction for sensitive data.
6. Provide near-real-time alerting for security, reliability, and budget anomalies.
7. Ensure every user-visible action is traceable to a machine-readable event and owner scope.

### 7.10 Compliance control model requirements

1. Define a controls catalog mapped to platform capabilities for security, privacy, access, change management, and auditability.
2. Tag each API, module, and workflow step with applicable control IDs.
3. Produce machine-generated evidence artifacts for each control: logs, traces, approvals, policy decisions, and configuration snapshots.
4. Enforce policy-as-code checks in CI and pre-release gates for control compliance.
5. Support configurable retention, legal hold, and deletion policies by data class and jurisdiction.
6. Maintain evidence lineage from control requirement to runtime proof.

### 7.11 Model tryout and evaluation requirements

1. Provide a controlled model tryout workspace for prompt, tool-call, and response testing.
2. Support side-by-side model comparison for latency, quality indicators, and estimated cost.
3. Allow tryout runs with policy simulation mode before production route changes.
4. Capture full trace, token usage, and guardrail decisions for every tryout run.
5. Allow saving an approved tryout configuration as route policy draft.
6. Enforce role-based access for tryout execution and production promotion actions.

### 7.12 Route draft approval and promotion requirements

1. Define route-draft lifecycle states: draft, submitted, security_approved, aiops_approved, change_window_approved, promoted, rejected, and expired.
2. Require dual approval for production promotion: security approver and AI operations approver.
3. Require change-window validation before promote action for production scopes.
4. Block promotion when policy simulation, guardrail checks, or budget checks fail.
5. Require linked evidence: tryout run IDs, comparison reports, and risk assessment ticket.
6. Support explicit reject and rollback-to-draft actions with reason codes.
7. Emit immutable audit events for every state transition.

### 7.13 Identity federation and SSO requirements

1. Support SSO via OIDC and SAML for control-plane and UI access.
2. Support SCIM-based user and group provisioning with deterministic role mapping.
3. Enforce MFA for privileged roles: Platform Admin, Security Approver, and Release Manager.
4. Support JIT user provisioning with default least-privilege role assignment.
5. Support session controls: max session age, idle timeout, forced re-auth for high-risk actions.
6. Emit immutable identity and access audit events for login, token issue, role changes, and failed authorization.
7. Support per-tenant identity provider configuration and fail-safe rollback.
8. Support federated workload identity through token exchange with bounded session duration (STS adapter when configured).
9. Support secret-provider-backed secret retrieval with lease TTL and automatic renewal controls.
10. Support optional basic-auth fallback for emergency access, disabled by default and enabled only through time-bounded break-glass policy.

## 8. UI Requirements

### 8.1 Agent list view

Columns:

1. Agent name
2. Owner
3. Team
4. Risk tier
5. Status
6. Last deploy
7. Benchmark status
8. Discovery status

### 8.2 Agent detail view

Sections:

1. Registration metadata
2. Owner and ownership history
3. Discovery evidence and source confidence
4. Security posture
5. Benchmarks and scan reports
6. Runtime traces
7. Cost timeline, current session burn rate, and budget status

### 8.3 Registration wizard

Steps:

1. Identity
2. Ownership
3. Tools and model
4. Policy and risk
5. Review and create

Validation:

1. Owner is required.
2. Owner must be valid enterprise identity.
3. Production registration requires team and risk tier.
4. High-risk activation requires approval assignment.

### 8.4 Discovery console

Views:

1. Source connectors and sync health
2. Discovered agents queue
3. Conflict resolution queue
4. Promote-to-registry queue
5. Shadow agent alerts

### 8.5 Ownership transfer modal

Fields:

1. New owner
2. Backup owner
3. Reason
4. Effective date
5. Ticket reference

### 8.6 Cost operations console

Views:

1. Live spend by agent, owner, team, and environment
2. Cost per session and per workflow step
3. Budget utilization with forecast-to-limit
4. Cost anomaly feed with root-cause drilldown
5. Policy action log (warn, throttle, block)

### 8.7 Module catalog and compatibility view

Views:

1. Available modules by capability and maturity
2. Contract version compatibility matrix
3. Security and policy requirements per module
4. Performance and cost benchmark per module version
5. Recommended upgrade path and migration notes

### 8.8 Gateway operations and key management console

Views:

1. Virtual key creation, rotation, revocation, and scope assignment
2. Route policy editor with retries, load balancing, and fallback graph
3. Cache policy controls and cache hit analytics
4. Endpoint compatibility dashboard by client and model provider
5. Guardrail policy monitor and policy decision logs
6. Auth posture dashboard for SSO/SAML and key hygiene
7. Request transformation debugger for provider payload troubleshooting
8. Workload identity trust policy and token exchange health dashboard (STS adapter when configured)
9. Secret provider lease and rotation health dashboard (HashiCorp adapter when configured)

### 8.9 Observability and compliance console

Views:

1. End-to-end trace explorer by session, request, agent, and owner scope
2. Structured log explorer with schema validation status
3. Audit timeline for control-plane and runtime policy actions
4. Compliance evidence view mapped by control ID
5. Retention and redaction policy posture dashboard
6. Alert center with triage workflow and incident linkage

### 8.10 Model tryout playground

Views:

1. Prompt and input editor with reusable test sets
2. Provider and model selector with environment scope
3. Side-by-side output comparison with quality annotations
4. Token, latency, and estimated cost breakdown per run
5. Guardrail and policy decision panel for each run
6. Save-as-route-draft action with approval workflow link
7. Replay previous runs by trace ID for regression checks

### 8.11 Route draft approval workflow console

Views:

1. Draft pipeline board grouped by lifecycle state
2. Approval checklist panel (security, AI ops, change window, policy simulation)
3. Evidence viewer for tryout runs, side-by-side comparisons, and risk ticket links
4. Action controls: submit, approve, reject, request changes, promote
5. Approval history timeline with actor, timestamp, and reason code
6. Promotion readiness score and blocking conditions

### 8.12 Identity and access administration console

Views:

1. Identity provider setup for OIDC and SAML with test connection flow
2. SCIM provisioning status and drift alerts for groups and role mappings
3. Session policy controls and privileged-action re-auth settings
4. Role binding simulator with effective permission preview
5. Authentication and authorization failure dashboard by tenant and environment
6. Workload identity provider registration and token exchange diagnostics
7. Secret provider auth method mapping and secret path policy validation
8. Basic-auth fallback policy controls with temporary enable, expiry timer, and IP allowlist settings

## 9. API Requirements

1. POST /agents/register
2. PATCH /agents/{agent_id}/owner
3. GET /agents/{agent_id}/ownership-history
4. GET /owners/{owner_id}/agents
5. GET /discovery/sources
6. POST /discovery/sources/{source_id}/sync
7. GET /discovery/agents
8. POST /discovery/resolve
9. POST /discovery/promote/{discovered_agent_id}
10. POST /benchmarks/run
11. POST /scans/run
12. GET /cost/live
13. GET /cost/sessions/{session_id}
14. GET /cost/agents/{agent_id}
15. POST /cost/budgets
16. POST /cost/policies/evaluate
17. GET /cost/anomalies
18. POST /modules/register
19. GET /modules
20. GET /modules/{module_id}/versions
21. POST /agents/{agent_id}/modules/validate
22. POST /agents/{agent_id}/modules/upgrade-plan
23. POST /keys
24. PATCH /keys/{key_id}
25. POST /keys/{key_id}/rotate
26. GET /keys/{key_id}/usage
26a. POST /keys/{key_id}/guardrails/evaluate
27. POST /gateway/routes
28. GET /gateway/routes
29. POST /gateway/cache/policies
30. GET /gateway/cache/stats
31. GET /gateway/endpoints/compatibility
32. POST /gateway/debug/transform-request
33. GET /observability/traces/{trace_id}
34. GET /observability/logs
35. GET /audit/events
36. GET /compliance/controls
37. GET /compliance/evidence/{control_id}
38. POST /playground/runs
39. GET /playground/runs/{run_id}
40. POST /playground/compare
41. POST /playground/runs/{run_id}/route-draft
42. GET /playground/test-sets
43. POST /route-drafts/{draft_id}/submit
44. POST /route-drafts/{draft_id}/approve
45. POST /route-drafts/{draft_id}/reject
46. POST /route-drafts/{draft_id}/promote
47. GET /route-drafts/{draft_id}/approval-history
48. GET /route-drafts
49. POST /auth/sso/providers
50. PATCH /auth/sso/providers/{provider_id}
51. POST /auth/sso/providers/{provider_id}/test
52. POST /auth/sso/providers/{provider_id}/scim/sync
53. GET /auth/sessions/{session_id}
54. POST /auth/roles/bindings/validate
55. POST /agentic/contracts/validate
56. GET /agentic/readiness/report
57. POST /auth/workload-identity/providers
58. POST /auth/workload-identity/token-exchange
59. POST /secrets/providers
60. POST /secrets/providers/{provider_id}/test
61. GET /secrets/providers/{provider_id}/leases
62. POST /keys/{key_id}/rotate-via-secret-provider
63. POST /auth/basic/config
64. PATCH /auth/basic/config/{config_id}
65. POST /auth/basic/config/{config_id}/enable-temporary
66. POST /auth/basic/config/{config_id}/disable

Schema governance requirement:

1. Virtual key and guardrail schema updates must be delivered via Alembic revisions under `backend/alembic/versions`.
2. Model, API schema, UI, and documentation updates must land in the same change set for each schema revision.

### 9.1 Role-to-action permission matrix

Roles:

1. Platform Admin
2. Agent Owner
3. Security Approver
4. AI Ops Approver
5. Release Manager
6. Auditor

Endpoint permissions:

1. Registration and ownership APIs (1-4):
Platform Admin and Agent Owner write access; Auditor read-only for ownership history.

2. Discovery APIs (5-9):
Platform Admin and Agent Owner execute sync, resolve, and promote actions; Auditor read-only.

3. Benchmark and scan APIs (10-11):
Platform Admin, Agent Owner, and AI Ops Approver execute; Auditor read-only to resulting evidence.

4. Cost APIs (12-17):
Platform Admin and Agent Owner read; Platform Admin and Release Manager may update budgets and policy evaluation.

5. Module APIs (18-22):
Platform Admin write access; Agent Owner can request validate and upgrade-plan; Auditor read-only.

6. Key and gateway policy APIs (23-32):
Platform Admin write access; Security Approver co-approval required for rotate and route policy updates in production.

7. Observability and compliance APIs (33-37):
Platform Admin and Auditor read access; Agent Owner read access limited to owned scope.

8. Playground APIs (38-42):
Platform Admin, Agent Owner, and AI Ops Approver execute; Security Approver read access to policy outcomes.

9. Route draft approval APIs (43-48):
submit (43): Agent Owner or AI Ops Approver.
approve (44): Security Approver and AI Ops Approver.
reject (45): Security Approver, AI Ops Approver, or Release Manager.
promote (46): Release Manager only, after required approvals.
approval history and list (47-48): Platform Admin, Release Manager, Auditor, and scoped Agent Owner.

10. Identity federation APIs (49-54):
Platform Admin write access; Security Approver read access; Auditor read-only for auth/session evidence APIs.

11. Agentic validation APIs (55-56):
Platform Admin and Release Manager execute; Auditor read access to readiness report.

12. Workload-identity and secret-provider integration APIs (57-62):
Platform Admin write access; Security Approver approve/test access for production scopes; Auditor read-only on lease and rotation evidence views.

13. Basic-auth fallback APIs (63-66):
Platform Admin write access; Security Approver co-approval required for temporary enable in production; Auditor read-only for fallback event evidence.

Mandatory authorization rules:

1. Production-scoped promote requires dual approval evidence.
2. Approve and promote require actor-role separation from original draft submitter.
3. All deny decisions must return machine-readable reason codes.
4. Every privileged action emits audit event with actor_role and permission_policy_version.
5. Privileged control-plane actions require MFA claim verification.
6. Workload-identity and secret-provider integration changes in production require Security Approver co-sign.
7. Basic-auth fallback enable requires dual approval, explicit expiry, and immutable break-glass reason.

### 9.2 Authorization error contract

All protected APIs must return consistent authorization errors.

1. error_code
2. message
3. actor_role
4. required_role
5. policy_version
6. decision_trace_id
7. remediation_hint

## 10. Data Model Requirements

### 10.1 Agent

1. agent_id
2. name
3. owner_id
4. owner_name
5. owner_team
6. backup_owner_id
7. risk_tier
8. allowed_workloads
9. allowed_tools
10. allowed_models
11. status
12. created_at

### 10.2 Ownership event

1. event_id
2. agent_id
3. old_owner_id
4. new_owner_id
5. changed_by
6. reason
7. ticket_ref
8. changed_at

### 10.3 Discovery record

1. discovered_agent_id
2. canonical_agent_key
3. source_system
4. source_fingerprint
5. discovery_confidence
6. discovery_status
7. last_discovered_at
8. promoted_to_agent_id

### 10.4 Cost event

1. cost_event_id
2. timestamp
3. session_id
4. agent_id
5. owner_team
6. environment
7. component_type
8. component_ref
9. usage_units
10. unit_price
11. estimated_cost
12. currency

### 10.5 Budget policy

1. budget_policy_id
2. scope_type
3. scope_id
4. budget_amount
5. time_window
6. warning_threshold
7. hard_threshold
8. action_on_breach
9. created_at

### 10.6 Module definition

1. module_id
2. module_name
3. module_type
4. version
5. contract_version
6. owner_team
7. compatibility_range
8. required_permissions
9. status

### 10.7 Agent module mapping

1. agent_id
2. module_id
3. pinned_version
4. config_hash
5. validated_at
6. validation_status

### 10.8 Virtual key

1. key_id
2. key_hash
3. owner_scope_type
4. owner_scope_id
5. allowed_endpoint_families
6. allowed_models
7. budget_policy_id
8. rate_limit_policy_id
9. authn_method
10. status
11. expires_at
12. guardrail_policy

### 10.9 Route policy

1. route_policy_id
2. route_name
3. candidate_deployments
4. load_balancing_strategy
5. retry_policy
6. fallback_policy
7. timeout_policy
8. status

### 10.10 Cache policy

1. cache_policy_id
2. scope
3. ttl_seconds
4. key_strategy
5. invalidation_strategy
6. privacy_mode
7. status

### 10.11 Audit event

1. audit_event_id
2. timestamp
3. actor_type
4. actor_id
5. action_type
6. resource_type
7. resource_id
8. trace_id
9. decision_outcome
10. policy_version

### 10.12 Compliance control mapping

1. control_id
2. control_family
3. requirement_text
4. applicable_components
5. required_evidence_types
6. automation_status
7. owner_team
8. review_frequency

### 10.13 Model tryout run

1. run_id
2. created_at
3. created_by
4. tenant_id
5. environment
6. input_payload_hash
7. model_candidates
8. selected_model
9. route_policy_snapshot_id
10. token_usage
11. latency_ms
12. estimated_cost
13. guardrail_outcomes
14. policy_decision
15. trace_id
16. save_as_route_draft_status

### 10.14 Route draft approval event

1. approval_event_id
2. draft_id
3. state_from
4. state_to
5. actor_id
6. actor_role
7. decision
8. decision_reason_code
9. evidence_refs
10. change_window_id
11. policy_simulation_status
12. risk_ticket_ref
13. occurred_at

### 10.15 Authorization policy binding

1. binding_id
2. role_name
3. resource_pattern
4. action
5. environment_scope
6. conditions
7. effect
8. policy_version
9. effective_from
10. effective_to

### 10.16 Identity provider configuration

1. provider_id
2. tenant_id
3. protocol_type
4. issuer_or_entity_id
5. jwks_or_metadata_url
6. scim_base_url
7. role_mapping_rules
8. mfa_required_roles
9. session_policy_id
10. status
11. last_validated_at

### 10.17 Agentic readiness control record

1. readiness_record_id
2. release_id
3. module_id
4. control_domain
5. control_name
6. validation_status
7. evidence_refs
8. validated_by
9. validated_at
10. blocker_severity

### 10.18 Workload identity federation profile

1. workload_identity_profile_id
2. tenant_id
3. provider_type
4. audience
5. role_arn_or_equivalent
6. session_duration_seconds
7. allowed_subject_patterns
8. status
9. last_token_exchange_at

### 10.19 Secret provider config

1. secret_provider_id
2. tenant_id
3. provider_type
4. provider_address
5. auth_method
6. role_or_mount
7. secret_path_prefixes
8. lease_ttl_seconds
9. auto_renew_enabled
10. status
11. last_health_check_at

### 10.20 Basic auth fallback config

1. basic_auth_config_id
2. tenant_id
3. environment
4. enabled
5. allowed_user_groups
6. ip_allowlist
7. max_enable_duration_minutes
8. enabled_by
9. break_glass_reason
10. expires_at
11. last_toggled_at

## 11. KPIs and SLOs

KPIs:

1. Registration completion rate
2. Ownership completeness rate
3. Discovery coverage rate
4. Shadow agent rate
5. Conflict resolution time
6. Benchmark pass rate
7. Cost per successful outcome
8. Budget breach rate
9. Mean time to cost anomaly detection
10. Time to first agent in production
11. Module reuse ratio across agents
12. Upgrade success rate without rollback
13. Gateway endpoint compatibility pass rate
14. Virtual key policy compliance rate
15. Cache hit ratio for eligible requests
16. Active users supported at target SLO
17. Peak concurrency handled without SLO breach
18. Route draft approval cycle time
19. Promotion success rate without rollback
20. SSO login success rate
21. Agentic readiness pass rate before release
22. Workload identity token exchange success rate
23. Secret provider lease renewal success rate
24. Basic-auth fallback activation count

SLOs:

1. Discovery sync success >= 99%
2. Ownership update propagation <= 5 minutes
3. Trace completeness >= 99.9%
4. Cost pipeline freshness <= 60 seconds
5. Cost anomaly detection <= 2 minutes
6. Module compatibility validation p95 <= 2 seconds
7. Gateway route decision p95 <= 100 ms
8. Virtual key authz decision p95 <= 50 ms
9. Audit event publication lag <= 30 seconds
10. Compliance evidence freshness <= 24 hours
11. Route-draft promotion API p95 <= 300 ms
12. Route-draft approval history query p95 <= 500 ms
13. SSO login flow success >= 99.5%
14. Authorization decision latency p95 <= 75 ms
15. Workload identity token exchange p95 <= 200 ms
16. Secret provider retrieval p95 <= 150 ms
17. Basic-auth fallback disable propagation <= 60 seconds

## 12. Rollout Plan

### Phase 0

1. Registration + ownership UI
2. Owner-required API validation
3. Initial audit logging
4. Starter agent template and module contract schema

### Phase 1

1. Discovery connectors (registry, runtime inventory, code metadata, gateway logs, and cloud product sources for AWS/Azure/GCP)
2. Discovery console and conflict queue
3. Promote-to-registry flow
4. Module catalog, AI Skills Registry, and compatibility validator
5. Gateway compatibility APIs and virtual key service
6. Scale tier 1 certification for 10k users
7. Workload identity provider baseline (STS optional) and secret provider integration baseline
8. Basic-auth fallback break-glass workflow validation

### Phase 2

1. Benchmarks and scans integrated into release process
2. Checkpoint and resume controls
3. Progressive deployment controls
4. Real-time cost pipeline and cost operations console
5. Route, fallback, and cache policy controls in gateway operations UI
6. Scale tier 2 certification for 50k users

### Phase 3

1. Advanced confidence tuning
2. Cost and value optimization
3. Automated risk-adaptive policy behaviors
4. Predictive spend forecasting and preemptive throttling
5. Scale tier 3 certification for 100k users

## 12.1 Minimal Rework Development Model

The program must optimize for first-time-right delivery and controlled change.

1. Definition of ready gate (before implementation)
Requirements, API contracts, data models, control IDs, and success metrics must be finalized and approved.

2. Interface freeze windows
API and event contract changes are blocked during active sprint execution except for critical fixes.

3. Change budget policy
Each release train has a capped percentage of scope allowed for requirement changes after sprint start.

4. One-way traceability
Every feature maps to module ID, API IDs, data entities, tests, and rollout gates.

5. Early validation gates
Contract tests, policy tests, and compatibility tests must pass before merge.

6. Rework prevention in planning
No implementation starts without explicit dependency closure and ownership assignment.

7. Design decision records
All non-trivial decisions require ADR entries with alternatives and rollback criteria.

8. Controlled exception path
Urgent exceptions must include impact analysis, owner approval, and post-release remediation tasks.

9. Mandatory development competency coverage
Implementation planning must include explicit coverage from security design, system design, cloud architecture, Python engineering, gateway engineering, and compliance review responsibilities.

## 12.2 Phase-wise Development Breakup and Requirement Traceability

Use this as the mandatory development breakdown and documentation mapping reference.

### Phase 0: Foundation and access controls

1. Primary development outcomes:
Registration, ownership, baseline identity federation, authorization policy binding, and audit foundations.

2. Requirement mapping:
Functional requirements: 7.1, 7.2, 7.13.
UI requirements: 8.1, 8.2, 8.3, 8.5, 8.12.
API requirements: 1-4, 49-54, 63-66 (basic-auth fallback optional and disabled by default).
Data model requirements: 10.1, 10.2, 10.11, 10.15, 10.16, 10.20.
Architecture references: sections 5.1, 5.2, 6.7, 6.8, 6.11, 10.1, 11.

3. Mandatory exit criteria:
Security signoff, SSO flow validation, authorization policy validation, and immutable audit coverage.

### Phase 1: Discovery, gateway foundations, and provider integrations

1. Primary development outcomes:
Discovery ingestion, module lifecycle foundation, gateway compatibility baseline, workload identity integration, and secret provider integration.

2. Requirement mapping:
Functional requirements: 7.3, 7.7, 7.8, 7.13 (items 8-10 where configured).
UI requirements: 8.4, 8.7, 8.8, 8.12 (items 6-8).
API requirements: 5-9, 18-32, 57-62.
Data model requirements: 10.3, 10.6, 10.7, 10.8, 10.9, 10.10, 10.18, 10.19.
Architecture references: sections 4.1-4.4, 6.2, 6.10, 9.1, 9.2, 17.

3. Mandatory exit criteria:
Endpoint parity baseline pass, discovery confidence thresholds operational, and provider integration evidence recorded.

### Phase 2: Reliability, cost intelligence, observability, and controlled promotion

1. Primary development outcomes:
Benchmark and scan automation, checkpoint/resume, cost intelligence, model tryout, route draft workflow, and observability controls.

2. Requirement mapping:
Functional requirements: 7.4, 7.5, 7.6, 7.9, 7.11, 7.12.
UI requirements: 8.6, 8.9, 8.10, 8.11.
API requirements: 10-17, 33-48.
Data model requirements: 10.4, 10.5, 10.13, 10.14, 10.17.
Architecture references: sections 6.5, 6.6, 7, 7.2, 10, 10.1, 10.3, 14.

3. Mandatory exit criteria:
Route promotion governance pass, cost anomaly detection targets met, and observability/compliance coverage complete.

### Phase 3: Optimization, scale certification, and release hardening

1. Primary development outcomes:
Advanced routing optimization, risk-adaptive policy automation, predictive spend controls, and 100k-scale certification.

2. Requirement mapping:
Functional requirements: 7.6-7.13 optimization and hardening extensions.
UI requirements: optimization across 8.6-8.12 surfaces.
API requirements: all production APIs with emphasis on 55-56 readiness controls.
Data model requirements: 10.17 plus all operational entities required for scale and evidence continuity.
Architecture references: sections 6.9, 13, 13.1, 13.2, 15.1, 20, 21.7.

3. Mandatory exit criteria:
Tier-3 scale certification, no unresolved critical readiness controls, and final compliance signoff.

## 13. Agent Developer Experience Blueprint

The platform should minimize agent build time with a standard delivery path.

1. Start from a reference template
Generate a production-ready scaffold with pre-wired identity, policy, telemetry, and cost hooks.

2. Compose from module catalog
Select approved modules instead of custom wiring for common capabilities.

3. Validate contracts early
Run local and CI module compatibility checks before deployment.

4. Use scenario packs
Run standard reliability, security, and cost test suites per agent type.

5. Ship with release guardrails
Require benchmark pass, policy pass, and budget policy checks before rollout.

6. Use deterministic implementation order
Follow module IDs and execution order strictly to avoid dependency churn.

7. Prefer extension over modification
Add capabilities via module extensions instead of editing stable core contracts.

## 14. Documentation and Handoff Standard

Each new agent and module must include:

1. One-page intent summary
2. Input and output contract
3. Dependency and permission manifest
4. Failure modes and recovery actions
5. Cost expectations and budget policy
6. Owner and escalation path

## 15. AI Gateway Technology Review and Adoption Criteria

This section defines how external gateway technologies are evaluated and adopted.

### 15.1 Evaluation summary

A unified model gateway solution provides strong acceleration for:

1. Multi-provider API standardization
2. Gateway-level routing and fallback
3. Key-level spend tracking and rate controls
4. Guardrail and observability integrations
5. OpenAI-compatible client interoperability

### 15.2 Required fit criteria

A gateway technology is acceptable only if it satisfies:

1. Contract compatibility:
Must map cleanly to platform contracts for policy, trace, cost, and module lifecycle.

2. Security compatibility:
Must support per-tenant isolation, key scoping, auditability, and enterprise auth integration.

3. Cost data quality:
Must expose request-level cost and usage telemetry with low-latency export paths.

4. Policy control parity:
Must support deny, warn, throttle, and block controls that align with platform governance rules.

5. Extensibility:
Must integrate through adapters, without coupling core domain logic to vendor-specific APIs.

### 15.3 Adoption constraints

1. Treat external gateway as infrastructure adapter, not core domain source of truth.
2. Keep ownership, policy intent, and compliance decisions in platform services.
3. Preserve abstraction boundary so gateway implementations are replaceable.
4. Require canary rollout and rollback plan before production expansion.

### 15.4 Delivery model

1. Phase A: sandbox integration
Validate routing, observability, and cost parity.

2. Phase B: limited production
Run selected low-risk workloads with strict budget guards.

3. Phase C: controlled scale-up
Expand by tenant and workflow category, with SLO and anomaly gates.

4. Phase D: steady-state operations
Use ongoing scorecards for reliability, security posture, and cost efficiency.

## 16. Risks and Mitigations

1. Duplicate identity collisions
Mitigation: canonical keys + confidence thresholds + reviewer approval.

2. Ownership drift
Mitigation: periodic ownership reconciliation and stale-owner alerts.

3. Shadow agent growth
Mitigation: discovery alerts + mandatory promotion workflow for production use.

4. Cost runaway
Mitigation: budget caps, value-based routing, and cost anomaly alerts.

5. False-positive anomaly alerts
Mitigation: adaptive baselines, environment-aware thresholds, and suppression windows.

6. Gateway compatibility drift across endpoint families
Mitigation: automated compatibility tests for every supported endpoint family in CI and pre-release.

7. Virtual key sprawl and stale credentials
Mitigation: lifecycle policies, rotation SLAs, and stale-key revocation jobs.

8. Cache privacy or policy leakage
Mitigation: privacy-aware cache modes and strict policy validation for sensitive workloads.

9. Logging blind spots in critical workflow steps
Mitigation: mandatory per-step telemetry contract and trace coverage gates.

10. Compliance evidence gaps at audit time
Mitigation: automated evidence pipelines with daily completeness checks and ownership alerts.

11. Development churn and rework spikes
Mitigation: definition-of-ready gate, interface freeze windows, and change budget policy.

12. Late contract changes causing cross-team regressions
Mitigation: contract governance board, semantic versioning rules, and migration playbooks.

13. Capacity underestimation at higher user tiers
Mitigation: quarterly load-model recalibration and scale certification before each tier increase.

14. Misuse of temporary basic-auth fallback
Mitigation: disabled-by-default posture, dual approval, strict expiry, IP allowlist, and mandatory audit review.

## 17. Gateway Feature Parity Checklist

This checklist defines 100% coverage for the reviewed gateway capability set.

1. Unified API compatibility: covered
2. OpenAI-compatible client support: covered
3. Endpoint family coverage: covered
4. Multi-provider routing and load balancing: covered
5. Retries and fallbacks: covered
6. Virtual key management: covered
7. Budget and rate-limit controls: covered
8. Spend tracking and real-time cost telemetry: covered
9. Guardrails and PII masking: covered
10. Caching and cache policy controls: covered
11. Observability callbacks and sinks: covered
12. Admin dashboard and operations console: covered
13. A2A and MCP gateway support: covered
14. Request transformation debugging: covered
15. Enterprise auth posture (SSO/SAML capable): covered
16. Audit logs and governance controls: covered
17. Adapter-based replaceability and no core lock-in: covered

## 18. LiteLLM API Case Coverage Matrix

This matrix maps reviewed LiteLLM API cases to design coverage.

1. /chat/completions: covered in endpoint family support and gateway compatibility.
2. /responses and /responses/compact: covered in endpoint family support.
3. /completions (text completion): covered in endpoint family support.
4. /embeddings: covered in endpoint family support.
5. /images and /images/edits and image variations: covered in endpoint family support.
6. /audio/speech and /audio/transcriptions: covered in endpoint family support.
7. /batches: covered in endpoint family support.
8. /rerank: covered in endpoint family support.
9. /v1/messages and /v1/messages/count_tokens: covered in endpoint family support and token telemetry.
10. /moderations and /guardrails/apply_guardrail: covered in guardrail and policy modules.
11. /a2a and agent invocation APIs: covered in gateway endpoint support and A2A parity checklist.
12. /mcp and mcp-rest tool list and call: covered in endpoint family support and MCP parity checklist.
13. /realtime and WebRTC realtime support: covered as gateway endpoint family with route and auth controls.
14. /assistants and managed agent endpoints: covered as compatibility-layer endpoint families.
15. /files, /fine_tuning, /vector_stores, /search, /rag/ingest, /rag/query: covered as supported endpoint families in compatibility layer.
16. Pass-through endpoint families: covered by compatibility layer and transform-request debugging API.
17. Key and auth management API cases: covered by key lifecycle APIs and virtual key model.
18. Budget and rate-limit API cases: covered by budget policy and key scope controls.
19. Logging and metrics API cases: covered by observability APIs and compliance evidence APIs.
20. Route, fallback, A/B mirroring, and caching policy APIs: covered by route and cache policy APIs.

Status:

1. Reviewed API cases: covered at design level.
2. Implementation sequencing: controlled by rollout phases and compatibility tests.

## 19. Observability and Compliance Coverage Checklist

1. Structured logs at every workflow step: covered
2. Distributed tracing with required correlation fields: covered
3. Immutable audit events for sensitive mutations: covered
4. Redaction and privacy-aware logging controls: covered
5. Alerting and incident linkage for critical anomalies: covered
6. Control catalog mapped to APIs/modules/workflows: covered
7. Automated evidence generation and retrieval APIs: covered
8. Retention and legal-hold policy support: covered
9. Evidence freshness and completeness SLOs: covered

## 20. Rework Control KPIs

1. Rework ratio:
Percent of completed stories reopened after merge.

2. Post-freeze change rate:
Count of contract or requirement changes after sprint freeze.

3. First-pass acceptance rate:
Percent of stories accepted without rollback or major redesign.

4. ADR coverage:
Percent of high-impact changes with approved ADRs.

5. Contract breakage rate:
Number of incompatible API or event changes per release.

## 21. Multi-Perspective Review and Development Directive

This section converts review findings into build requirements.

### 21.1 Security engineer perspective

Findings and required development actions:

1. Enforce tenant and environment isolation at API, queue, and storage boundaries.
2. Add mandatory mTLS for service-to-service traffic and short-lived workload identities.
3. Require policy decision logs for all allow and deny outcomes with immutable audit records.
4. Enforce key lifecycle controls: rotation SLA, stale key revocation, and break-glass approvals.
5. Add secrets scanning and dependency vulnerability gates in CI.
6. Implement security incident workflows with trace-to-audit linkage.

### 21.2 AI engineer perspective

Findings and required development actions:

1. Add model policy profiles by workload class (low risk, regulated, restricted).
2. Enforce prompt and response guardrails with configurable deny, redact, and fallback actions.
3. Track model quality with offline eval packs and online outcome metrics.
4. Add deterministic fallback trees for provider/model failures.
5. Add drift detection for quality, safety, and cost with auto-alerts.
6. Require experiment metadata for model and prompt changes.

### 21.3 UI engineer perspective

Findings and required development actions:

1. Add role-based UI views for owner, reviewer, operator, and auditor personas.
2. Standardize critical workflows: register, approve, promote, rollback, and evidence export.
3. Add inline policy and budget warnings before risky actions.
4. Add per-step trace visualization with cost and policy outcomes.
5. Add accessibility gates (WCAG 2.2 AA) in release criteria.
6. Add design tokens and component contracts to reduce UI rework.

### 21.4 Data engineer perspective

Findings and required development actions:

1. Define canonical event schemas for agent, gateway, policy, and cost events.
2. Enforce schema versioning and compatibility checks for all producers and consumers.
3. Add data quality SLOs: freshness, completeness, uniqueness, and lineage coverage.
4. Add PII classification and field-level retention policies.
5. Add replay-safe idempotency for event ingestion and reconciliation jobs.
6. Implement data product contracts for reporting and compliance evidence.

### 21.5 Gateway engineer perspective

Findings and required development actions:

1. Keep endpoint-family parity tests mandatory in CI and pre-release.
2. Implement policy-aware route selection with deterministic fallback.
3. Add virtual key scoping by tenant, environment, and workload type.
4. Enforce timeout, retry, circuit-breaker, and cache policy standards.
5. Add transform-debug traces with strict redaction controls.
6. Add gateway performance budgets for route decision and authz latency.

### 21.6 Python engineer perspective

Implementation requirements for fast, low-rework delivery:

1. Standard runtime stack:
Python 3.12, FastAPI, Pydantic v2, SQLAlchemy, Alembic, asyncio-based workers.

2. Contract package:
Shared typed models for API and event schemas used by control plane and workers.

3. Project structure:
domain, application, interfaces, infrastructure, modules, tests.

4. Test gates:
unit, contract, integration, policy, compatibility, and load smoke tests.

5. CI quality gates:
type checks, linting, security scan, schema compatibility, and migration validation.

6. Operational standards:
OpenTelemetry tracing, structured logs, and metric naming conventions from day one.

### 21.7 Delivery increments (develop it)

1. Sprint A:
Security and data foundations, contract package, and baseline gateway endpoints.

2. Sprint B:
AI guardrails, UI role workflows, and cost telemetry pipeline.

3. Sprint C:
Advanced routing, policy automation, evidence exports, and scale hardening.

## 22. Agentic Design Readiness Standard (100% Gate)

A release is considered 100% agentic-ready only when all gates pass.

1. Security gate:
Identity federation configured, MFA enforced for privileged actions, and zero critical vulnerabilities.

2. AI gate:
Guardrail coverage complete, fallback DAG validated, and drift monitors active.

3. SSO gate:
OIDC or SAML login validated in target environment and SCIM mappings reconciled.

3a. Basic-auth fallback gate (optional):
If enabled for emergency use, break-glass controls, expiry enforcement, and alerting must be validated.

4. Gateway gate:
Endpoint-family parity tests pass and route policy rollback path validated.

5. Python engineering gate:
Type checks, contract tests, migration checks, and load smoke tests pass.

6. System architecture gate:
Contract compatibility, observability completeness, and evidence freshness SLOs are all compliant.

7. Compliance gate:
Control mappings are complete for changed capabilities, required evidence artifacts are generated, and compliance signoff is recorded before release.

## 23. Development Execution Plan (Proceeding Work)

This section is the immediate development plan to start execution from the documented baseline.

### 23.1 Sprint 0 (Week 0-1) setup and governance

1. Finalize ownership model for all modules in section 6.4.
2. Freeze Phase 0 contracts and API schemas listed in section 12.2.
3. Create implementation repositories and baseline CI with required quality gates.
4. Enable traceability template requiring links to requirement, API, data model, and architecture section.

Exit criteria:

1. Definition-of-ready checklist signed.
2. CI quality gates active.
3. Requirement-to-doc traceability template mandatory in PR workflow.

### 23.2 Phase 0 execution backlog (Weeks 1-3)

1. EPIC-P0-REG: registration and ownership APIs/UI.
Scope: APIs 1-4, UI 8.1/8.2/8.3/8.5, data 10.1/10.2.

2. EPIC-P0-IDENT: identity federation and access baseline.
Scope: APIs 49-54 and 63-66 (if fallback enabled), UI 8.12, data 10.15/10.16/10.20.

3. EPIC-P0-AUDIT: immutable audit and authorization telemetry.
Scope: APIs 35 and 53, data 10.11, observability requirements 7.9.

Exit criteria:

1. Authentication and authorization test suites pass.
2. Audit trail validated for all privileged actions.
3. Phase 0 requirements mapped and signed off.

### 23.3 Phase 1 execution backlog (Weeks 3-6)

1. EPIC-P1-DISC: discovery ingestion and conflict resolution.
Scope: APIs 5-9, UI 8.4, data 10.3.

2. EPIC-P1-MODULE: module registry and compatibility baseline.
Scope: APIs 18-22, UI 8.7, data 10.6/10.7.

3. EPIC-P1-GW-BASE: gateway endpoint parity and key controls baseline.
Scope: APIs 23-32, UI 8.8, data 10.8/10.9/10.10.

4. EPIC-P1-PROVIDER: workload identity and secret provider adapters.
Scope: APIs 57-62, UI 8.8/8.12, data 10.18/10.19.

Exit criteria:

1. Endpoint parity baseline report published.
2. Discovery confidence and promotion flow validated.
3. Provider integration evidence captured.

### 23.4 Phase 2 execution backlog (Weeks 6-10)

1. EPIC-P2-RELIABILITY: benchmark, scan, checkpoint and resume controls.
Scope: APIs 10-11, functional 7.5.

2. EPIC-P2-COST: real-time cost intelligence and anomaly control loop.
Scope: APIs 12-17, UI 8.6, data 10.4/10.5.

3. EPIC-P2-TRYOUT: model tryout and route draft pipeline.
Scope: APIs 38-48, UI 8.10/8.11, data 10.13/10.14.

4. EPIC-P2-OBS-COMP: observability and compliance evidence automation.
Scope: APIs 33-37, UI 8.9, data 10.11/10.12/10.17.

Exit criteria:

1. Promotion governance path validated end-to-end.
2. Cost and observability SLO targets passing in staging.
3. Compliance evidence generation proven for changed controls.

### 23.5 Phase 3 execution backlog (Weeks 10-14)

1. EPIC-P3-OPT: route and policy optimization features.
2. EPIC-P3-SCALE: 100k readiness and multi-region resilience certification.
3. EPIC-P3-READINESS: release gate automation for section 22 controls.

Exit criteria:

1. Tier-3 scale certification completed.
2. All section 22 gates pass with signed readiness report.
3. Compliance signoff recorded for production cutover.

### 23.6 Mandatory requirement mapping in implementation artifacts

Every story and PR must include:

1. Product requirement link (section 7/8/9/10/11/12/22).
2. Architecture link (section 4-15/21).
3. API contract IDs touched.
4. Data model entities touched.
5. Test evidence and compliance evidence references.

### 23.7 Phase 0 story-level development plan

1. STORY-P0-REG-001: Create agent registration API and persistence flow.
Maps: functional 7.1, API 1, data 10.1, architecture 5.1.
Acceptance criteria: successful create flow, idempotency behavior documented, audit event emitted.

2. STORY-P0-REG-002: Implement ownership transfer workflow.
Maps: functional 7.2, API 2-4, data 10.2, architecture 5.2.
Acceptance criteria: ownership transfer requires reason, ownership history query works, notification and audit emitted.

3. STORY-P0-IDENT-001: Configure SSO provider setup and validation endpoints.
Maps: functional 7.13, API 49-51, data 10.16, architecture 6.8.
Acceptance criteria: provider create and test supported per tenant, failure mode logged, rollback supported.

4. STORY-P0-IDENT-002: Implement SCIM sync and role binding validation.
Maps: functional 7.13, API 52 and 54, data 10.15/10.16, architecture 6.7 and 6.8.
Acceptance criteria: deterministic mapping applied, invalid mappings rejected with reason codes.

5. STORY-P0-IDENT-003: Build optional basic-auth fallback control APIs.
Maps: functional 7.13 item 10, API 63-66, data 10.20, architecture 6.11.
Acceptance criteria: fallback is disabled by default, enable requires dual approval and expiry, disable path tested.

6. STORY-P0-AUDIT-001: Enforce immutable audit events for privileged actions.
Maps: functional 7.9 and 7.10, API 35 and 53, data 10.11, architecture 10 and 11.
Acceptance criteria: all privileged actions include actor role, policy version, and trace ID.

### 23.8 Definition of Done for phase promotion

A phase can be marked complete only when all conditions are true.

1. All mapped stories have passing tests and merged code.
2. All listed APIs have contract tests and compatibility evidence.
3. All listed data entities have migration scripts and rollback plan.
4. Security and compliance signoff is attached for changed controls.
5. Observability dashboards and alerts are active for new capabilities.
6. Readiness report in section 22 gates is signed and archived.

### 23.9 Phase 1 story-level development plan

1. STORY-P1-DISC-001: Build connector ingestion jobs and cursor-based sync.
Maps: functional 7.3, API 5-6, data 10.3, architecture 4.1 and 4.2.
Acceptance criteria: connector health visible, incremental sync stable, retries and rate limits enforced.

2. STORY-P1-DISC-002: Build discovery queue, conflict resolution, and promotion flow.
Maps: functional 7.3, API 7-9, UI 8.4, data 10.3, architecture 4.2.
Acceptance criteria: confidence thresholds applied, conflict queue actions auditable, promote-to-registry path validated.

3. STORY-P1-MOD-001: Implement module registry and version compatibility checks.
Maps: functional 7.7, API 18-22, UI 8.7, data 10.6 and 10.7, architecture 7.1.
Acceptance criteria: semantic version constraints enforced, upgrade impact report generated.

4. STORY-P1-GW-001: Implement gateway key and route policy baseline.
Maps: functional 7.8, API 23-30, UI 8.8, data 10.8/10.9/10.10, architecture 6.2.
Acceptance criteria: key scope validation, route policy CRUD, retry/fallback policy checks.

5. STORY-P1-GW-002: Implement endpoint compatibility and transform debugging.
Maps: functional 7.8, API 31-32, UI 8.8, architecture 17 and 19.
Acceptance criteria: endpoint family coverage report generated, transform debug path redaction-safe.

6. STORY-P1-PROV-001: Implement workload identity provider and token exchange adapters.
Maps: functional 7.8 and 7.13, API 57-58, data 10.18, architecture 6.10.
Acceptance criteria: provider onboarding and token exchange pass policy checks and audit hooks.

7. STORY-P1-PROV-002: Implement secret provider onboarding and lease operations.
Maps: functional 7.8 and 7.13, API 59-62, data 10.19, architecture 6.10.
Acceptance criteria: lease lifecycle visible, rotation via provider path tested, failure handling validated.

### 23.10 Phase 2 story-level development plan

1. STORY-P2-REL-001: Integrate benchmark and scan orchestration.
Maps: functional 7.5, API 10-11, architecture 7 and 14.
Acceptance criteria: benchmark and scan results gate release paths.

2. STORY-P2-REL-002: Implement checkpoint and resume execution control.
Maps: functional 7.5, architecture 7 and 14.
Acceptance criteria: resume from latest valid checkpoint, replay behavior deterministic.

3. STORY-P2-COST-001: Implement real-time cost ingestion and anomaly detection.
Maps: functional 7.6, API 12-17, UI 8.6, data 10.4 and 10.5, architecture 7.2.
Acceptance criteria: freshness SLO achieved, anomaly actions auditable and policy-driven.

4. STORY-P2-TRY-001: Implement model tryout run and compare flows.
Maps: functional 7.11, API 38-42, UI 8.10, data 10.13, architecture 6.5.
Acceptance criteria: tryout traces include token, latency, cost, and policy decisions.

5. STORY-P2-PROM-001: Implement route draft approval and promotion workflow.
Maps: functional 7.12, API 43-48, UI 8.11, data 10.14, architecture 6.6.
Acceptance criteria: dual approval and separation-of-duties enforced, rollback path validated.

6. STORY-P2-OBS-001: Implement trace/log/audit exploration and compliance evidence automation.
Maps: functional 7.9 and 7.10, API 33-37, UI 8.9, data 10.11/10.12/10.17, architecture 10 and 10.3.
Acceptance criteria: evidence completeness checks pass for changed controls.

### 23.11 Phase 3 story-level development plan

1. STORY-P3-OPT-001: Implement adaptive route optimization and policy tuning.
Maps: functional 7.6 and 7.8, architecture 21.5.
Acceptance criteria: optimization does not violate policy, cost and latency targets improve.

2. STORY-P3-SCALE-001: Execute tier-3 load certification and failure-injection tests.
Maps: sections 4.1, 11, 12, architecture 13 and 13.2.
Acceptance criteria: 100k tier tests pass with no critical control regressions.

3. STORY-P3-READINESS-001: Automate release gate evaluation and signed readiness report.
Maps: section 22, API 55-56, data 10.17, architecture 6.9 and 21.7.
Acceptance criteria: release blocked on unresolved critical controls, signoff workflow auditable.

### 23.12 Execution cadence and reporting

1. Weekly architecture and compliance checkpoint: requirement mapping, risk review, and control evidence status.
2. End-of-phase review: exit criteria verification and readiness gate pre-check.
3. Mandatory release packet: test report, parity report, control evidence index, and signed readiness report.

### 23.13 API implementation sequence (development order)

1. Identity and access APIs first:
1-4, 49-54, and 63-66.

2. Discovery and module lifecycle APIs second:
5-9 and 18-22.

3. Gateway and provider APIs third:
23-32 and 57-62.

4. Reliability and cost APIs fourth:
10-17.

5. Tryout and promotion APIs fifth:
38-48.

6. Observability, compliance, and readiness APIs last:
33-37 and 55-56.

Rule:
No later API group starts production rollout until the prior group passes contract, security, and evidence checks.

### 23.14 Sprint tracker template (mandatory)

Every sprint should publish this tracker block.

1. Story ID and epic.
2. Requirement links (product and architecture sections).
3. API IDs and data entities touched.
4. Test status:
unit, contract, integration, security, performance.
5. Compliance evidence refs and control IDs.
6. Risk status:
open risks, mitigations, and owner.
7. Release decision:
ready, conditional, or blocked.

### 23.15 Authentication and directory security update (2026-06-06)

1. Password login now supports server-side account lockout after repeated failed attempts.
2. Lockout policy is operator-tunable through runtime config with bounded validation:
	- `auth.login.max_failed_attempts`
	- `auth.login.lockout_minutes`
3. Security operations can unlock locked directory users through a dedicated admin API:
	- `POST /auth/directory/users/{user_id}/unlock`
4. Unlock operations require privileged role and MFA and emit immutable audit evidence.
5. Successful logins clear lockout counters and update last login timestamp for governance reporting.
