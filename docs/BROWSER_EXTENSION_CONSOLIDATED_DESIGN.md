# Browser Extension Consolidated Design

Date: 2026-06-09
Scope: Consolidated design for enterprise browser-side AI security controls based on user-provided reference patterns.

Related market analysis: `docs/BROWSER_AI_SECURITY_VENDOR_DEEP_RESEARCH.md`

## 1. Objective

Design a browser extension and backend control-plane integration that:

- Detects and reduces prompt/data leakage to third-party GenAI apps.
- Monitors and governs user interactions with AI web apps in real time.
- Surfaces shadow AI usage and risky browser extension behavior.
- Enforces enterprise policies with auditable outcomes.
- Preserves productivity while failing closed for high-risk actions.

## 2. Reference Capability Themes (Consolidated)

From the referenced products and patterns, required capability clusters are:

1. Prompt security and DLP-style protection
- Detect sensitive prompt content before send.
- Mask/anonymize/redact content by policy.
- Block policy-violating submissions.

2. Real-time monitoring and logging
- Capture prompt destination, action type, and policy decision metadata.
- Stream telemetry to central governance service.

3. Shadow AI and browser-risk visibility
- Detect unapproved AI apps and extension risk posture.
- Identify unsanctioned uploads/downloads and data sharing behavior.

4. In-browser policy enforcement
- Apply tenant/role/environment policy at interaction time.
- Support soft controls (warn/challenge) and hard controls (deny).

5. Local-first assistant/automation controls
- Allow approved local automation workflows under guardrails.
- Bind automation to identity, scope, and audit evidence.

## 3. Product Problem Statement

Without browser-layer controls, users can bypass platform governance by directly interacting with external GenAI sites. This creates blind spots in:

- Data exfiltration prevention
- Policy enforcement
- Auditability and compliance
- Shadow AI risk detection

The extension closes this gap by moving enforcement and telemetry to the browser interaction boundary while keeping decision authority centralized.

## 4. Target Architecture

### 4.1 High-Level Components

1. Browser Extension (MV3)
- Content scripts for supported AI web apps and generic detectors.
- Prompt interception hooks (submit, paste, file attach, drag/drop).
- Local classification/redaction engine.
- Secure event sender to backend.

2. Extension Policy SDK
- Cached policy bundle with TTL and signature.
- Decision modes: `allow`, `warn`, `challenge`, `deny`, `mask`.
- Emergency policy update channel.

3. Backend Browser Governance API
- Session registration and heartbeat.
- Policy fetch/evaluate endpoints.
- Event ingest endpoint for prompt/action telemetry.
- Investigation and evidence export endpoints.

4. Control Plane UI
- Browser risk dashboard.
- Shadow AI app inventory.
- Prompt policy hit/deny timelines.
- Incident review and evidence export workflows.

### 4.2 Data Flow

1. User types prompt or attaches file in a monitored AI app.
2. Extension extracts minimal context and classifies content locally.
3. Extension enforces local allow/warn/block/mask policy immediately.
4. Decision + metadata sent to backend audit/event APIs.
5. Backend correlates with actor/session/tenant and stores evidence.
6. UI exposes events, trends, and incident investigation pivots.

## 5. Core Functional Requirements

### 5.1 Prompt Security

- Sensitive-pattern detection (PII, credentials, secrets, regulated terms).
- Context-aware masking templates.
- Policy-based destination allowlist/denylist for AI domains.
- Upload guardrails by file type, size, and data classification.

### 5.2 Interaction Monitoring

- Capture:
  - actor/session identity
  - destination app/domain
  - action type (prompt send, upload, download)
  - policy decision outcome
  - trace id and timestamp
- No raw secret storage in logs by default.

### 5.3 Shadow AI Discovery

- Domain/app fingerprinting for known AI services.
- Unsanctioned app detection and severity scoring.
- Optional enforcement mode: warn-only or block.

### 5.4 Extension Risk Governance

- Inventory installed extensions by risk labels (managed policy boundary).
- Flag unapproved extensions with data access risk.
- Integration path to endpoint/browser management policy controls.

### 5.5 Secure Automation Support

- Approved web automation actions with explicit policy scope.
- Action whitelists and rate limits.
- Mandatory audit evidence for automation-triggered actions.

## 6. Security and Compliance Controls

1. Identity and trust
- Enterprise SSO session binding for extension telemetry.
- Signed extension policy bundles.

2. Data minimization
- Prefer hashed/fingerprinted payload fields.
- Optional short-lived encrypted payload capture only for approved incident workflows.

3. Fail-closed behaviors
- If policy cannot be fetched/refreshed in strict mode, block high-risk actions.
- If telemetry ingest fails repeatedly, elevate alert and optionally challenge users.

4. Audit integrity
- Tamper-evident event chaining and signed evidence export.
- Deny-path logging as first-class evidence.

5. Privacy and legal boundaries
- Configurable jurisdiction-aware masking rules.
- Explicit user notice for monitored actions based on policy and region.

## 7. Integration with Existing Platform Modules

Map to current architecture module boundaries:

- MOD-GATEWAY: AI destination governance and request policy.
- MOD-OBS: event ingest, traceability, evidence export.
- MOD-REG: actor and ownership context.
- MOD-RUNTIME: policy enforcement and session controls.
- MOD-COST: destination/model usage telemetry.

## 8. API and UI Additions (Proposed)

### 8.1 Proposed API Surface

- `POST /browser/extensions/sessions`
- `POST /browser/extensions/sessions/{session_id}/heartbeat`
- `GET /browser/extensions/policies`
- `POST /browser/extensions/events`
- `GET /browser/extensions/shadow-ai/apps`
- `GET /browser/extensions/risk/summary`
- `POST /browser/extensions/incidents/export`

### 8.2 Proposed UI Console

New console: Browser Security

- Real-time event stream
- Prompt policy decision analytics
- Shadow AI app inventory
- Risk posture and controls
- Incident/evidence export panel

## 9. Rollout Plan

Phase 1: Visibility only
- Observe prompts/apps/extensions, no hard blocking.

Phase 2: Guided control
- Enable warn/challenge for high-risk patterns and unsanctioned apps.

Phase 3: Enforced control
- Block disallowed destinations and sensitive prompt leakage.
- Enforce strict policy sync and evidence requirements.

Phase 4: Advanced automation governance
- Allow approved local automation with signed policy and full traceability.

## 10. KPIs

- Shadow AI app discovery coverage
- Prompt leak prevention rate
- Unauthorized upload/download block rate
- Mean time to detect and investigate policy violations
- False positive rate of prompt masking/blocking
- Evidence completeness score for incidents

## 11. Open Decisions

1. Enforcement default by environment (dev/staging/prod).
2. Exact boundary between local vs backend inference for classification.
3. Retention windows for browser telemetry by jurisdiction.
4. Managed browser policy dependencies for extension inventory visibility.

## 12. Recommended Next Step

Build a thin MVP:

1. Browser extension event collector + policy fetch.
2. Backend event ingest + policy endpoint.
3. Browser Security UI panel with list/filter/export.
4. Security smoke tests for allow/deny/mask paths.
