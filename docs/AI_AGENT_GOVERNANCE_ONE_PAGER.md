# AI Agent Governance Platform One-Pager

## 1. Problem This Product Solves

Enterprises want AI agents to automate work, but unmanaged agents create serious risk:

- Unauthorized actions across systems
- Data leakage and weak policy enforcement
- No clear approval path for high-risk operations
- Poor audit trails for compliance and investigations
- Uncontrolled cost growth from model/tool usage

This platform solves those gaps by providing a governed control plane for AI agents, with browser-based operations and security-first policy controls.

## 2. What It Is (and Is Not)

What it is:

- A browser-based enterprise console to govern AI agents, policies, routing, approvals, and evidence
- A secure API/control plane with role-based permissions and auditable decisions
- A release/governance framework for CISO and security architecture review

What it is not:

- Not a consumer Chrome extension for everyday browsing
- Not an unmanaged chatbot wrapper

## 3. Who It Serves

- Platform Admins: configure runtime, routes, providers, and operations
- Security and CISO teams: review risk posture, sign off high-risk changes, and verify controls
- Compliance and Audit teams: export and verify evidence bundles for investigations
- Cloud and IAM teams: enforce least privilege, JIT access, and identity boundaries
- Product and Operations teams: run AI workflows with guardrails and reliability controls

## 4. Core Functionalities

### Security and Access Governance

- Role-based authorization for privileged actions
- Dual-approval enforcement for high-risk production operations
- Session and policy governance workflows

### Policy and Decision Control

- Policy decision preview for governed actions
- Explainability and traceability for policy outcomes

### Evidence and Audit Integrity

- PII-safe audit events
- Tamper-evident event chaining (`prev_event_hash`, `event_hash`)
- Signed evidence export and verification endpoints

### AI/Gateway Governance

- Model/provider routing controls, fallback policies, and guardrails
- OpenAI-compatible operations with governed lifecycle actions
- Request-level operational controls for production safety

### Compliance and Release Governance

- Risk closure dashboards and pending-signoff reporting
- Structured GO/NO-GO decision records
- Guardrail validation for production release posture

### Browser-Based Operator Experience

- Full control-center UI for Playground, Routing/Gateway, Security, Compliance, Observability, Cost, and more
- Security and smoke-check scripts to verify critical UI/API behaviors

## 5. End-to-End Outcome

The platform enables enterprises to use AI agents in production with:

- Safer execution of agent actions
- Better compliance and auditability
- Lower operational and security risk
- Clear cross-functional accountability (Security, CISO, Cloud, IAM, Product)
- Faster, repeatable release decisions with evidence-backed governance

## 6. Business Value

- Reduces security/compliance exposure from agent automation
- Improves trust and adoption of AI operations by governance teams
- Lowers incident blast radius with fail-closed controls
- Accelerates delivery by standardizing approvals, evidence, and validation

## 7. Quick References

- Python platform assets are deprecated (kept for historical reference only): `archive/python-platform/FUNCTIONALITIES_AND_BROWSER_SETUP.md`
- Deprecated Python platform overview: `archive/python-platform/README.md`
- Browser UI capability surface: `frontend/README.md`
- API/UI coverage map: `backend/docs/governance/ui-api-design-coverage-map.md`