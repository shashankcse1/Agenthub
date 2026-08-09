# Glossary

Short operator vocabulary for AgentHub. Deeper design lives under `backend/docs/governance/`.

| Term | Meaning |
| ---- | ------- |
| **API Base** | Console setting for where `/auth`, `/gateway`, `/v1`, … are called. Local default should be the UI origin (`http://127.0.0.1:4173`) so cookies stay same-origin. |
| **CPLI** | Control Plane Leadership Index (engineering posture score, max 20). Not a marketing claim by itself. |
| **CSRF / `gb_csrf`** | Double-submit cookie + `X-CSRF-Token` header required for cookie-authenticated mutations. |
| **Day-0 admin** | Bootstrap directory user (`admin`) created for local/prod bootstrap; see Day-0 hardening docs. |
| **Dual-approval** | Production privileged actions require a second authenticated approver session/role. |
| **Flow Studio** | Operator console for design → govern → run multi-step orchestration flows. |
| **Gateway API Base** | Optional Session Context field: inference paths (`/v1/…`, `/rag/…`) go to the data-plane process while admin stays on API Base (plane-split). |
| **IGA coexistence** | Export/deny/correlation hooks for external identity governance tools — not a full SaaS crawler. |
| **JIT** | Just-in-time short-lived credentials / access exceptions (gateway VK mint or orchestration JIT queues). |
| **LRS** | Leader Readiness Score (program honesty gate for external leadership claims). |
| **NHI** | Non-human identity hygiene on the gateway plane (agents, keys, workloads, deny/intent gates). |
| **Plane-split** | Deploy-time isolation: control-plane admin API vs data-plane inference workers (`APP_PLANE`, compose profile). |
| **Runtime risk** | Heuristic pre-upstream allow/warn/block policy (`/gateway/runtime-risk/*`); default disabled/observe. |
| **Same-origin proxy** | UI static server forwards API prefixes to `API_UPSTREAM` so the browser talks only to `:4173`. |
| **Session cookie / `gb_session`** | HttpOnly login session cookie; preferred over persisting bearer tokens in `localStorage`. |
| **SoT** | Documentation source of truth hierarchy (`documentation-source-of-truth.md`). |
| **VK** | Virtual key — gated inference credential with lifecycle, scopes, and optional JIT minting. |
