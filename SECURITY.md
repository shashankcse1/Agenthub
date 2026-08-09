# Security Policy

## Supported versions

| Version / branch | Security updates |
| ---------------- | ---------------- |
| `main` (default) | ✅ Supported |
| Older tags / forks | ❌ Please rebase onto `main` before reporting |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

### Preferred

Use GitHub **Private vulnerability reporting**:

1. Open the repository **Security** tab  
2. Choose **Report a vulnerability**  
3. Include impact, reproduction steps, and suggested fix if you have one  

Direct link (when enabled on the repo):  
https://github.com/shashankcse1/Agenthub/security/advisories/new

### Alternative

Contact the repository owner (`shashankcse1`) via GitHub with a private message/email and include:

- Affected component or path (`backend/…`, `frontend/…`, `sdk/…`)
- Reproduction steps (local ports, API Base, actor role, minimal payload)
- Impact (auth bypass, data exposure, SSRF, privilege escalation, etc.)
- Whether a public PoC already exists

### What to expect

- Acknowledgement when the report is seen
- Coordination on disclosure timing
- Credit in release notes when appropriate and desired

Complex issues may take longer. Please avoid public disclosure until a fix or coordinated advisory is ready.

## Safe harbor

We will not pursue legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, service disruption, and data destruction
- Do not exploit the issue beyond what is needed to demonstrate it
- Report findings promptly through the channels above

## Known residual risk

AgentHub maintains an explicit residual and accepted risk register. A green CI run or local demo is **not** a claim of “fully secure” or zero residual risk.

- [backend/docs/security/residual-and-accepted-risk-register.md](./backend/docs/security/residual-and-accepted-risk-register.md)
- Security contract for implementers: [backend/AGENTS.md](./backend/AGENTS.md)

## Security-sensitive contributions

When changing auth, cookies/CSRF, dual-approval, SSRF-sensitive outbound HTTP, virtual keys, or inference allow/deny paths:

1. Prefer fail-closed behavior
2. Add abuse-oriented tests under `backend/tests/`
3. Update the residual risk register when posture changes
4. Never commit secrets, Day-0 passwords, or production credentials
