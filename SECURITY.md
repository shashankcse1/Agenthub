# Security Policy

## Supported versions

Security fixes are accepted against the default branch (`main`). If you maintain a fork or older tag, please rebase or cherry-pick onto current `main` when reporting.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for sensitive vulnerabilities.

1. Prefer GitHub **Private vulnerability reporting** on this repository (Security tab), if enabled.
2. Otherwise email the maintainer associated with the GitHub org/user `shashankcse1` with:
   - Affected component/path
   - Reproduction steps (local ports, role, minimal payload)
   - Impact assessment (auth bypass, data exposure, SSRF, etc.)
   - Any suggested fix

You should receive an acknowledgement when the report is seen. Complex issues may take longer; please avoid public disclosure until a fix or coordinated advisory is ready.

## Known residual risk

This project maintains an explicit residual and accepted risk register:

- [backend/docs/security/residual-and-accepted-risk-register.md](./backend/docs/security/residual-and-accepted-risk-register.md)

Do not interpret a green CI run or local demo as “fully secure” or free of residual risk.

## Safe contribution notes

- Never commit secrets, production credentials, or Day-0 passwords.
- Prefer failing closed on authz, dual-approval, and SSRF-sensitive outbound paths.
- Add abuse-oriented tests for security-relevant behavior changes.
