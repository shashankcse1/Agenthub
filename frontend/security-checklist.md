# Frontend Security Checklist

Use this checklist before merging UI changes.

## Baseline policy checks

- Confirm CSP is present in `index.html` and includes at least:
  - `default-src 'self'`
  - `script-src 'self'`
  - `object-src 'none'`
  - `frame-ancestors 'none'`
  - `base-uri 'none'`
- Confirm `referrer` policy is set to `no-referrer`.
- Confirm no third-party font/style hosts are used by default.

## DOM/XSS checks

- Do not use `innerHTML` with untrusted data.
- Prefer `textContent`, `createElement`, and explicit node assembly.
- Keep table rendering through safe helper functions.
- Treat all backend fields as untrusted.

## Request safety checks

- Keep API base URL validation strict (`http/https`, no credentials).
- Keep production write confirmation guard enabled.
- Validate profile switching does not silently change security posture.

## Manual runtime checks

1. Start backend and frontend.
2. Load the UI and verify no console CSP violations.
3. Switch to Prod profile and attempt a write action; verify confirmation prompt appears.
4. Load Discovery/Audit with sample data containing HTML-like payloads; verify rendered output is plain text.

## Accessibility checks

- Verify a skip link is present and moves focus to main content.
- Verify keyboard focus is clearly visible for links, buttons, inputs, and selects.
- Verify status and incident messaging use live-region semantics for assistive technologies.
- Verify table captions exist for screen-reader context.

## Automated local smoke

Run:

```bash
cd frontend
bash scripts/security_smoke.sh
```

This script enforces core security invariants for the static UI.
