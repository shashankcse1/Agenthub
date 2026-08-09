# Safari Build Notes

Use Safari Web Extension conversion from the Chromium scaffold:

1. Ensure Xcode is installed.
2. From this directory, run conversion from the Chromium manifest source tree.
3. In Xcode, configure signing/team identifiers.
4. Keep telemetry contract aligned with backend GuardBridge data-minimization constants.

Recommended flow:

- Use `manifests/chromium/manifest.json` and `src/` as the canonical source.
- Generate Safari project with Xcode converter.
- Build and run in Safari with extension development enabled.

Security checks before release:

- Verify no raw prompt text is transmitted.
- Verify no raw IP or full user-agent fields are transmitted.
- Verify only host/domain-level URL data is sent.
- Verify policy fetch and event ingest use expected backend endpoint and actor headers.
