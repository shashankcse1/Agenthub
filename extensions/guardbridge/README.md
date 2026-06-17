# GuardBridge Browser Extension Scaffold

This package provides a cross-browser scaffold for the GuardBridge extension.

## Goals

- Keep extension identity separate from the web control plane.
- Enforce minimal telemetry collection by default.
- Support Chromium browsers, Firefox, and Safari conversion flows.

## Layout

- `manifest.json`: default Chromium MV3 manifest for local load/unpacked testing.
- `manifests/chromium/manifest.json`: Chromium MV3 manifest (Chrome, Edge, Opera, Brave, Arc, Vivaldi, Samsung Internet).
- `manifests/firefox/manifest.json`: Firefox-compatible manifest variant.
- `manifests/safari/README.md`: Safari conversion instructions.
- `src/background.js`: Policy fetch and telemetry forwarding workers.
- `src/content.js`: Browser-page interaction hooks for governed AI actions.
- `src/common.js`: Shared constants and sanitization helpers.

## Privacy Contract

GuardBridge should transmit only privacy-safe telemetry:

- Allowed: browser name/version, extension version, os class/version, device type, hashed UA digest, hashed IP, country, region, action type, destination domain/app, decision outcome, risk labels, content fingerprint.
- Disallowed: raw prompt text, raw IP, raw user agent, full URL, file bytes, city/postal location.

## Local Dev Smoke

Load unpacked extension from this directory with browser-specific manifest pathing:

- Chromium: load this directory unpacked (`manifest.json` + `src/`).
- Firefox: use `manifests/firefox/manifest.json` via `about:debugging`.
- Safari: convert from Chromium scaffold using Xcode converter workflow in `manifests/safari/README.md`.

Set backend target in `src/common.js` (`apiBase`) before testing.

Repository-level compatibility validation:

- `bash scripts/check_guardbridge_browser_compat.sh`
- `bash scripts/check_guardbridge_browser_compat.sh --strict-safari` (release gate; fails when Safari converter tooling is unavailable)
- `bash scripts/check_guardbridge_browser_compat.sh --strict-firefox-lint` (release gate; fails when web-ext lint tooling is unavailable; uses global `web-ext` or `npx web-ext` fallback)
- `bash scripts/configure_xcode_for_safari_converter.sh` (diagnose/switch active Xcode developer directory for Safari converter tooling)
