# SDK Publish Runbook

## Packages

| Package | Path | Registry |
|---------|------|----------|
| `@agenthub/gateway-sdk` | `sdk/js` | npm |
| `agenthub-gateway` | `sdk/python` | PyPI |

## Pre-flight (CI dry-run)

GitHub Actions: `.github/workflows/sdk-publish-dry-run.yml`

Local:

```bash
# JS
cd sdk/js && npm run check && npm publish --dry-run

# Python
cd sdk/python
python -m pip install build twine
python -m build && twine check dist/*
```

## Real publish (human-gated)

Workflow: `.github/workflows/sdk-publish.yml` (`workflow_dispatch`, confirm=`publish`).

1. Bump version in `sdk/js/package.json` and `sdk/python/pyproject.toml` (semver).  
2. Ensure CHANGELOG entry for the SDK slice.  
3. Set repository secrets: `NPM_TOKEN`, `TWINE_USERNAME`, `TWINE_PASSWORD`.  
4. Run **SDK publish (secrets-gated)** with confirm=`publish` (fails clearly if secrets missing).  
5. Verify install:

```bash
npm install @agenthub/gateway-sdk@X.Y.Z
pip install agenthub-gateway==X.Y.Z
```

## Instrumenters

- JS: `createGatewayFetchInstrumenter`  
- Python: `create_gateway_request_instrumenter`  
Optional: pass `fetchImpl` / stamped headers into `AgentHubGateway` constructors for gateway-native session/user/property propagation.

## Independence

SDKs have **zero runtime dependencies** and talk only to this gateway. Do not add Portkey/Helicone/n8n/LiteLLM/LangSmith (or OpenAI/Anthropic official SDKs) as package deps — see `backend/docs/governance/external-product-independence.md`.
