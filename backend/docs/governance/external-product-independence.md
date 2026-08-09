# External Product Independence

**Status:** Normative for core gateway operation  
**Date:** 2026-08-02

## Guarantee

The AgentHub AI Gateway **does not depend on Portkey, Helicone, n8n, LiteLLM, LangSmith, or any competing AI-gateway / workflow SaaS** for startup, authentication, policy enforcement, cost/observability storage, Flow Studio dry-run, or SDK clients.

Parity language in docs/comments (“Portkey-style”, “Helicone-style”, “n8n-class”) means **API/UX competitive benchmarks only**. Those products are never required at runtime.

## What is in-process / first-party

| Surface | Dependency posture |
|---------|-------------------|
| Backend API | First-party FastAPI app; no competitor SDKs in `requirements.txt` |
| SDK (JS/Python) | Zero runtime package dependencies; talks only to this gateway |
| Inference | Optional upstream model providers via httpx/bindings; **simulation** path when credentials absent |
| Orchestration connectors | Opt-in HTTP presets + host allowlist + credentials; never required to boot |
| Discovery connectors | Opt-in; credential-gated |
| Cost / observability | First-party APIs and DB; SDK stamps headers to **this** gateway only |

## Explicitly forbidden as hard deps

Do **not** add these as required packages or boot-time services:

- `portkey`, `portkey-ai`, `helicone`, `n8n-*`, `litellm`, `langsmith`, `langchain` (as required)
- Official competitor proxy URLs as non-overridable defaults for control-plane traffic

Optional SaaS nodes (Datadog, Sentry, Slack, GitHub, …) remain catalog entries only.

## Verification

```bash
cd backend
python3 -m pytest -q tests/test_external_product_independence.py
```

## Operator note

Upstream **model** endpoints (e.g. OpenAI-compatible bases) are customer-chosen providers, not AI-gateway product dependencies. Override via bindings / `*_API_BASE` / simulation.
