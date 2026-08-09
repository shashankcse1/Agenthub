# @agenthub/gateway-sdk

First-party turnkey client for the AgentHub AI Gateway. **Zero runtime dependencies** — no Helicone, Portkey, n8n, or other gateway SaaS required.

- OpenAI-compatible `chatCompletions` and `responses`
- Automatic `POST /cost/events` instrumentation
- Gateway-native session/user properties + `cache_mode` + virtual key headers
- Returns `traceId` + Observability deep-link on every call

## Install

```bash
# from repo (local / unpublished)
cd sdk/js
npm install
npm link

# when published
npm install @agenthub/gateway-sdk
```

## Quick start

```js
import { AgentHubGateway } from "@agenthub/gateway-sdk";

const gateway = new AgentHubGateway({
  baseUrl: "https://gateway.example.com",
  apiKey: process.env.GATEWAY_VIRTUAL_KEY,
  actorRole: "AI Ops Approver",
  actorId: "my-service",
  agentId: "support-copilot",
  environment: "prod",
  trackCost: true,
});

const result = await gateway.chatCompletions({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "Summarize today's incidents" }],
});

console.log(result.choices[0].message.content);
console.log(result.agenthub.traceId);
console.log(result.agenthub.observabilityUrl);

// Optional Helicone-class fetch instrumenter (session/user/property headers)
import { createGatewayFetchInstrumenter } from "@agenthub/gateway-sdk";
const fetchImpl = createGatewayFetchInstrumenter({
  sessionId: "sess-1",
  user: "ada",
  properties: { plan: "pro" },
});
```

## What this closes vs Helicone

| Helicone | AgentHub SDK |
|----------|--------------|
| Proxy + auto cost | Direct `/v1/chat/completions`, `/v1/responses` + `/cost/events` |
| Request/response logging | Trace id for `GET /observability/traces/{id}` |
| Drop-in OpenAI client | Thin wrapper; swap base URL + headers |

```js
const response = await gateway.responses({
  model: "gpt-4o-mini",
  input: "Draft a status update",
}, {
  sessionPath: "/ops/status",
  cacheMode: "inherit",
});
```

Python twin (`agenthub_gateway.py`) exposes `chat_completions` / `responses` with identical payloads.
