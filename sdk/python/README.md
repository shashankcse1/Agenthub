# agenthub-gateway (Python)

First-party turnkey client for the AgentHub AI Gateway. **Zero runtime dependencies** — no Helicone, Portkey, n8n, or other gateway SaaS required.

## Install

```bash
# from repo root
pip install -e sdk/python
```

## Quick start

```python
from agenthub_gateway import AgentHubGateway

gateway = AgentHubGateway(
    base_url="https://gateway.example.com",
    api_key="vk_...",
    actor_role="AI Ops Approver",
    actor_id="my-service",
    environment="dev",
)
result = gateway.chat_completions(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello"}],
)
print(result["choices"][0]["message"]["content"])
```
