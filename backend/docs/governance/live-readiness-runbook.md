# Non-prod Live Readiness Runbook (Wave 2)

**Goal:** Turn on Flow Studio live execution safely for GitHub / Slack / Stripe without enabling prod live.

## Bootstrap (recommended)

```bash
# 1) Seed allowlisted connector hosts + enable non-prod live
curl -X POST "$GATEWAY/orchestration/live-readiness/bootstrap" \
  -H "X-Actor-Role: Platform Admin" \
  -H "X-Actor-Id: ops-bootstrap" \
  -H "Content-Type: application/json" \
  -d '{"seed_connector_hosts":true,"enable_non_prod_live":true}'

# 2) Confirm posture
curl "$GATEWAY/orchestration/live-readiness" \
  -H "X-Actor-Role: Platform Admin" \
  -H "X-Actor-Id: ops-bootstrap"
```

Expect `non_prod_live_ready=true` and `prod_live_enabled=false`.

## Manual runtime-config alternative

1. Set `orchestration.http_allowed_hosts_json` to include at least:
   - `api.github.com`
   - `slack.com`
   - `api.stripe.com`
2. Set `orchestration.live_executor_enabled=true`
3. Leave `orchestration.live_executor_prod_enabled=false`

These keys are dual-approval sensitive on `PUT /runtime-config/{key}`.

## Connector operations

Use `operation` on nodes instead of raw paths when possible:

| Node | Operations |
|------|------------|
| `github_api` | `get_user`, `get_repo`, `list_issues`, `create_issue`, `list_pulls`, `get_issue` |
| `slack_api` | `auth_test`, `chat_post_message`, `conversations_list`, `users_info` |
| `stripe_api` | `get_balance`, `list_customers`, `list_charges`, `create_customer` |

Always bind credentials via `auth_binding_id` (no inline secrets).

## Prod live go-live checklist (still flag-gated)

Complete **before** flipping `orchestration.live_executor_prod_enabled=true`:

1. [ ] CISO / SecArch written approval for prod live egress  
2. [ ] `GET /orchestration/live-readiness` shows connector hosts seeded and non-prod proven green  
3. [ ] Allowlist is exact hosts only (no `*`); SIEM rule covers secret-value access  
4. [ ] Per-flow IGA certification current; SoD dual-approval on prod graph changes  
5. [ ] Credential bindings use secret providers (no inline tokens in graphs)  
6. [ ] Rate-limit Redis healthy (or degraded alerts wired)  
7. [ ] Rollback: set `orchestration.live_executor_prod_enabled=false` + dual-approval documented  
8. [ ] Tabletop: failed connector + secret rotation drill dated in evidence archive  

## Explicit non-goals

- Do **not** enable `orchestration.live_executor_prod_enabled` from this runbook.
- Do **not** open the HTTP allowlist to `*`.
- Do **not** treat Wave 2 bootstrap as prod enablement.
