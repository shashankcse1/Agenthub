# AWS Integration and Multi-Cloud Model Fallback

Date: 2026-06-05
Scope: Enterprise Multi-Agent Platform backend

## 1) Executive Summary

Yes, you can run multiple providers together (AWS, Azure, Google, NVIDIA, and additional well-known AI vendors) with tenant-scoped priority-based fallback.

Current state in this codebase:

1. AWS workload identity token exchange through STS already exists.
2. Provider health and trust validation flows already exist.
3. Gateway route policies include provider-priority configuration, fallback simulation, and runtime fallback execution.
4. Per-hop fallback telemetry and cost event persistence are implemented.

Current engineering posture:

1. Baseline control-plane implementation is complete for multi-tenant, multi-provider routing and workload identity exchange.
2. Remaining work is operational hardening and SLO tuning per environment.

This document gives a production-ready implementation path.

## 2) Existing AWS-Ready Foundation

1. AWS SDK dependency exists in backend requirements.
2. Workload identity provider create endpoint exists.
3. Workload identity token exchange endpoint exists and supports AWS STS AssumeRole.
4. Workload identity trust validation and provider health endpoints exist.
5. Security posture forces sensitive token exposure off outside local/test.

## 3) Target Multi-Cloud Fallback Architecture

### 3.1 Design Goals

1. Deterministic provider selection by explicit priority.
2. Fast failover with bounded retries and bounded timeout budget.
3. Cost-aware and risk-aware routing decisions.
4. Full auditability of each fallback hop.

### 3.2 Routing Model

For a logical route such as chat-default, define ordered candidates:

1. aws-bedrock-claude-sonnet (priority 1)
2. azure-openai-gpt-4o (priority 2)
3. openai-gpt-4o-mini (priority 3)

Runtime behavior:

1. Attempt candidate 1.
2. If timeout, throttling, or provider-unavailable error occurs, move to candidate 2.
3. If candidate 2 fails with retryable cause, move to candidate 3.
4. If all fail, return routed failure with trace containing attempted providers.

## 4) Proposed Configuration Contract

Use one policy document per route:

```json
{
  "route_name": "chat-default",
  "environment": "prod",
  "priority_order": [
    {
      "provider_id": "aws-bedrock-claude-sonnet",
      "priority": 1,
      "max_requests_per_min": 1200,
      "max_cost_cents_per_1k_tokens": 180,
      "timeout_ms": 2500,
      "retryable_error_classes": ["throttle", "timeout", "5xx"]
    },
    {
      "provider_id": "azure-openai-gpt-4o",
      "priority": 2,
      "max_requests_per_min": 1000,
      "max_cost_cents_per_1k_tokens": 220,
      "timeout_ms": 2400,
      "retryable_error_classes": ["throttle", "timeout", "5xx"]
    }
  ],
  "global_timeout_ms": 4500,
  "max_fallback_hops": 2,
  "fail_open_to_last_provider": false
}
```

Validation rules:

1. Priorities must be unique and contiguous.
2. Global timeout must be greater than or equal to max candidate timeout.
3. Provider must be active and trust-validated before becoming priority 1.
4. At least one provider must be in allow status for the environment.

## 5) AWS Integration Steps

### 5.1 IAM and Trust

1. Create IAM role for platform token exchange.
2. Grant minimal permissions for Bedrock invoke or target AWS service.
3. Restrict trust relationship to platform workload identity principal.
4. Require external ID or equivalent trust condition if cross-account.

### 5.2 Register Workload Identity Provider

1. Call create workload identity provider endpoint with provider_type set to aws.
2. Store role ARN in role_arn_or_equivalent.
3. Set allowed subject patterns to least privilege.

### 5.3 Validate Trust and Health

1. Run provider trust validation endpoint.
2. Verify provider health endpoint indicates active and non-stale exchange.
3. Confirm audit events for provider create, trust validate, and token exchange.

### 5.4 Security Controls

1. Keep EXPOSE_WORKLOAD_IDENTITY_ACCESS_TOKEN disabled outside local/test.
2. Require MFA for provider and exchange actions.
3. Keep dual approval for production-sensitive mutations.

## 6) Provider Expansion Notes

Current live exchange supports AWS, Azure, Google, NVIDIA, and runtime-token vendor adapters.

Future optional enhancements:

1. Native token acquisition adapters for additional runtime-token vendors.
2. Per-provider adaptive retry budgets based on rolling SLO error rates.
3. Automated circuit-breaker routing updates from live telemetry.

## 7) Priority-Based Fallback Execution Algorithm

Given ordered candidates and a request timeout budget:

1. Filter providers by environment and active health state.
2. Sort by priority ascending.
3. For each provider:
   - Enforce per-provider timeout.
   - Attempt invocation.
   - On success, return response and emit allow audit/cost events.
   - On retryable failure, record fallback hop and continue.
   - On non-retryable failure, break and return failure.
4. If all candidates exhausted, return routed failure with attempted provider list.

Recommended non-retryable classes:

1. Authn/authz denied.
2. Invalid request schema.
3. Prompt policy hard deny.

## 8) Observability, Cost, and SLO

Emit these fields per request:

1. route_name
2. primary_provider_id
3. final_provider_id
4. fallback_hops_used
5. provider_attempts
6. total_latency_ms
7. total_estimated_cost_cents
8. final_outcome

Recommended alerts:

1. Fallback rate above 5% over 15 minutes.
2. Primary provider timeout rate above 2% over 15 minutes.
3. Cost delta above policy threshold when fallback provider is used.

## 9) Security and Compliance Checklist

1. Least-privilege IAM and scoped trust conditions.
2. No long-lived static cloud credentials in app config.
3. Secret material only from approved secret provider path.
4. Production token visibility disabled.
5. Auditable changes for provider config and route priority updates.
6. Dual approval for production route priority changes.

## 10) API Status

Implemented:

1. POST /gateway/routes/{route_policy_id}/providers/priority
  - Updates ordered provider list with validation, tenant scoping, and production dual-approval guard.
2. GET /gateway/routes/{route_policy_id}/providers/priority
  - Reads effective provider priority chain including tenant scope.
3. POST /gateway/routes/{route_policy_id}/simulate-fallback
  - Dry-runs deterministic fallback behavior without live provider invocation and enforces tenant scope match.

Workload identity parity status:

1. AWS STS live exchange is supported.
2. Azure workload identity exchange supports both runtime token injection and native OAuth2 client-credentials acquisition:
   - `AZURE_WORKLOAD_IDENTITY_ACCESS_TOKEN`
   - `AZURE_WORKLOAD_IDENTITY_EXPIRES_IN`
  - `AZURE_WORKLOAD_IDENTITY_TENANT_ID`
  - `AZURE_WORKLOAD_IDENTITY_CLIENT_ID`
  - `AZURE_WORKLOAD_IDENTITY_CLIENT_SECRET`
  - `AZURE_WORKLOAD_IDENTITY_TOKEN_URL` (optional when tenant id is provided)
  - `AZURE_WORKLOAD_IDENTITY_SCOPE`
  - `AZURE_WORKLOAD_IDENTITY_TIMEOUT_SECONDS`
3. Google workload identity exchange supports runtime token injection and native metadata/token endpoint retrieval:
  - `GOOGLE_WORKLOAD_IDENTITY_ACCESS_TOKEN`
  - `GOOGLE_WORKLOAD_IDENTITY_EXPIRES_IN`
  - `GOOGLE_WORKLOAD_IDENTITY_TOKEN_URL`
  - `GOOGLE_WORKLOAD_IDENTITY_TIMEOUT_SECONDS`
  - `GOOGLE_WORKLOAD_IDENTITY_BEARER`
4. NVIDIA workload identity exchange supports runtime token injection and native OAuth2 client-credentials acquisition:
  - `NVIDIA_WORKLOAD_IDENTITY_ACCESS_TOKEN`
  - `NVIDIA_WORKLOAD_IDENTITY_EXPIRES_IN`
  - `NVIDIA_WORKLOAD_IDENTITY_CLIENT_ID`
  - `NVIDIA_WORKLOAD_IDENTITY_CLIENT_SECRET`
  - `NVIDIA_WORKLOAD_IDENTITY_TOKEN_URL`
  - `NVIDIA_WORKLOAD_IDENTITY_SCOPE`
  - `NVIDIA_WORKLOAD_IDENTITY_TIMEOUT_SECONDS`
5. Additional well-known AI vendors support tenant-scoped runtime token injection:
  - OpenAI: `OPENAI_WORKLOAD_IDENTITY_ACCESS_TOKEN`, `OPENAI_WORKLOAD_IDENTITY_EXPIRES_IN`
  - Anthropic: `ANTHROPIC_WORKLOAD_IDENTITY_ACCESS_TOKEN`, `ANTHROPIC_WORKLOAD_IDENTITY_EXPIRES_IN`
  - Cohere: `COHERE_WORKLOAD_IDENTITY_ACCESS_TOKEN`, `COHERE_WORKLOAD_IDENTITY_EXPIRES_IN`
  - Mistral: `MISTRAL_WORKLOAD_IDENTITY_ACCESS_TOKEN`, `MISTRAL_WORKLOAD_IDENTITY_EXPIRES_IN`
  - Groq: `GROQ_WORKLOAD_IDENTITY_ACCESS_TOKEN`, `GROQ_WORKLOAD_IDENTITY_EXPIRES_IN`
  - Together: `TOGETHER_WORKLOAD_IDENTITY_ACCESS_TOKEN`, `TOGETHER_WORKLOAD_IDENTITY_EXPIRES_IN`
  - Fireworks: `FIREWORKS_WORKLOAD_IDENTITY_ACCESS_TOKEN`, `FIREWORKS_WORKLOAD_IDENTITY_EXPIRES_IN`
  - Perplexity: `PERPLEXITY_WORKLOAD_IDENTITY_ACCESS_TOKEN`, `PERPLEXITY_WORKLOAD_IDENTITY_EXPIRES_IN`
  - xAI: `XAI_WORKLOAD_IDENTITY_ACCESS_TOKEN`, `XAI_WORKLOAD_IDENTITY_EXPIRES_IN`
6. Tenant scope matching is enforced for token exchange, trust validation, provider health, and route fallback execution/simulation.

Pending:

1. No open engineering gaps for baseline multi-cloud fallback control plane implementation.

Implemented runtime fallback telemetry endpoint:

1. POST /gateway/routes/{route_policy_id}/execute-fallback
  - Executes fallback attempt chain under configured priority policy.
  - Enforces tenant scope matching.
  - Records per-hop telemetry in response and persists per-hop cost events.

## 11) Rollout Plan

1. Stage 0: AWS-only with explicit priority chain support.
2. Stage 1: Add Azure provider adapter and health parity.
3. Stage 2: Enable cross-cloud fallback in staging with synthetic load.
4. Stage 3: Enable production with dual approval and alert gates.
5. Stage 4: Review fallback/cost metrics and tune priorities weekly.

## 12) Runbook Commands

1. Execute strict review:

bash scripts/full_stack_expert_review.sh --strict

2. Validate security monitor setup:

cd backend
make security-monitoring-check

3. Validate ingress security headers:

cd backend
make ingress-security-validate BASE_URL=https://api.example.com TEST_PATH=/health

## 13) Decision

Yes, multi-cloud fallback with tenant-scoped controls is implemented and aligns with current architecture.

The next milestone is operational tuning: provider-specific SLO thresholds, alert calibration, and production cutover rehearsals.
