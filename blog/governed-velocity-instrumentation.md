# Control Plane Instrumentation Guide

**Purpose:** Make scorecard and SLOs computable — not slideware.  
**Owners:** OACP + Platform observability  
**Rule:** Chat UI is not the system of record. Side effects are.

---

## Event classes (emit on plane)

| Event | When | Required fields |
|-------|------|-----------------|
| `agency.infer.allow` / `deny` | Model call mediated | `actor_id`, `agent_id`, `route_id`, `decision`, `policy_ids`, `request_id`, `env` |
| `agency.tool.allow` / `deny` | Tool/MCP pre-exec | above + `tool_name`, `server_id`, `arg_fingerprint` |
| `agency.egress.allow` / `deny` | Outbound fetch/passthrough | above + `destination_host`, `reason` |
| `agency.approval.requested` / `granted` / `denied` | Escalation paths | `approval_type`, `approver_ids`, `dual=true/false` |
| `agency.memory.write` | Long-term memory | `scope`, `dual_approved` |
| `agency.budget.hit` | Soft/hard limits | `budget_id`, `threshold`, `action` |
| `agency.revoke` | Kill switch | `target`, `operator`, `t_effective` |
| `agency.evidence.export` | Bundle generated | `filters`, `row_count`, `duration_ms` |

**Never log:** raw secrets, full PANs, unnecessary prompt bodies in shared sinks. Use redaction policies aligned with Mandate.

---

## Metric formulas

| Metric | Formula |
|--------|---------|
| On-plane coverage | `infer_on_plane / (infer_on_plane + infer_off_plane_detected)` for tier-1 |
| Dual-approval coverage | `prod_mutations_with_valid_dual / prod_mutations_in_scope` |
| MCP allowlist coverage | `tool_calls_to_registered / all_prod_tool_calls` |
| Egress deny rate | `egress_deny / (egress_allow + egress_deny)` (interpret with volume) |
| Time-to-revoke | `t_effective - t_command` median over drills+incidents |
| Evidence export RTO | drill `duration` until verified bundle |

Off-plane detection sources: secret scanning, provider bill anomalies, browser extension telemetry, CASB — document which sensors feed the denominator.

---

## Dashboards (minimum)

1. **Coverage** — on-plane %, off-plane detections, unmanaged keys  
2. **Agency** — tool allow/deny, top tools, MCP servers  
3. **Escalation** — approval lag, dual failures  
4. **Fence** — egress denies, budget hits  
5. **Prove** — last revoke drill, last export drill, open RT findings  

Board sees weekly snapshots; OACP sees real-time.

---

## SIEM content pack (starter alerts)

| Alert | Condition |
|-------|-----------|
| Off-plane prod inference suspected | Provider usage without gateway `request_id` correlation |
| Tool burst | Tool allows &gt; N× baseline for agent in 10m |
| Egress to new domain | First-seen destination for agent |
| Dual-approval missing | Prod mutation audit without dual fields |
| Exception expiry | Privilege still active past expiry timestamp |

---

## Acceptance test for “instrumented”

- [ ] Can answer who/tool/data/decision for any tier-1 act in last 24h within export RTO  
- [ ] Scorecard cells auto-populate weekly (not manual guess)  
- [ ] S1 tabletop pulls ledger events, not screenshots of chat  
