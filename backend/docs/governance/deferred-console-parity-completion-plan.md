# Deferred Console Parity — Completion Plan

Status: **Complete** (2026-06-12). Use this document for operator verification and regression scope.

## Objective

Close deferred Assistants-parity and console-surface gaps:

1. Live fine-tuning upstream (runtime-gated)
2. Dedicated `/cost/timeseries` Telemetry panel
3. Orchestration data-connection test-query UI
4. Browser smoke for new operator surfaces

## Deliverables

| Item | Backend | Frontend | Tests / smoke |
| --- | --- | --- | --- |
| Live fine-tuning | `gateway_fine_tuning_upstream.py`, wired in `gateway_fine_tuning.py`; flag `gateway.fine_tuning.live_enabled` | Routing & Gateway Workspace — mode badge, Mode column, upstream job id on retrieve | `test_gateway_fine_tuning.py` (simulated, live mock, cancel, dual-approval) |
| Cost timeseries panel | `GET /cost/timeseries` in `cost.py` | Cost → Telemetry — `#costTimeseriesPanel`, chart + hourly table | `console_surface_smoke.sh` |
| Orchestration test query | `POST /orchestration/data-connections/{id}/test-query` | Flow Orchestration → Security — connection picker, SQL, parameters JSON | `test_orchestration_data_connection_test_query_platform` |
| SIEM Rules (prior) | `GET/POST /observability/siem-rules*` | Observability → SIEM Rules tab | `test_siem_alert_rules.py` |
| Overview orchestration (prior) | `GET /orchestration/summary` | Overview → Flow Orchestration card | `console_surface_smoke.sh` |
| Audit login/role/description (prior) | `AuditEvent` columns + catalog | Audit Events tab columns | `test_audit_actor_login.py` |

## Runtime configuration

| Key | Default | Effect |
| --- | --- | --- |
| `gateway.fine_tuning.live_enabled` | `false` | When `true`, create/sync/cancel fine-tuning jobs against OpenAI-compatible upstream using inference credentials |
| `orchestration.data_connections_json` | `[]` | Registers external PostgreSQL connections for dynamic scope resolution and test-query |
| `observability.siem_rules_json` | catalog default | SIEM alert rules evaluated on audit create |

## Operator verification (hard refresh recommended)

1. **Observability → SIEM Rules** — Load rules table; optional Export / Evaluate dry-run.
2. **Overview → Flow Orchestration** — Summary chips populate from `/orchestration/summary`.
3. **Cost → Telemetry** — Spend timeseries panel loads chart + table; Scope breakdown loads separately.
4. **Flow Orchestration → Security** — Data connection test query against `platform` with read-only SQL.
5. **Flow Orchestration → Approvals** — Due certification queue (filter, certify) and JIT access requests (filter, approve/deny).
6. **Routing & Gateway → Workspace → Fine-tuning** — Mode badge shows Simulated (default) or Live when flag enabled.

## Validation commands

```bash
cd backend && python3 -m pytest \
  tests/test_gateway_fine_tuning.py \
  tests/test_gateway_assistants.py \
  tests/test_siem_alert_rules.py \
  tests/test_audit_actor_login.py \
  tests/test_orchestration_flows.py -q

cd ../frontend
node --check app.js
bash scripts/console_surface_smoke.sh
bash scripts/security_smoke.sh
```

## Python design anchors

- **Fine-tuning:** `create_fine_tuning_job` branches on `_live_enabled()`; upstream helpers in `gateway_fine_tuning_upstream.py`; responses include `live_mode` and optional `upstream_job_id`.
- **Cost timeseries:** Admin/owner role gate; dimension validation matches breakdown endpoint.
- **Test query:** `ROLES_ORCHESTRATION_WRITE`; read-only SQL validation; audited `orchestration.data_connection.test_query`.
- **SIEM:** Audit hook in `create_audit_event`; rules from runtime config JSON.

## Residual gaps (out of scope)

- Visual drag-drop orchestration canvas
- Live fine-tuning E2E against real OpenAI (requires credentials + flag in staging)

## IGA approver queues (complete)

- **Approvals → Due certification queue** — filterable table, certify-from-queue with prod dual-approval.
- **Approvals → JIT access requests** — filterable table, approve/deny review with prod dual-approval on approve.
- **Security tab** — compact preview; full workflow on Approvals tab.

## Related governance

- [api-inventory-and-ui-map.md](./api-inventory-and-ui-map.md)
- [ui-api-design-coverage-map.md](./ui-api-design-coverage-map.md)
- [e2e-requirement-api-ui-verification.md](./e2e-requirement-api-ui-verification.md)
- [litellm-assistants-parity-impact-analysis.md](./litellm-assistants-parity-impact-analysis.md)
