# Flow Orchestration IGA Impact Analysis (GOV-FLOW-IGA-001)

## Purpose

Documents advanced Identity Governance & Administration (IGA) for Flow Orchestration: Segregation of Duties (SoD), staged multi-level approvals, JIT access, access certification, gateway entitlement linkage, approval event trail, and explain/posture APIs.

## Module Impact

- **MOD-RUNTIME**: orchestration flow access policy enforcement
- **MOD-GATEWAY**: `GatewayEntitlement` ABAC bridge for `orchestration.run|approve|manage`
- **MOD-OBS**: audit events and approval event readback

## Controls Added

1. **SoD (`access_policy_json.iga.sod`)** — configurable rules with production defaults: prevent self-approval, creator-as-approver, runner-as-approver (prod), owner-as-sole-approver (prod), require dual approval (prod).
2. **Staged approvals** — `approvers.mode=staged` with per-stage state in `approval_stage_state_json`.
3. **JIT access** — `OrchestrationJitAccessRequest` with time-bound grants after policy deny.
4. **Access certification** — `OrchestrationFlowAccessCertification` with recertify interval (default 90 days); prod run blocked when expired (`orchestration.prod_run_requires_access_certification`, default true).
5. **Entitlement linkage** — optional `iga.entitlement_id` enforced fail-closed.
6. **Approval events** — `OrchestrationFlowApprovalEvent` for non-repudiation on promotion, JIT, certification, and run-gate decisions.
7. **Explain / posture** — operator diagnostics aligned with gateway authz explain patterns.

## API Additions

| Method | Route | Role gate |
|--------|-------|-----------|
| GET | `/orchestration/flows/{flow_id}/iga/posture` | Orchestration read + flow read scope |
| POST | `/orchestration/flows/{flow_id}/iga/explain` | Orchestration read + flow read scope |
| POST | `/orchestration/flows/{flow_id}/jit-access-requests` | Orchestration read |
| GET | `/orchestration/jit-access-requests` | Orchestration read |
| POST | `/orchestration/jit-access-requests/{request_id}/approve` | Orchestration approve |
| POST | `/orchestration/flows/{flow_id}/access-policy/certify` | Orchestration write + owner scope |
| GET | `/orchestration/access-certifications/due` | Orchestration read |
| GET | `/orchestration/flows/{flow_id}/approval-events` | Orchestration read |

Extended: `POST /orchestration/flows/{flow_id}/approve` accepts optional `stage_id`.

## Schema Migration

- Alembic `0038_orchestration_iga` (revises `0037_orchestration_approval_gates`)
- Column `approval_stage_state_json` on `orchestration_flow_definitions`
- Tables: `orchestration_jit_access_requests`, `orchestration_flow_access_certifications`, `orchestration_flow_approval_events`

## Residual Risk

1. Group/team-only SoD checks rely on resolved scope at decision time; misconfigured directory membership remains an operator risk.
2. JIT grants are time-bound but still expand privilege — approver workload and audit review required.
3. Entitlement linkage requires operators to maintain gateway entitlement catalog entries for orchestration actions.

## Validation

```bash
python3 -m pytest backend/tests/test_orchestration_iga.py backend/tests/test_orchestration_flows.py -q
node --check frontend/app.js
```
