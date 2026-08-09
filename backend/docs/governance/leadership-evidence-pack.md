# Leadership Evidence Pack (Loop L1)

**Date:** 2026-08-02  
**Purpose:** Evidence to flip RSK-011–015 → Mitigated and support Wave 3 sign-off.

| Risk | Control | Primary verification |
|------|---------|----------------------|
| RSK-011 | CC-020 | `test_playground_prompt_registry_promote_requires_render_variables_and_prod_dual_approval` + Playground promote form co-approver fields |
| RSK-012 | CC-021, CC-022 | `test_phase0_phase1.py` playground quality triage + escalation tests |
| RSK-013 | CC-023 | `test_supported_model_catalog_tracks_explainability_and_approval_versions` + `test_supported_models_api.py` |
| RSK-014 | CC-024 | `test_gateway_external_callback_registry_and_export_flow` |
| RSK-015 | CC-025 | realtime inline binary / allowlist / correlation tests in `test_phase0_phase1.py` |
| RSK-020 | CC-033 | `test_orchestration_jit_access_requests_list_endpoint`, `test_orchestration_access_certifications_due_endpoint` |

## Operator commands

```bash
cd backend
python3 -m pytest -q \
  tests/test_phase0_phase1.py -k "prompt_registry_promote or quality_triage or supported_model_catalog or external_callback_registry or realtime" \
  tests/test_orchestration_iga.py -k "jit_access_requests_list or access_certifications_due"
```

## UI evidence (RSK-011)

- Form: `frontend/views/playground.html` `#promptRegistryPromotionForm` includes Approver Role/ID.
- Client: `frontend/app.js` `promotePromptRegistryItem` sends `X-Approver-Role` / `X-Approver-Id` and blocks prod promote without them (except Super/Master Admin).
