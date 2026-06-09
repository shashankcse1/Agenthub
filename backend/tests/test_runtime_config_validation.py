from fastapi.testclient import TestClient

from app.main import app
from app.policy_constants import ROLE_PLATFORM_ADMIN, ROLE_SECURITY_APPROVER

client = TestClient(app)


def _admin_headers(actor_id: str) -> dict[str, str]:
    return {"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id}


def _approved_headers(actor_id: str, approver_id: str) -> dict[str, str]:
    return {
        "X-Actor-Role": ROLE_PLATFORM_ADMIN,
        "X-Actor-Id": actor_id,
        "X-Approver-Role": ROLE_SECURITY_APPROVER,
        "X-Approver-Id": approver_id,
    }


def test_runtime_config_validate_endpoint_rejects_invalid_ui_feature_flag_value():
    response = client.post(
        "/runtime-config/validate",
        json={"config_key": "ui.feature.discovery.enabled.prod", "config_value": "maybe"},
        headers=_admin_headers("admin-rc-validate-ui"),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
    assert "boolean-like" in body["error"]


def test_runtime_config_validate_endpoint_accepts_valid_rate_limit_rules_json():
    response = client.post(
        "/runtime-config/validate",
        json={
            "config_key": "rate_limit.rules_exact_json",
            "config_value": '[{"method":"POST","path":"/auth/sessions","max_requests":20,"window_seconds":60}]',
        },
        headers=_admin_headers("admin-rc-validate-rate"),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["error"] is None


def test_runtime_config_validation_rules_endpoint_lists_known_constraints():
    response = client.get(
        "/runtime-config/validation-rules",
        headers=_admin_headers("admin-rc-rules"),
    )
    assert response.status_code == 200
    body = response.json()
    rules = body.get("rules") or []
    assert isinstance(rules, list)
    assert any(rule.get("key") == "gateway.default_global_timeout_ms" for rule in rules)
    assert any(rule.get("key_pattern") == r"^ui\.feature\.[a-z0-9-]+\.enabled(?:\.[a-z0-9-]+)?$" for rule in rules)


def test_runtime_config_upsert_rejects_invalid_structured_value():
    response = client.put(
        "/runtime-config/observability.logs.default_limit",
        json={"config_value": "10000", "description": "invalid limit"},
        headers=_admin_headers("admin-rc-upsert-invalid"),
    )
    assert response.status_code == 400
    assert "between 1 and 500" in str(response.json()["detail"])


def test_runtime_config_validate_rejects_invalid_gateway_defaults():
    bad_timeout = client.post(
        "/runtime-config/validate",
        json={"config_key": "gateway.default_global_timeout_ms", "config_value": "10"},
        headers=_admin_headers("admin-rc-gw-timeout"),
    )
    assert bad_timeout.status_code == 200
    assert bad_timeout.json()["valid"] is False
    assert "between 100 and 120000" in bad_timeout.json()["error"]

    bad_hops = client.post(
        "/runtime-config/validate",
        json={"config_key": "gateway.default_max_fallback_hops", "config_value": "99"},
        headers=_admin_headers("admin-rc-gw-hops"),
    )
    assert bad_hops.status_code == 200
    assert bad_hops.json()["valid"] is False
    assert "between 0 and 10" in bad_hops.json()["error"]


def test_runtime_config_validate_accepts_login_lockout_policy_and_rejects_out_of_range():
    good_attempts = client.post(
        "/runtime-config/validate",
        json={"config_key": "auth.login.max_failed_attempts", "config_value": "5"},
        headers=_admin_headers("admin-rc-auth-lockout-attempts-ok"),
    )
    assert good_attempts.status_code == 200
    assert good_attempts.json()["valid"] is True

    bad_lockout_minutes = client.post(
        "/runtime-config/validate",
        json={"config_key": "auth.login.lockout_minutes", "config_value": "500"},
        headers=_admin_headers("admin-rc-auth-lockout-minutes-bad"),
    )
    assert bad_lockout_minutes.status_code == 200
    assert bad_lockout_minutes.json()["valid"] is False
    assert "between 1 and 240" in bad_lockout_minutes.json()["error"]


def test_runtime_config_validate_accepts_valid_workload_identity_defaults():
    good_expiry = client.post(
        "/runtime-config/validate",
        json={"config_key": "workload_identity.default_expires_in_seconds", "config_value": "3600"},
        headers=_admin_headers("admin-rc-wi-expiry"),
    )
    assert good_expiry.status_code == 200
    assert good_expiry.json()["valid"] is True

    good_timeout = client.post(
        "/runtime-config/validate",
        json={"config_key": "workload_identity.default_http_timeout_seconds", "config_value": "3.0"},
        headers=_admin_headers("admin-rc-wi-timeout"),
    )
    assert good_timeout.status_code == 200
    assert good_timeout.json()["valid"] is True


def test_runtime_config_validate_accepts_workload_identity_expose_access_token_flag():
    good = client.post(
        "/runtime-config/validate",
        json={"config_key": "workload_identity.expose_access_token", "config_value": "false"},
        headers=_admin_headers("admin-rc-wi-expose-ok"),
    )
    assert good.status_code == 200
    assert good.json()["valid"] is True

    bad = client.post(
        "/runtime-config/validate",
        json={"config_key": "workload_identity.expose_access_token", "config_value": "maybe"},
        headers=_admin_headers("admin-rc-wi-expose-bad"),
    )
    assert bad.status_code == 200
    assert bad.json()["valid"] is False
    assert "boolean-like" in bad.json()["error"]


def test_runtime_config_validate_accepts_and_rejects_cors_origin_csv_values():
    good = client.post(
        "/runtime-config/validate",
        json={
            "config_key": "security.cors_allow_origins_csv",
            "config_value": "http://127.0.0.1:4173,https://control.example.com",
        },
        headers=_admin_headers("admin-rc-cors-good"),
    )
    assert good.status_code == 200
    assert good.json()["valid"] is True

    bad = client.post(
        "/runtime-config/validate",
        json={
            "config_key": "security.cors_allow_origins_csv",
            "config_value": "*.example.com",
        },
        headers=_admin_headers("admin-rc-cors-bad"),
    )
    assert bad.status_code == 200
    assert bad.json()["valid"] is False
    assert "must not include wildcard" in bad.json()["error"]


def test_runtime_config_validate_accepts_valid_cost_model_token_rates_json():
    response = client.post(
        "/runtime-config/validate",
        json={
            "config_key": "cost.model_token_rates_json",
            "config_value": '{"default":{"input_cents_per_1k":0.5,"output_cents_per_1k":1.25},"models":{"gpt-4o-mini":{"input_cents_per_1k":0.15,"output_cents_per_1k":0.6}}}',
        },
        headers=_admin_headers("admin-rc-cost-model-rates-ok"),
    )
    assert response.status_code == 200
    assert response.json()["valid"] is True


def test_runtime_config_validate_rejects_invalid_cost_model_token_rates_json():
    missing_default = client.post(
        "/runtime-config/validate",
        json={
            "config_key": "cost.model_token_rates_json",
            "config_value": '{"models":{"gpt-4o-mini":{"input_cents_per_1k":0.15}}}',
        },
        headers=_admin_headers("admin-rc-cost-model-rates-bad-default"),
    )
    assert missing_default.status_code == 200
    assert missing_default.json()["valid"] is False
    assert "must include object field default" in missing_default.json()["error"]

    negative_rate = client.post(
        "/runtime-config/validate",
        json={
            "config_key": "cost.model_token_rates_json",
            "config_value": '{"default":{"input_cents_per_1k":-1,"output_cents_per_1k":1}}',
        },
        headers=_admin_headers("admin-rc-cost-model-rates-bad-negative"),
    )
    assert negative_rate.status_code == 200
    assert negative_rate.json()["valid"] is False
    assert "must be >= 0" in negative_rate.json()["error"]


def test_runtime_config_validate_accepts_valid_cost_cloud_component_multipliers_json():
    response = client.post(
        "/runtime-config/validate",
        json={
            "config_key": "cost.cloud_component_multipliers_json",
            "config_value": '{"provider_type":{"aws":1.05,"azure":1.0},"endpoint_family":{"responses":1.0,"chat":0.95}}',
        },
        headers=_admin_headers("admin-rc-cost-cloud-mult-ok"),
    )
    assert response.status_code == 200
    assert response.json()["valid"] is True


def test_runtime_config_validate_rejects_invalid_cost_cloud_component_multipliers_json():
    missing_provider_type = client.post(
        "/runtime-config/validate",
        json={
            "config_key": "cost.cloud_component_multipliers_json",
            "config_value": '{"endpoint_family":{"responses":1.0}}',
        },
        headers=_admin_headers("admin-rc-cost-cloud-mult-bad-missing"),
    )
    assert missing_provider_type.status_code == 200
    assert missing_provider_type.json()["valid"] is False
    assert "provider_type must be a JSON object" in missing_provider_type.json()["error"]

    zero_value = client.post(
        "/runtime-config/validate",
        json={
            "config_key": "cost.cloud_component_multipliers_json",
            "config_value": '{"provider_type":{"aws":0},"endpoint_family":{"responses":1.0}}',
        },
        headers=_admin_headers("admin-rc-cost-cloud-mult-bad-zero"),
    )
    assert zero_value.status_code == 200
    assert zero_value.json()["valid"] is False
    assert "must be > 0" in zero_value.json()["error"]


def test_runtime_config_validate_accepts_and_rejects_provider_discounts_json():
    valid = client.post(
        "/runtime-config/validate",
        json={
            "config_key": "cost.provider_discounts_json",
            "config_value": '{"provider_type":{"openai":5.0},"models":{"gpt-4o-mini":2.5}}',
        },
        headers=_admin_headers("admin-rc-cost-discount-ok"),
    )
    assert valid.status_code == 200
    assert valid.json()["valid"] is True

    invalid = client.post(
        "/runtime-config/validate",
        json={
            "config_key": "cost.provider_discounts_json",
            "config_value": '{"provider_type":{"openai":120},"models":{}}',
        },
        headers=_admin_headers("admin-rc-cost-discount-bad"),
    )
    assert invalid.status_code == 200
    assert invalid.json()["valid"] is False
    assert "between 0 and 95" in invalid.json()["error"]


def test_runtime_config_upsert_requires_dual_approval_for_sensitive_cost_keys():
    denied = client.put(
        "/runtime-config/cost.model_token_rates_json",
        json={
            "config_value": '{"default":{"input_cents_per_1k":1.0,"output_cents_per_1k":2.0}}',
            "description": "pricing update",
        },
        headers=_admin_headers("admin-rc-cost-upsert-denied"),
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    allowed = client.put(
        "/runtime-config/cost.model_token_rates_json",
        json={
            "config_value": '{"default":{"input_cents_per_1k":1.0,"output_cents_per_1k":2.0}}',
            "description": "pricing update",
        },
        headers=_approved_headers("admin-rc-cost-upsert-allow", "security-rc-approve"),
    )
    assert allowed.status_code == 200

    deleted = client.delete(
        "/runtime-config/cost.model_token_rates_json",
        headers=_approved_headers("admin-rc-cost-delete-allow", "security-rc-delete-approve"),
    )
    assert deleted.status_code == 200

    denied_discounts = client.put(
        "/runtime-config/cost.provider_discounts_json",
        json={
            "config_value": '{"provider_type":{"openai":4.0},"models":{}}',
            "description": "discount update",
        },
        headers=_admin_headers("admin-rc-discount-upsert-denied"),
    )
    assert denied_discounts.status_code == 403
    assert denied_discounts.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    allowed_discounts = client.put(
        "/runtime-config/cost.provider_discounts_json",
        json={
            "config_value": '{"provider_type":{"openai":4.0},"models":{}}',
            "description": "discount update",
        },
        headers=_approved_headers("admin-rc-discount-upsert-allow", "security-rc-discount-approve"),
    )
    assert allowed_discounts.status_code == 200


def test_runtime_config_upsert_requires_dual_approval_for_workload_identity_expose_flag():
    denied = client.put(
        "/runtime-config/workload_identity.expose_access_token",
        json={
            "config_value": "true",
            "description": "temporarily expose workload identity tokens in local test",
        },
        headers=_admin_headers("admin-rc-expose-upsert-denied"),
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    allowed = client.put(
        "/runtime-config/workload_identity.expose_access_token",
        json={
            "config_value": "true",
            "description": "temporarily expose workload identity tokens in local test",
        },
        headers=_approved_headers("admin-rc-expose-upsert-allow", "security-rc-expose-approve"),
    )
    assert allowed.status_code == 200

    deleted = client.delete(
        "/runtime-config/workload_identity.expose_access_token",
        headers=_approved_headers("admin-rc-expose-delete-allow", "security-rc-expose-delete-approve"),
    )
    assert deleted.status_code == 200


def test_runtime_config_read_and_validate_paths_emit_audit_events():
    actor_id = "admin-rc-audit-read-validate"
    headers = _admin_headers(actor_id)

    rules_resp = client.get("/runtime-config/validation-rules", headers=headers)
    assert rules_resp.status_code == 200

    list_resp = client.get("/runtime-config", headers=headers)
    assert list_resp.status_code == 200

    validate_resp = client.post(
        "/runtime-config/validate",
        json={"config_key": "observability.logs.default_limit", "config_value": "50"},
        headers=headers,
    )
    assert validate_resp.status_code == 200
    assert validate_resp.json()["valid"] is True

    rules_audit = client.get(
        "/audit/events?action_type=runtime_config.validation_rules.read&actor_id=admin-rc-audit-read-validate&limit=20",
        headers=headers,
    )
    assert rules_audit.status_code == 200
    assert len(rules_audit.json()) >= 1

    read_audit = client.get(
        "/audit/events?action_type=runtime_config.read&actor_id=admin-rc-audit-read-validate&limit=20",
        headers=headers,
    )
    assert read_audit.status_code == 200
    assert len(read_audit.json()) >= 1

    validate_audit = client.get(
        "/audit/events?action_type=runtime_config.validate&actor_id=admin-rc-audit-read-validate&limit=20",
        headers=headers,
    )
    assert validate_audit.status_code == 200
    assert len(validate_audit.json()) >= 1


def test_runtime_config_upsert_and_delete_emit_cache_invalidation_audit_events():
    actor_id = "admin-rc-audit-cache"
    key = "ui.feature.cache-audit.enabled.test"
    headers = _admin_headers(actor_id)

    upsert = client.put(
        f"/runtime-config/{key}",
        json={"config_value": "true", "description": "cache audit coverage"},
        headers=headers,
    )
    assert upsert.status_code == 200

    deleted = client.delete(f"/runtime-config/{key}", headers=headers)
    assert deleted.status_code == 200

    cache_audit = client.get(
        f"/audit/events?action_type=runtime_config.cache_invalidate&resource_id={key}&actor_id={actor_id}&limit=20",
        headers=headers,
    )
    assert cache_audit.status_code == 200
    assert len(cache_audit.json()) >= 2
