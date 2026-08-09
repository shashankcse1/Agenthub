"""Gateway runtime risk policy: assess, evaluate, enforce block, security gates."""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_RUNTIME_RISK_JSON
from app.services.gateway_runtime_risk import (
    assess_and_enforce_inference_risk,
    assess_inference_risk,
    evaluate_runtime_risk,
    load_runtime_risk_config,
    save_runtime_risk_config,
)
from app.services.runtime_config import upsert_runtime_config_value

client = TestClient(app)


def _headers(actor_id: str, *, approver: bool = False, mfa: bool = True) -> dict[str, str]:
    headers = {
        "X-Actor-Role": "Platform Admin",
        "X-Actor-Id": actor_id,
    }
    if mfa:
        headers["X-MFA-Verified"] = "true"
    if approver:
        headers["X-Approver-Role"] = "Security Approver"
        headers["X-Approver-Id"] = f"sec-{actor_id}"
    return headers


def _reset_policy(db, actor_id: str = "risk-reset") -> None:
    save_runtime_risk_config(
        db,
        {
            "enabled": False,
            "mode": "observe",
            "high_action": "block",
            "medium_action": "warn",
            "low_action": "allow",
            "enforce_environments": ["prod", "production"],
            "fail_closed_on_config_error": True,
        },
        actor_id=actor_id,
    )
    db.commit()


def test_assess_inference_risk_high_for_prod_tools_frontier():
    tier, reasons = assess_inference_risk(
        model_name="gpt-4o",
        environment="production",
        has_tool_calls=True,
        selected_provider_id="prov-1",
    )
    assert tier == "high"
    assert "production_environment" in reasons
    assert "tool_call_execution_path" in reasons


def test_assess_elevated_endpoint_family_and_large_input():
    tier, reasons = assess_inference_risk(
        model_name="dall-e-3",
        environment="production",
        endpoint_family="images",
        has_agent_id=True,
        input_chars=150_000,
        selected_provider_id="prov-1",
    )
    assert tier == "high"
    assert any(item.startswith("elevated_endpoint_family:images") for item in reasons)
    assert "agent_scoped_request" in reasons
    assert "large_input_payload" in reasons


def test_runtime_risk_config_and_evaluate_api():
    suffix = uuid4().hex[:8]
    actor = f"risk-admin-{suffix}"
    loaded = client.get("/gateway/runtime-risk/config", headers=_headers(actor))
    assert loaded.status_code == 200, loaded.text
    assert loaded.json()["enabled"] is False
    assert loaded.json().get("fail_closed_on_config_error") is True

    saved = client.put(
        "/gateway/runtime-risk/config",
        json={
            "enabled": True,
            "mode": "enforce",
            "high_action": "block",
            "medium_action": "warn",
            "low_action": "allow",
            "enforce_environments": ["prod", "production"],
            "fail_closed_on_config_error": True,
        },
        headers=_headers(actor, approver=True),
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["mode"] == "enforce"

    evaluated = client.post(
        "/gateway/runtime-risk/evaluate",
        json={
            "model_name": "gpt-4o",
            "environment": "production",
            "has_tool_calls": True,
            "selected_provider_id": "prov-1",
            "endpoint_family": "images",
            "has_agent_id": True,
        },
        headers=_headers(actor),
    )
    assert evaluated.status_code == 200, evaluated.text
    body = evaluated.json()
    assert body["risk_tier"] == "high"
    assert body["would_block"] is True
    assert body["decision"] == "block"
    assert body["endpoint_family"] == "images"


def test_put_config_requires_mfa(monkeypatch):
    import app.security as security

    monkeypatch.setattr(security, "_MFA_ENFORCEMENT_OPTIONAL", False)
    suffix = uuid4().hex[:8]
    actor = f"risk-mfa-{suffix}"
    denied = client.put(
        "/gateway/runtime-risk/config",
        json={
            "enabled": False,
            "mode": "observe",
            "high_action": "block",
            "medium_action": "warn",
            "low_action": "allow",
            "enforce_environments": ["production"],
        },
        headers=_headers(actor, approver=True, mfa=False),
    )
    assert denied.status_code == 403, denied.text
    detail = denied.json().get("detail") or {}
    if isinstance(detail, dict):
        assert detail.get("error_code") == "AUTHZ_MFA_REQUIRED"


def test_put_config_rejects_invalid_action():
    suffix = uuid4().hex[:8]
    actor = f"risk-bad-{suffix}"
    denied = client.put(
        "/gateway/runtime-risk/config",
        json={
            "enabled": True,
            "mode": "enforce",
            "high_action": "drop",
            "medium_action": "warn",
            "low_action": "allow",
            "enforce_environments": ["production"],
        },
        headers=_headers(actor, approver=True),
    )
    assert denied.status_code == 422, denied.text


def test_enforce_blocks_high_risk_in_prod():
    db = SessionLocal()
    try:
        save_runtime_risk_config(
            db,
            {
                "enabled": True,
                "mode": "enforce",
                "high_action": "block",
                "medium_action": "warn",
                "low_action": "allow",
                "enforce_environments": ["production"],
            },
            actor_id="risk-enforcer",
        )
        db.commit()
        try:
            assess_and_enforce_inference_risk(
                db,
                actor_id="risk-enforcer",
                model_name="gpt-4o",
                environment="production",
                has_tool_calls=True,
                selected_provider_id="prov-1",
                request_id="req-risk-1",
                endpoint_family="chat.completions",
            )
            assert False, "expected block"
        except Exception as exc:
            detail = getattr(exc, "detail", {}) or {}
            assert getattr(exc, "status_code", None) == 403
            assert isinstance(detail, dict)
            assert detail.get("error_code") == "GATEWAY_RUNTIME_RISK_BLOCKED"
    finally:
        _reset_policy(db, "risk-enforcer")
        db.close()


def test_enforce_blocks_elevated_family_in_prod():
    db = SessionLocal()
    try:
        save_runtime_risk_config(
            db,
            {
                "enabled": True,
                "mode": "enforce",
                "high_action": "block",
                "medium_action": "block",
                "low_action": "allow",
                "enforce_environments": ["production"],
            },
            actor_id="risk-images",
        )
        db.commit()
        with pytest.raises(HTTPException) as exc_info:
            assess_and_enforce_inference_risk(
                db,
                actor_id="risk-images",
                model_name="dall-e-3",
                environment="production",
                has_tool_calls=False,
                selected_provider_id="prov-1",
                request_id="req-risk-img",
                endpoint_family="images",
                has_agent_id=True,
            )
        assert exc_info.value.status_code == 403
        detail = exc_info.value.detail
        assert isinstance(detail, dict)
        assert detail.get("endpoint_family") == "images"
    finally:
        _reset_policy(db, "risk-images")
        db.close()


def test_evaluate_out_of_scope_dev_does_not_block():
    db = SessionLocal()
    try:
        save_runtime_risk_config(
            db,
            {
                "enabled": True,
                "mode": "enforce",
                "high_action": "block",
                "medium_action": "block",
                "low_action": "block",
                "enforce_environments": ["production"],
            },
            actor_id="risk-scope",
        )
        db.commit()
        result = evaluate_runtime_risk(
            db,
            model_name="gpt-4o",
            environment="dev",
            has_tool_calls=True,
            selected_provider_id="prov-1",
        )
        assert result["would_block"] is False
        assert result["mode"] == "out_of_scope"
    finally:
        _reset_policy(db, "risk-scope")
        db.close()


def test_corrupt_config_fail_closed_in_production(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("ENVIRONMENT", "production")
    db = SessionLocal()
    try:
        upsert_runtime_config_value(
            db,
            RUNTIME_CONFIG_GATEWAY_RUNTIME_RISK_JSON,
            "{not-json",
            description="corrupt runtime risk",
        )
        db.commit()
        with pytest.raises(HTTPException) as exc_info:
            load_runtime_risk_config(db)
        assert exc_info.value.status_code == 503
        detail = exc_info.value.detail
        assert isinstance(detail, dict)
        assert detail.get("error_code") == "GATEWAY_RUNTIME_RISK_CONFIG_INVALID"
    finally:
        _reset_policy(db, "risk-corrupt")
        db.close()
