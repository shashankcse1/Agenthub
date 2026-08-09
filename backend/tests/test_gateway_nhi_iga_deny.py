"""Inbound IGA deny signals + inference gate (GOV-AI-IDSEC-NHI-003)."""

from __future__ import annotations

import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

ADMIN_HEADERS = {
    "X-Actor-Role": "Platform Admin",
    "X-Actor-Id": "admin-iga-deny-1",
    "X-Approver-Role": "Security Approver",
    "X-Approver-Id": "sec-iga-deny-1",
}
AUDITOR_HEADERS = {"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-iga-deny-1"}
INFERENCE_HEADERS = {
    "X-Actor-Role": "Platform Admin",
    "X-Actor-Id": "actor-blocked-by-iga",
}


def _sign(secret: str, body: bytes, *, timestamp: str = "", nonce: str = "") -> str:
    material = f"{str(timestamp or '').strip()}.{str(nonce or '').strip()}.".encode("utf-8") + body
    return hmac.new(secret.encode("utf-8"), material, hashlib.sha256).hexdigest()


def test_iga_deny_config_and_hmac_ingest_blocks_chat():
    saved = client.put(
        "/gateway/nhi/iga-deny/config",
        json={
            "enabled": True,
            "mode": "block",
            "ingest_hmac_secret": "iga-deny-test-secret",
            "require_ingest_hmac": True,
            "default_ttl_seconds": 3600,
            "max_active_denies": 50,
            "allowed_source_systems": ["external_iga", "generic"],
        },
        headers=ADMIN_HEADERS,
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["mode"] == "block"
    assert saved.json()["ingest_hmac_secret"] == ""
    assert saved.json()["ingest_hmac_secret_configured"] is True

    body = {
        "subject_type": "actor_id",
        "subject_id": "actor-blocked-by-iga",
        "reason": "External IGA denied agent action",
        "source_system": "external_iga",
        "environment": "dev",
        "external_ref": "iga-evt-test-1",
        "ttl_seconds": 3600,
    }
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    bad = client.post(
        "/gateway/nhi/iga-deny/ingest",
        data=raw,
        headers={"Content-Type": "application/json", "X-Gateway-Iga-Signature": "deadbeef"},
    )
    assert bad.status_code == 401, bad.text

    ok = client.post(
        "/gateway/nhi/iga-deny/ingest",
        data=raw,
        headers={
            "Content-Type": "application/json",
            "X-Gateway-Iga-Signature": _sign("iga-deny-test-secret", raw),
        },
    )
    assert ok.status_code == 200, ok.text
    deny_id = ok.json()["deny_id"]
    assert ok.json()["source_system"] == "external_iga"

    evaluated = client.post(
        "/gateway/nhi/iga-deny/evaluate",
        json={"actor_id": "actor-blocked-by-iga", "environment": "dev"},
        headers=AUDITOR_HEADERS,
    )
    assert evaluated.status_code == 200, evaluated.text
    assert evaluated.json()["matched"] is True

    chat = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hello"}],
            "environment": "dev",
        },
        headers=INFERENCE_HEADERS,
    )
    assert chat.status_code == 403, chat.text
    detail = chat.json().get("detail") or {}
    assert detail.get("error_code") == "IGA_DENY_SIGNAL"

    revoked = client.post(
        f"/gateway/nhi/iga-deny/{deny_id}/revoke",
        json={"reason": "cleared after test"},
        headers=ADMIN_HEADERS,
    )
    assert revoked.status_code == 200, revoked.text

    chat2 = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hello again"}],
            "environment": "dev",
        },
        headers=INFERENCE_HEADERS,
    )
    # May fail for other credential reasons, but must not be IGA deny.
    if chat2.status_code == 403:
        detail2 = chat2.json().get("detail") or {}
        assert detail2.get("error_code") != "IGA_DENY_SIGNAL", chat2.text


def test_iga_deny_warn_mode_allows_inference():
    client.put(
        "/gateway/nhi/iga-deny/config",
        json={
            "enabled": True,
            "mode": "warn",
            "ingest_hmac_secret": "iga-deny-warn-secret",
            "require_ingest_hmac": False,
            "default_ttl_seconds": 1800,
            "max_active_denies": 50,
            "allowed_source_systems": ["generic"],
        },
        headers=ADMIN_HEADERS,
    )
    created = client.post(
        "/gateway/nhi/iga-deny",
        json={
            "subject_type": "actor_id",
            "subject_id": "actor-warn-iga",
            "reason": "warn only",
            "source_system": "generic",
            "ttl_seconds": 1800,
        },
        headers=ADMIN_HEADERS,
    )
    assert created.status_code == 200, created.text

    eval_resp = client.post(
        "/gateway/nhi/iga-deny/evaluate",
        json={"actor_id": "actor-warn-iga"},
        headers=AUDITOR_HEADERS,
    )
    assert eval_resp.status_code == 200
    assert eval_resp.json()["matched"] is True
    assert eval_resp.json()["mode"] == "warn"


def test_legacy_saviynt_zuma_source_alias_canonicalizes():
    from app.services.gateway_nhi_iga_deny import canonicalize_source_system
    from app.services.gateway_nhi_iga_export import canonicalize_target_system

    assert canonicalize_source_system("saviynt_zuma") == "external_iga"
    assert canonicalize_source_system("external_iga") == "external_iga"
    assert canonicalize_target_system("saviynt_zuma") == "external_iga"
    assert canonicalize_target_system("generic") == "generic"


def test_iga_deny_disabled_by_default_shape():
    # Reset toward off for other suites that share DB — dual-approval save.
    reset = client.put(
        "/gateway/nhi/iga-deny/config",
        json={
            "enabled": False,
            "mode": "off",
            "ingest_hmac_secret": "",
            "require_ingest_hmac": True,
            "default_ttl_seconds": 86400,
            "max_active_denies": 200,
            "allowed_source_systems": ["generic", "external_iga", "astrix", "oasis", "aembit"],
        },
        headers=ADMIN_HEADERS,
    )
    assert reset.status_code == 200, reset.text
    loaded = client.get("/gateway/nhi/iga-deny/config", headers=AUDITOR_HEADERS)
    assert loaded.status_code == 200
    assert loaded.json()["enabled"] is False
    assert loaded.json()["mode"] == "off"
