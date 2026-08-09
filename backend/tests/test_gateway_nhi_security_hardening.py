"""Security hardening regressions for NHI/IGA ingest and block-mode gates."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app
from app.services.gateway_nhi_iga_deny import (
    sign_ingest_body,
    verify_ingest_signature,
    _is_production_runtime,
)

client = TestClient(app)

ADMIN_HEADERS = {
    "X-Actor-Role": "Platform Admin",
    "X-Actor-Id": "admin-nhi-sec-hard",
    "X-Approver-Role": "Security Approver",
    "X-Approver-Id": "sec-nhi-sec-hard",
}
INFERENCE_HEADERS = {
    "X-Actor-Role": "Platform Admin",
    "X-Actor-Id": f"actor-sec-hard-{uuid4().hex[:8]}",
}


def test_ingest_signature_binds_timestamp_and_nonce():
    body = b'{"subject_id":"x"}'
    secret = "sec-hard-secret"
    bound = sign_ingest_body(secret, body, timestamp="1700000000", nonce="n1")
    assert verify_ingest_signature(
        secret=secret,
        body=body,
        provided=bound,
        timestamp="1700000000",
        nonce="n1",
    )
    # Fresh headers with body-only signature must fail when freshness is bound.
    body_only = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    assert not verify_ingest_signature(
        secret=secret,
        body=body,
        provided=body_only,
        timestamp="1700000000",
        nonce="n-new",
        allow_legacy_body_only=False,
    )
    # Legacy body-only still accepted only when no freshness headers and allowed.
    assert verify_ingest_signature(
        secret=secret,
        body=body,
        provided=body_only,
        allow_legacy_body_only=True,
    )


def test_production_runtime_recognizes_production_alias(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    assert _is_production_runtime() is True
    monkeypatch.setenv("APP_ENV", "prod")
    assert _is_production_runtime() is True
    monkeypatch.setenv("APP_ENV", "dev")
    assert _is_production_runtime() is False


def test_block_mode_requires_declared_intent_on_chat():
    saved = client.put(
        "/gateway/nhi/governance/config",
        json={"intent_mode": "block", "access_mode": "off"},
        headers=ADMIN_HEADERS,
    )
    assert saved.status_code == 200, saved.text

    missing = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hello"}],
            "environment": "dev",
        },
        headers=INFERENCE_HEADERS,
    )
    assert missing.status_code == 403, missing.text
    detail = missing.json().get("detail") or {}
    assert detail.get("error_code") == "NHI_DECLARED_INTENT_REQUIRED"

    # restore
    client.put(
        "/gateway/nhi/governance/config",
        json={"intent_mode": "off", "access_mode": "off"},
        headers=ADMIN_HEADERS,
    )


def test_require_timestamp_rejects_missing_nonce():
    saved = client.put(
        "/gateway/nhi/iga-deny/config",
        json={
            "enabled": True,
            "mode": "warn",
            "ingest_hmac_secret": "sec-hard-deny",
            "require_ingest_hmac": True,
            "require_ingest_timestamp": True,
            "allowed_source_systems": ["generic", "external_iga"],
        },
        headers=ADMIN_HEADERS,
    )
    assert saved.status_code == 200, saved.text
    body = {
        "subject_type": "actor_id",
        "subject_id": "actor-missing-nonce",
        "reason": "nonce required",
        "source_system": "generic",
        "ttl_seconds": 600,
    }
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    ts = "1700000000"
    sig = sign_ingest_body("sec-hard-deny", raw, timestamp=ts, nonce="")
    resp = client.post(
        "/gateway/nhi/iga-deny/ingest",
        data=raw,
        headers={
            "Content-Type": "application/json",
            "X-Gateway-Iga-Signature": sig,
            "X-Gateway-Iga-Timestamp": ts,
        },
    )
    assert resp.status_code == 401, resp.text

    client.put(
        "/gateway/nhi/iga-deny/config",
        json={"enabled": False, "mode": "off", "ingest_hmac_secret": "sec-hard-deny"},
        headers=ADMIN_HEADERS,
    )
