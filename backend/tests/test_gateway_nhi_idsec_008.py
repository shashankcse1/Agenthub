"""Native gate hardening: SSRF, ingest freshness, fail-closed edges (NHI-008)."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import app
from app.services.url_ssrf_guard import validate_outbound_webhook_url

client = TestClient(app)

ADMIN_HEADERS = {
    "X-Actor-Role": "Platform Admin",
    "X-Actor-Id": "admin-nhi-idsec008",
    "X-Approver-Role": "Security Approver",
    "X-Approver-Id": "sec-nhi-idsec008",
}
AUDITOR_HEADERS = {"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-nhi-idsec008"}
INFERENCE_HEADERS = {
    "X-Actor-Role": "Platform Admin",
    "X-Actor-Id": f"actor-idsec008-{uuid4().hex[:8]}",
}


def _sign(secret: str, body: bytes, *, timestamp: str = "", nonce: str = "") -> str:
    material = f"{str(timestamp or '').strip()}.{str(nonce or '').strip()}.".encode("utf-8") + body
    return hmac.new(secret.encode("utf-8"), material, hashlib.sha256).hexdigest()


def test_webhook_ssrf_blocks_private_ip_literals():
    with pytest.raises(HTTPException) as exc:
        validate_outbound_webhook_url("https://10.0.0.5/hooks/nhi", allow_empty=False)
    assert exc.value.status_code == 422
    with pytest.raises(HTTPException) as exc2:
        validate_outbound_webhook_url("http://169.254.169.254/latest/meta-data", allow_empty=False)
    assert exc2.value.status_code == 422
    assert validate_outbound_webhook_url("https://iga.example/hooks/nhi") == "https://iga.example/hooks/nhi"


def test_access_block_empty_policy_set_fail_closed():
    saved = client.put(
        "/gateway/nhi/access/config",
        json={"access_mode": "block", "access_policies": [], "policy_count": 0},
        headers=ADMIN_HEADERS,
    )
    assert saved.status_code == 200, saved.text
    denied = client.post(
        "/gateway/nhi/access/authorize",
        json={
            "declared_intent": "summarize",
            "resource": "model:gpt-4o-mini",
            "action": "chat.completions",
        },
        headers=AUDITOR_HEADERS,
    )
    assert denied.status_code == 200, denied.text
    assert denied.json()["decision"] == "deny"
    assert denied.json()["reason"] == "empty_policy_set_fail_closed"
    client.put(
        "/gateway/nhi/access/config",
        json={"access_mode": "off", "access_policies": []},
        headers=ADMIN_HEADERS,
    )


def test_intent_enforce_fail_closed_unbound_on_chat():
    gov = client.put(
        "/gateway/nhi/governance/config",
        json={"intent_mode": "block"},
        headers=ADMIN_HEADERS,
    )
    assert gov.status_code == 200, gov.text

    chat = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hello"}],
            "environment": "dev",
            "declared_intent": "summarize",
        },
        headers=INFERENCE_HEADERS,
    )
    assert chat.status_code == 403, chat.text
    detail = chat.json().get("detail") or {}
    assert detail.get("error_code") == "NHI_INTENT_DENIED"

    events = client.get("/gateway/nhi/gate-events?limit=20", headers=AUDITOR_HEADERS)
    assert events.status_code == 200, events.text
    assert events.json()["event_count"] >= 1
    assert any(row.get("gate") == "intent" for row in events.json().get("events") or [])

    client.put(
        "/gateway/nhi/governance/config",
        json={"intent_mode": "off"},
        headers=ADMIN_HEADERS,
    )


def test_iga_deny_timestamp_and_nonce_replay():
    saved = client.put(
        "/gateway/nhi/iga-deny/config",
        json={
            "enabled": True,
            "mode": "warn",
            "ingest_hmac_secret": "idsec008-deny-secret",
            "require_ingest_hmac": True,
            "require_ingest_timestamp": True,
            "max_ingest_skew_seconds": 300,
            "default_ttl_seconds": 3600,
            "allowed_source_systems": ["external_iga", "generic"],
        },
        headers=ADMIN_HEADERS,
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["require_ingest_timestamp"] is True

    body = {
        "subject_type": "actor_id",
        "subject_id": "actor-freshness-idsec008",
        "reason": "freshness test",
        "source_system": "external_iga",
        "external_ref": f"idsec008-{uuid4().hex[:10]}",
        "ttl_seconds": 3600,
    }
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    stale_ts = str(int(time.time()) - 10_000)
    stale_nonce = "nonce-idsec008-1"
    stale_sig = _sign("idsec008-deny-secret", raw, timestamp=stale_ts, nonce=stale_nonce)

    stale = client.post(
        "/gateway/nhi/iga-deny/ingest",
        data=raw,
        headers={
            "Content-Type": "application/json",
            "X-Gateway-Iga-Signature": stale_sig,
            "X-Gateway-Iga-Timestamp": stale_ts,
            "X-Gateway-Iga-Nonce": stale_nonce,
        },
    )
    assert stale.status_code == 401, stale.text

    nonce = f"nonce-{uuid4().hex}"
    ts = str(int(time.time()))
    ok_sig = _sign("idsec008-deny-secret", raw, timestamp=ts, nonce=nonce)
    ok = client.post(
        "/gateway/nhi/iga-deny/ingest",
        data=raw,
        headers={
            "Content-Type": "application/json",
            "X-Gateway-Iga-Signature": ok_sig,
            "X-Gateway-Iga-Timestamp": ts,
            "X-Gateway-Iga-Nonce": nonce,
        },
    )
    assert ok.status_code == 200, ok.text

    replay = client.post(
        "/gateway/nhi/iga-deny/ingest",
        data=raw,
        headers={
            "Content-Type": "application/json",
            "X-Gateway-Iga-Signature": ok_sig,
            "X-Gateway-Iga-Timestamp": ts,
            "X-Gateway-Iga-Nonce": nonce,
        },
    )
    assert replay.status_code == 401, replay.text

    # disable for other suites
    client.put(
        "/gateway/nhi/iga-deny/config",
        json={"enabled": False, "mode": "off", "require_ingest_timestamp": False},
        headers=ADMIN_HEADERS,
    )


def test_export_config_rejects_metadata_host():
    bad = client.put(
        "/gateway/nhi/iga-export/config",
        json={
            "enabled": False,
            "target_system": "generic",
            "webhook_url": "http://169.254.169.254/latest/meta-data",
            "hmac_secret": "x",
            "sign_requests": True,
            "include_hygiene_summary": True,
            "default_profile": "iga_correlation",
            "max_records": 10,
        },
        headers=ADMIN_HEADERS,
    )
    assert bad.status_code == 422, bad.text
