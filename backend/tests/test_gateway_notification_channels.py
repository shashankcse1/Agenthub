import json
from typing import Optional

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.main import app
from app.models import RuntimeConfig
from app.services.gateway_notification_channels import validate_notification_channels_json
from app.services.runtime_config import invalidate_runtime_config_cache

client = TestClient(app)

AUDITOR_HEADERS = {"X-Actor-Role": "Auditor", "X-Actor-Id": "notify-auditor-test"}
ADMIN_HEADERS = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": "notify-admin-test"}


def _sample_channel(**overrides) -> dict:
    base = {
        "channel_id": "ops-sendgrid",
        "provider_type": "sendgrid",
        "enabled": True,
        "environment": "dev",
        "from_address": "alerts@example.com",
        "default_recipient_domain_allowlist": ["example.com"],
        "credential_binding_id": "bind-notify-001",
        "api_base_url": "https://api.sendgrid.com",
        "metadata": {},
    }
    base.update(overrides)
    return base


def _seed_notification_channels(channels: Optional[list] = None) -> None:
    payload = channels if channels is not None else [_sample_channel()]
    db: Session = SessionLocal()
    try:
        row = db.query(RuntimeConfig).filter_by(config_key="gateway.notification_channels_json").first()
        value = json.dumps(payload)
        if row is None:
            db.add(RuntimeConfig(config_key="gateway.notification_channels_json", config_value=value))
        else:
            row.config_value = value
        db.commit()
        invalidate_runtime_config_cache("gateway.notification_channels_json")
    finally:
        db.close()


def test_validate_notification_channels_json_rejects_inline_secret():
    bad = json.dumps([{**_sample_channel(), "api_key": "sk-live-secret"}])
    assert validate_notification_channels_json(bad) is not None


def test_validate_notification_channels_json_requires_binding_when_enabled():
    bad = json.dumps([{**_sample_channel(), "credential_binding_id": ""}])
    assert "credential_binding_id" in (validate_notification_channels_json(bad) or "")


def test_validate_notification_channels_json_rejects_duplicate_channel_id():
    channel = _sample_channel()
    bad = json.dumps([channel, {**channel, "provider_type": "twilio"}])
    assert "duplicate" in (validate_notification_channels_json(bad) or "")


def test_runtime_config_validate_rejects_bad_notification_channels_json():
    bad = json.dumps([{"channel_id": "x", "provider_type": "unknown", "enabled": True}])
    response = client.post(
        "/runtime-config/validate",
        json={"config_key": "gateway.notification_channels_json", "config_value": bad},
        headers=ADMIN_HEADERS,
    )
    assert response.status_code == 200
    assert response.json()["valid"] is False


def test_gateway_notification_channels_list():
    _seed_notification_channels()
    response = client.get("/gateway/notification-channels", headers=AUDITOR_HEADERS)
    assert response.status_code == 200
    data = response.json()["data"]
    assert any(row["channel_id"] == "ops-sendgrid" for row in data)
    assert data[0]["credential_binding_id"] == "bind-notify-001"
    assert "api_key" not in data[0]


def test_gateway_notification_channel_context():
    _seed_notification_channels()
    response = client.get("/gateway/notification-channels/ops-sendgrid/context", headers=AUDITOR_HEADERS)
    assert response.status_code == 200
    payload = response.json()
    assert payload["channel"]["channel_id"] == "ops-sendgrid"
    assert payload["credential_binding_configured"] is True
    assert payload["phase_1_runtime"] == "stub_simulated_only"


def test_gateway_notification_channel_context_not_found():
    _seed_notification_channels([])
    response = client.get("/gateway/notification-channels/missing/context", headers=AUDITOR_HEADERS)
    assert response.status_code == 404
