import json
from unittest.mock import Mock, patch
from uuid import uuid4

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import ProviderCredentialBinding, RuntimeConfig
from app.services.gateway_notification_delivery import deliver_email, deliver_sms
from app.services.runtime_config import invalidate_runtime_config_cache


def _seed_channel_and_binding(*, binding_id: str, channel_id: str, provider_type: str) -> None:
    channels_json = json.dumps(
        [
            {
                "channel_id": channel_id,
                "provider_type": provider_type,
                "enabled": True,
                "environment": "dev",
                "from_address": "alerts@example.com" if provider_type == "sendgrid" else "+15551234567",
                "default_recipient_domain_allowlist": ["example.com"],
                "credential_binding_id": binding_id,
                "api_base_url": "https://api.sendgrid.com" if provider_type == "sendgrid" else "https://api.twilio.com",
                "metadata": {},
            }
        ]
    )
    db: Session = SessionLocal()
    try:
        row = db.query(RuntimeConfig).filter_by(config_key="gateway.notification_channels_json").first()
        if row is None:
            db.add(RuntimeConfig(config_key="gateway.notification_channels_json", config_value=channels_json))
        else:
            row.config_value = channels_json
        db.add(
            ProviderCredentialBinding(
                binding_id=binding_id,
                tenant_id=f"tenant-{uuid4().hex[:6]}",
                binding_name="Notify binding",
                consumer_type="platform",
                consumer_key="gateway",
                provider_type=provider_type,
                credential_plane="secret_ref",
                secret_provider_id="sp-test",
                secret_ref="providers/notifications/key",
                environment="dev",
                status="active",
            )
        )
        db.commit()
        invalidate_runtime_config_cache("gateway.notification_channels_json")
    finally:
        db.close()


@pytest.fixture
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_deliver_email_sendgrid_success(db_session):
    binding_id = f"bind-email-{uuid4().hex[:8]}"
    channel_id = f"channel-email-{uuid4().hex[:8]}"
    _seed_channel_and_binding(binding_id=binding_id, channel_id=channel_id, provider_type="sendgrid")

    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = 202
    mock_response.headers = {"X-Message-Id": "sg-test-123"}
    mock_response.text = ""

    with patch(
        "app.services.gateway_notification_delivery.resolve_binding_for_runtime",
        return_value=Mock(secret_value="SG.test-key"),
    ):
        with patch("app.services.gateway_notification_delivery.httpx.post", return_value=mock_response) as mock_post:
            result = deliver_email(
                db_session,
                channel_id=channel_id,
                to="ops@example.com",
                subject="Alert",
                body="Workflow complete",
            )

    assert result["live"] is True
    assert result["simulated"] is False
    assert result["delivery_status"] == "sent"
    assert result["provider_type"] == "sendgrid"
    assert result["receipt_id"] == "sg-test-123"
    mock_post.assert_called_once()
    assert mock_post.call_args.kwargs["headers"]["Authorization"] == "Bearer SG.test-key"


def test_deliver_email_rejects_disallowed_domain(db_session):
    binding_id = f"bind-email-{uuid4().hex[:8]}"
    channel_id = f"channel-email-{uuid4().hex[:8]}"
    _seed_channel_and_binding(binding_id=binding_id, channel_id=channel_id, provider_type="sendgrid")

    with pytest.raises(HTTPException) as exc:
        deliver_email(
            db_session,
            channel_id=channel_id,
            to="ops@other-domain.com",
            subject="Alert",
            body="Body",
        )
    assert exc.value.status_code == 403


def test_deliver_sms_twilio_success(db_session):
    binding_id = f"bind-sms-{uuid4().hex[:8]}"
    channel_id = f"channel-sms-{uuid4().hex[:8]}"
    _seed_channel_and_binding(binding_id=binding_id, channel_id=channel_id, provider_type="twilio")

    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = 201
    mock_response.json.return_value = {"sid": "SM123"}
    mock_response.text = ""

    credentials = json.dumps({"username": "AC123", "password": "secret-token"})
    with patch(
        "app.services.gateway_notification_delivery.resolve_binding_for_runtime",
        return_value=Mock(secret_value=credentials),
    ):
        with patch("app.services.gateway_notification_delivery.httpx.post", return_value=mock_response) as mock_post:
            result = deliver_sms(
                db_session,
                channel_id=channel_id,
                to="+15559876543",
                body="Workflow alert",
            )

    assert result["delivery_status"] == "sent"
    assert result["provider_type"] == "twilio"
    assert result["receipt_id"] == "SM123"
    mock_post.assert_called_once()
    assert mock_post.call_args.kwargs["headers"]["Authorization"].startswith("Basic ")


def test_deliver_sms_rejects_invalid_e164(db_session):
    binding_id = f"bind-sms-{uuid4().hex[:8]}"
    channel_id = f"channel-sms-{uuid4().hex[:8]}"
    _seed_channel_and_binding(binding_id=binding_id, channel_id=channel_id, provider_type="twilio")

    with pytest.raises(HTTPException) as exc:
        deliver_sms(
            db_session,
            channel_id=channel_id,
            to="5559876543",
            body="Invalid number",
        )
    assert exc.value.status_code == 422
