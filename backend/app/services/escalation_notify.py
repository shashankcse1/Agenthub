from __future__ import annotations

import json
import time
from datetime import datetime
from typing import TypedDict
from urllib import error as url_error
from urllib import parse as url_parse
from urllib import request as url_request
from uuid import uuid4


class DeliveryResult(TypedDict):
    delivered: bool
    attempts: int
    receipt_id: str
    delivery_status: str
    error_message: str | None


def _simulated_channel_delivery(destination: str) -> bool:
    parsed = url_parse.urlparse(destination)
    return parsed.scheme in {"pagerduty", "slack", "opsgenie", "email", "sms"}


def deliver_escalation_notification(
    *,
    channel: str,
    destination: str,
    message: str,
    max_attempts: int = 3,
    timeout_seconds: int = 3,
) -> DeliveryResult:
    receipt_id = f"rcpt-{uuid4().hex[:16]}"
    normalized_destination = str(destination).strip()
    normalized_channel = str(channel).strip().lower()

    if _simulated_channel_delivery(normalized_destination):
        return DeliveryResult(
            delivered=True,
            attempts=1,
            receipt_id=receipt_id,
            delivery_status="sent",
            error_message=None,
        )

    parsed = url_parse.urlparse(normalized_destination)
    if parsed.scheme not in {"http", "https"}:
        return DeliveryResult(
            delivered=False,
            attempts=1,
            receipt_id=receipt_id,
            delivery_status="failed",
            error_message=(
                f"Unsupported destination scheme '{parsed.scheme or 'none'}'. "
                "Use http(s) webhook URLs or supported channel-style destinations."
            ),
        )

    payload = {
        "channel": normalized_channel,
        "destination": normalized_destination,
        "message": message,
        "sent_at": datetime.utcnow().isoformat(),
        "receipt_id": receipt_id,
    }
    encoded_payload = json.dumps(payload).encode("utf-8")

    attempts = 0
    last_error: str | None = None
    while attempts < max_attempts:
        attempts += 1
        req = url_request.Request(
            normalized_destination,
            method="POST",
            data=encoded_payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with url_request.urlopen(req, timeout=timeout_seconds) as response:
                status = int(getattr(response, "status", 0) or 0)
                if 200 <= status < 300:
                    return DeliveryResult(
                        delivered=True,
                        attempts=attempts,
                        receipt_id=receipt_id,
                        delivery_status="sent",
                        error_message=None,
                    )
                last_error = f"Webhook returned unexpected status code {status}."
        except (url_error.URLError, url_error.HTTPError, TimeoutError) as exc:
            last_error = str(exc)

        if attempts < max_attempts:
            time.sleep(0.2 * attempts)

    return DeliveryResult(
        delivered=False,
        attempts=attempts,
        receipt_id=receipt_id,
        delivery_status="failed",
        error_message=last_error,
    )
