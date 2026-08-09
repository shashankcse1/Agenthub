"""Outbound URL SSRF guards for gateway webhooks (private IP / metadata / loopback)."""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import Optional
from urllib.parse import urlparse

from fastapi import HTTPException

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1", "localhost."})
_METADATA_HOSTS = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "169.254.169.254",
    }
)


def _app_env() -> str:
    from app.services.runtime_env import runtime_environment

    return runtime_environment()


def _is_production_runtime() -> bool:
    from app.services.runtime_env import is_production_runtime

    return is_production_runtime()


def _is_non_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def host_is_public(hostname: str, *, resolve_dns: bool = True) -> tuple[bool, str]:
    host = str(hostname or "").strip().lower().rstrip(".")
    if not host:
        return False, "empty host"
    if host in _LOOPBACK_HOSTS:
        return False, "loopback host blocked"
    if host in _METADATA_HOSTS or host.endswith(".metadata.google.internal"):
        return False, "cloud metadata host blocked"
    try:
        ip = ipaddress.ip_address(host)
        if _is_non_public_ip(ip):
            return False, f"non-public IP {host}"
        return True, "ok"
    except ValueError:
        pass
    if not resolve_dns:
        return True, "hostname deferred"
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False, "DNS resolution failed"
    if not infos:
        return False, "DNS resolution returned no addresses"
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_non_public_ip(ip):
            return False, f"non-public IP {ip_str}"
    return True, "ok"


def validate_outbound_webhook_url(
    raw: str,
    *,
    allow_empty: bool = True,
    resolve_dns: bool = False,
    allow_loopback_outside_prod: bool = True,
) -> str:
    """Validate absolute http(s) URL; block loopback/metadata/private IP literals.

    DNS resolution is optional at config-save time (avoid flaky .example hosts in tests);
    call with resolve_dns=True before live delivery.
    """
    value = str(raw or "").strip()
    if not value:
        if allow_empty:
            return ""
        raise HTTPException(status_code=422, detail="webhook_url is required")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=422, detail="webhook_url must be an absolute http(s) URL")
    host = (parsed.hostname or "").lower()
    if not host:
        raise HTTPException(status_code=422, detail="webhook_url must include a host")

    if host in _LOOPBACK_HOSTS:
        if _is_production_runtime() or not allow_loopback_outside_prod:
            raise HTTPException(
                status_code=422,
                detail="webhook_url must not target loopback in production",
            )
        return value

    ok, reason = host_is_public(host, resolve_dns=resolve_dns)
    if not ok:
        # Hostname without DNS at save time is deferred (ok=True); other failures block.
        if reason == "hostname deferred":
            return value
        raise HTTPException(status_code=422, detail=f"webhook_url blocked: {reason}")
    return value


def assert_webhook_url_safe_for_delivery(url: str) -> None:
    """Fail closed before live HTTP POST (full private-IP SSRF denylist via DNS)."""
    validate_outbound_webhook_url(
        url,
        allow_empty=False,
        resolve_dns=True,
        allow_loopback_outside_prod=False,
    )


def ingest_timestamp_skew_ok(
    timestamp_header: Optional[str],
    *,
    now_epoch: Optional[int] = None,
    max_skew_seconds: int = 300,
) -> tuple[bool, str]:
    import time

    raw = str(timestamp_header or "").strip()
    if not raw:
        return False, "missing timestamp"
    try:
        ts = int(raw)
    except ValueError:
        return False, "invalid timestamp"
    current = int(now_epoch if now_epoch is not None else time.time())
    skew = abs(current - ts)
    if skew > max(30, min(3600, int(max_skew_seconds or 300))):
        return False, "timestamp outside allowed skew"
    return True, "ok"
