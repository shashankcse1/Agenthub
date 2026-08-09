"""IP-pinned outbound HTTP to mitigate DNS-rebinding TOCTOU after SSRF checks (CC-047)."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from typing import Any, Mapping, Optional
from urllib.parse import urlparse, urlunparse

from fastapi import HTTPException

from app.services.url_ssrf_guard import host_is_public


@dataclass(frozen=True)
class PinnedTarget:
    scheme: str
    hostname: str
    ip: str
    port: int
    path: str


@dataclass
class PinnedResponse:
    status_code: int
    content: bytes
    headers: dict[str, str]

    def json(self) -> Any:
        import json

        return json.loads(self.content.decode("utf-8") if self.content else "null")


def _format_netloc(ip: str, port: int) -> str:
    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError:
        return f"{ip}:{port}"
    if isinstance(parsed_ip, ipaddress.IPv6Address):
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def resolve_public_ips(hostname: str) -> list[str]:
    """Single DNS resolution; fail closed if any answer is non-public."""
    host = str(hostname or "").strip().lower().rstrip(".")
    if not host:
        raise HTTPException(status_code=422, detail="webhook host is empty")
    # Literal IPs: validate without DNS.
    ok, reason = host_is_public(host, resolve_dns=False)
    if not ok and reason != "hostname deferred":
        raise HTTPException(status_code=422, detail=f"webhook_url blocked: {reason}")
    try:
        literal = ipaddress.ip_address(host)
        if (
            literal.is_private
            or literal.is_loopback
            or literal.is_link_local
            or literal.is_reserved
            or literal.is_multicast
            or literal.is_unspecified
        ):
            raise HTTPException(status_code=422, detail=f"webhook_url blocked: non-public IP {host}")
        return [str(literal)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise HTTPException(status_code=422, detail=f"webhook_url blocked: DNS resolution failed ({exc})") from exc
    ips: list[str] = []
    seen: set[str] = set()
    for info in infos:
        ip_str = str(info[4][0])
        if ip_str in seen:
            continue
        seen.add(ip_str)
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        ):
            raise HTTPException(status_code=422, detail=f"webhook_url blocked: non-public IP {ip_str}")
        ips.append(ip_str)
    if not ips:
        raise HTTPException(status_code=422, detail="webhook_url blocked: DNS resolution returned no addresses")
    return ips


def resolve_pinned_target(url: str) -> PinnedTarget:
    """Validate URL structure, resolve DNS once, pin connect to a public IP."""
    from app.services.url_ssrf_guard import validate_outbound_webhook_url

    # Structure/literal checks only — DNS happens exactly once below (no check/connect TOCTOU).
    validate_outbound_webhook_url(
        url,
        allow_empty=False,
        resolve_dns=False,
        allow_loopback_outside_prod=False,
    )
    parsed = urlparse(str(url).strip())
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise HTTPException(status_code=422, detail="webhook_url must include a host")
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise HTTPException(status_code=422, detail="webhook_url must be http(s)")
    port = int(parsed.port or (443 if scheme == "https" else 80))
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    ips = resolve_public_ips(hostname)
    return PinnedTarget(scheme=scheme, hostname=hostname, ip=ips[0], port=port, path=path)


def pinned_request(
    method: str,
    url: str,
    *,
    headers: Optional[Mapping[str, str]] = None,
    content: bytes | None = None,
    timeout: float = 10.0,
) -> PinnedResponse:
    """
    Perform an HTTP request connecting to the pre-resolved public IP.

    TLS uses SNI + cert verification against the original hostname while the TCP
    peer is the pinned IP, closing the classic DNS-rebinding check/connect gap.
    Redirects are never followed.
    """
    target = resolve_pinned_target(url)
    hdrs = {str(k): str(v) for k, v in dict(headers or {}).items()}
    hdrs["Host"] = target.hostname
    body = content if content is not None else None

    if target.scheme == "https":
        context = ssl.create_default_context()

        class _PinnedHTTPSConnection(http.client.HTTPSConnection):
            def connect(self) -> None:  # type: ignore[override]
                sock = socket.create_connection((target.ip, target.port), self.timeout)
                self.sock = context.wrap_socket(sock, server_hostname=target.hostname)

        conn: http.client.HTTPConnection = _PinnedHTTPSConnection(
            target.hostname,
            port=target.port,
            timeout=timeout,
            context=context,
        )
    else:
        conn = http.client.HTTPConnection(target.ip, port=target.port, timeout=timeout)

    try:
        conn.request(method.upper(), target.path, body=body, headers=hdrs)
        raw = conn.getresponse()
        payload = raw.read()
        response_headers = {k: v for k, v in raw.getheaders()}
        return PinnedResponse(status_code=int(raw.status), content=payload, headers=response_headers)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def pinned_httpx_compatible_post(
    url: str,
    *,
    content: bytes | None = None,
    headers: Optional[Mapping[str, str]] = None,
    timeout: float = 10.0,
) -> PinnedResponse:
    """Drop-in style POST used by webhook deliverers (status_code attribute)."""
    return pinned_request("POST", url, headers=headers, content=content, timeout=timeout)


def pinned_url_for_logging(url: str) -> str:
    """Return original URL with pinned IP annotation for diagnostics (never used to connect)."""
    try:
        target = resolve_pinned_target(url)
    except Exception:
        return str(url)
    return f"{urlunparse((target.scheme, _format_netloc(target.ip, target.port), target.path, '', '', ''))} (host={target.hostname})"
