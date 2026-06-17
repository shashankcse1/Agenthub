from typing import Any, Optional, Optional

import httpx

DEFAULT_TIMEOUT_SECONDS = 15.0


def http_get_json(
    url: str,
    *,
    headers: Optional[dict[str, str]] = None,
    params: Optional[dict[str, Any]] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> Any:
    response = httpx.get(
        url,
        headers=headers or {},
        params=params or {},
        timeout=timeout,
        follow_redirects=True,
    )
    response.raise_for_status()
    if response.headers.get("content-type", "").startswith("application/json"):
        return response.json()
    return {"raw": response.text}


def bearer_headers(token: str, extra: Optional[dict[str, str]] = None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token.strip()}"}
    if extra:
        headers.update(extra)
    return headers
