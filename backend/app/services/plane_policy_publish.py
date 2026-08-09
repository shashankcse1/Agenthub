"""Hot policy-generation publish/read for control ↔ data plane fencing.

Publishes the desired-state fingerprint to:
1. Redis (optional, ``RATE_LIMIT_REDIS_URL`` / ``PLANE_POLICY_REDIS_URL``)
2. RuntimeConfig ``plane.policy_generation_json`` (durable shared Postgres)

Data plane workers read published generation without re-hashing inventories on
every request; fail-closed mode can require local fingerprint == published.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.logging_utils import get_logger, sanitize_fields
from app.runtime_constants import RUNTIME_CONFIG_PLANE_POLICY_GENERATION_JSON
from app.services.runtime_config import get_runtime_config, upsert_runtime_config_value

logger = get_logger(__name__)

REDIS_URL_ENV = "PLANE_POLICY_REDIS_URL"
REDIS_KEY_ENV = "PLANE_POLICY_REDIS_KEY"
DEFAULT_REDIS_KEY = "plane:policy_generation"
REDIS_TTL_SECONDS = 86400

_redis_client = None
_redis_init_attempted = False


def _redis_url() -> str:
    return (
        (os.getenv(REDIS_URL_ENV) or "").strip()
        or (os.getenv("RATE_LIMIT_REDIS_URL") or "").strip()
    )


def _redis_key() -> str:
    return (os.getenv(REDIS_KEY_ENV) or DEFAULT_REDIS_KEY).strip() or DEFAULT_REDIS_KEY


def _get_redis():
    global _redis_client, _redis_init_attempted
    if _redis_client is not None:
        return _redis_client
    if _redis_init_attempted:
        return None
    _redis_init_attempted = True
    url = _redis_url()
    if not url:
        return None
    try:
        import redis  # type: ignore

        client = redis.from_url(url, decode_responses=True)
        client.ping()
        _redis_client = client
        return _redis_client
    except Exception as exc:  # noqa: BLE001
        logger.info(
            "plane_policy_redis_unavailable %s",
            sanitize_fields({"error": type(exc).__name__}),
        )
        _redis_client = None
        return None


def publish_policy_generation(
    db: Session,
    generation: dict[str, Any],
    *,
    app_plane: str = "all",
) -> dict[str, Any]:
    """Persist generation to runtime_config and best-effort Redis."""
    payload = {
        "fingerprint": generation.get("fingerprint"),
        "generation": generation.get("generation"),
        "route_count": generation.get("route_count"),
        "key_count": generation.get("key_count"),
        "cache_policy_count": generation.get("cache_policy_count"),
        "algorithm": generation.get("algorithm"),
        "published_at_unix": time.time(),
        "published_by_plane": app_plane,
    }
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_PLANE_POLICY_GENERATION_JSON,
        encoded,
        description="Hot control-plane policy generation fingerprint for data-plane fencing.",
    )
    backends = ["runtime_config"]
    client = _get_redis()
    if client is not None:
        try:
            client.setex(_redis_key(), REDIS_TTL_SECONDS, encoded)
            backends.append("redis")
        except Exception as exc:  # noqa: BLE001
            logger.info(
                "plane_policy_redis_publish_failed %s",
                sanitize_fields({"error": type(exc).__name__}),
            )
    result = {**payload, "publish_backends": backends}
    logger.info(
        "plane_policy_generation_published %s",
        sanitize_fields(
            {
                "fingerprint": payload.get("fingerprint"),
                "backends": backends,
                "app_plane": app_plane,
            }
        ),
    )
    return result


def read_published_policy_generation(db: Optional[Session] = None) -> Optional[dict[str, Any]]:
    """Read published generation: Redis first, then runtime_config."""
    client = _get_redis()
    if client is not None:
        try:
            raw = client.get(_redis_key())
            if raw:
                parsed = json.loads(raw)
                if isinstance(parsed, dict) and parsed.get("fingerprint"):
                    parsed["read_backend"] = "redis"
                    return parsed
        except Exception:
            pass
    if db is None:
        return None
    raw_cfg = get_runtime_config(db, RUNTIME_CONFIG_PLANE_POLICY_GENERATION_JSON, "")
    if not raw_cfg.strip():
        return None
    try:
        parsed = json.loads(raw_cfg)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, dict) and parsed.get("fingerprint"):
        parsed["read_backend"] = "runtime_config"
        return parsed
    return None
