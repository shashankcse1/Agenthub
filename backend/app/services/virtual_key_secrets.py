"""Virtual-key bearer hashing (at-rest) + lookup with legacy plaintext migration."""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import VirtualKey


def _pepper() -> bytes:
    raw = (
        os.getenv("VIRTUAL_KEY_PEPPER")
        or os.getenv("SESSION_TOKEN_SECRET")
        or "dev-session-secret-change-me"
    )
    return str(raw).encode("utf-8")


def hash_virtual_key_token(token: str) -> str:
    normalized = str(token or "").strip()
    if not normalized:
        raise ValueError("token is required")
    digest = hmac.new(_pepper(), normalized.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"vkh1:{digest}"


def mint_virtual_key_bearer() -> tuple[str, str]:
    """Return (bearer_token, key_hash_to_store)."""
    bearer = str(uuid4())
    return bearer, hash_virtual_key_token(bearer)


def lookup_virtual_key_by_bearer(db: Session, bearer_token: str) -> Optional[VirtualKey]:
    """Resolve a VK by bearer. Migrates legacy plaintext key_hash rows on hit."""
    token = str(bearer_token or "").strip()
    if not token:
        return None
    digest = hash_virtual_key_token(token)
    key = db.query(VirtualKey).filter_by(key_hash=digest).first()
    if key is not None:
        return key
    # Legacy: key_hash stored the raw bearer (pre CC-045).
    legacy = db.query(VirtualKey).filter_by(key_hash=token).first()
    if legacy is None:
        return None
    legacy.key_hash = digest
    db.add(legacy)
    try:
        db.flush()
    except Exception:
        # Best-effort migrate; auth still succeeds with the in-memory object.
        pass
    return legacy
