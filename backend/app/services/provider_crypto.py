from __future__ import annotations

import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken

from app.logging_utils import get_logger


logger = get_logger(__name__)


def _runtime_environment() -> str:
    return (os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "dev").strip().lower()


def _derive_local_key() -> bytes:
    seed = (os.getenv("SESSION_TOKEN_SECRET") or "dev-session-secret-change-me").encode("utf-8")
    digest = hashlib.sha256(seed).digest()
    return base64.urlsafe_b64encode(digest)


def _load_key_material() -> bytes:
    raw = (os.getenv("PROVIDER_CONFIG_ENCRYPTION_KEY") or "").strip()
    if raw:
        return raw.encode("utf-8")
    if _runtime_environment() in {"dev", "test", "local"}:
        return _derive_local_key()
    raise RuntimeError("PROVIDER_CONFIG_ENCRYPTION_KEY must be configured outside dev/test/local environments")


def _fernet() -> Fernet:
    try:
        return Fernet(_load_key_material())
    except Exception as exc:
        raise RuntimeError("Invalid PROVIDER_CONFIG_ENCRYPTION_KEY configuration") from exc


def validate_provider_encryption_configuration() -> None:
    # Ensure key material is present and valid in non-local environments.
    _fernet()


def provider_encryption_warnings() -> list[str]:
    warnings: list[str] = []
    env = _runtime_environment()
    raw = (os.getenv("PROVIDER_CONFIG_ENCRYPTION_KEY") or "").strip()
    if env in {"dev", "test", "local"} and not raw:
        warnings.append(
            "PROVIDER_CONFIG_ENCRYPTION_KEY is not set; provider config encryption uses a derived local key in dev/test/local."
        )
        return warnings

    if env not in {"dev", "test", "local"} and not raw:
        warnings.append("PROVIDER_CONFIG_ENCRYPTION_KEY is required outside dev/test/local.")
        return warnings

    try:
        Fernet(raw.encode("utf-8"))
    except Exception:
        warnings.append("PROVIDER_CONFIG_ENCRYPTION_KEY is not a valid Fernet key.")
    return warnings


def encrypt_value(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return _fernet().encrypt(text.encode("utf-8")).decode("utf-8")


def decrypt_value(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return _fernet().decrypt(text.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        # Fail-open for legacy plaintext rows created before encryption rollout.
        logger.warning("provider_crypto_legacy_plaintext_fallback_detected")
        return text
