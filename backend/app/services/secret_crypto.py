from __future__ import annotations

import base64
import hashlib
import os
from cryptography.fernet import Fernet, InvalidToken

_RUNTIME_ENVIRONMENT = (os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "dev").strip().lower()
_LOCAL_ENVIRONMENTS = {"dev", "test", "local"}


class SecretCryptoError(RuntimeError):
    pass


def _derive_fernet_key_from_text(raw_secret: str) -> bytes:
    digest = hashlib.sha256(raw_secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _resolve_fernet_key() -> bytes:
    explicit_key = (
        os.getenv("SECRET_ENCRYPTION_KEY")
        or os.getenv("APP_SECRET_ENCRYPTION_KEY")
        or os.getenv("GATEWAY_SECRET_ENCRYPTION_KEY")
        or ""
    ).strip()
    if explicit_key:
        return _derive_fernet_key_from_text(explicit_key)

    if _RUNTIME_ENVIRONMENT in _LOCAL_ENVIRONMENTS:
        fallback = (os.getenv("SESSION_TOKEN_SECRET") or "dev-session-secret-change-me").strip()
        return _derive_fernet_key_from_text(fallback)

    raise SecretCryptoError(
        "SECRET_ENCRYPTION_KEY (or APP_SECRET_ENCRYPTION_KEY) is required outside dev/test/local."
    )


def _fernet() -> Fernet:
    return Fernet(_resolve_fernet_key())


def encrypt_secret_value(plaintext: str) -> str:
    normalized = str(plaintext or "").strip()
    if not normalized:
        return ""
    token = _fernet().encrypt(normalized.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_secret_value(ciphertext: str) -> str:
    normalized = str(ciphertext or "").strip()
    if not normalized:
        return ""
    try:
        plaintext = _fernet().decrypt(normalized.encode("utf-8"))
    except InvalidToken as exc:
        raise SecretCryptoError("Encrypted secret payload is invalid or key does not match.") from exc
    return plaintext.decode("utf-8")


def encrypt_sensitive_value(plaintext: str) -> str:
    return encrypt_secret_value(plaintext)


def decrypt_sensitive_value(ciphertext: str) -> str:
    return decrypt_secret_value(ciphertext)
