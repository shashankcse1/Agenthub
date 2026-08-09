"""Wave-3: VK at-rest hashing, rate-limit default merge, one-time JIT confirm nonce."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.services.rate_limit import DEFAULT_UI_POLLING_RULES, DEFAULT_WILDCARD_RULES, SlidingWindowRateLimiter
from app.services.virtual_key_secrets import hash_virtual_key_token, mint_virtual_key_bearer


def test_virtual_key_bearer_is_hashed_not_plaintext():
    bearer, digest = mint_virtual_key_bearer()
    assert digest.startswith("vkh1:")
    assert digest != bearer
    assert hash_virtual_key_token(bearer) == digest
    assert hash_virtual_key_token(bearer + "x") != digest


def test_rate_limit_db_empty_json_cannot_wipe_defaults():
    limiter = SlidingWindowRateLimiter(backend="memory")
    exact_rules: dict = {}
    wildcard_rules: dict = {}
    limiter._exact_rules = {**DEFAULT_UI_POLLING_RULES, **exact_rules}
    limiter._wildcard_rules = {**DEFAULT_WILDCARD_RULES, **wildcard_rules}
    assert ("POST", "/gateway/jit-actions/") in limiter._wildcard_rules
    assert ("POST", "/auth/login") in limiter._exact_rules


def test_jit_confirm_nonce_one_time_and_not_offline():
    from app.database import SessionLocal
    from app.services.gateway_jit_notifications import mint_confirm_nonce, verify_confirm_nonce

    db = SessionLocal()
    try:
        nonce = mint_confirm_nonce(
            db,
            jti="jti-wave3-1",
            decision="approve",
            request_id="req-wave3-1",
            exp=4102444800,
        )
        with pytest.raises(HTTPException):
            verify_confirm_nonce(
                db,
                jti="jti-wave3-1",
                decision="approve",
                request_id="req-wave3-1",
                nonce="not-the-issued-nonce",
            )
        verify_confirm_nonce(
            db,
            jti="jti-wave3-1",
            decision="approve",
            request_id="req-wave3-1",
            nonce=nonce,
        )
        with pytest.raises(HTTPException):
            verify_confirm_nonce(
                db,
                jti="jti-wave3-1",
                decision="approve",
                request_id="req-wave3-1",
                nonce=nonce,
            )
    finally:
        db.close()
