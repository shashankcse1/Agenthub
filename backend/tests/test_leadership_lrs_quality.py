"""Regression coverage for LRS normalization, honesty gate, and program summary."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_LEADERSHIP_LRS_ATTESTATION_JSON
from app.services.leadership_lrs import (
    build_program_leadership_summary,
    lrs_honesty_posture,
    normalize_lrs_attestation,
    upsert_lrs_attestation,
)
from app.services.runtime_config import upsert_runtime_config_value

client = TestClient(app)
ADMIN = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": "lrs-quality-admin"}
READER = {"X-Actor-Role": "Auditor", "X-Actor-Id": "lrs-quality-auditor"}


def test_normalize_lrs_attestation_clamps_and_rejects_future():
    normalized = normalize_lrs_attestation(
        {
            "attestation_id": "  X  ",
            "score": "99",
            "max_score": "40",
            "authority_zeros": "-1",
            "clocks_zeros": "2",
            "formal_signoff_complete": 1,
            "band": "Governed velocity",
            "attested_on": "2026-08-06",
            "dimensions": {"authority": 99, "clocks": 8, "gates": 8, "assurance": 8, "honesty": 8},
        }
    )
    assert normalized["attestation_id"] == "X"
    assert normalized["score"] == 40
    assert normalized["authority_zeros"] == 0
    assert normalized["clocks_zeros"] == 2
    assert normalized["formal_signoff_complete"] is True
    assert normalized["dimensions"]["authority"] == 8

    with pytest.raises(ValueError):
        normalize_lrs_attestation({"attestation_id": "bad", "attested_on": "2099-01-01", "score": 40})


def test_lrs_honesty_blocks_on_malformed_zeros():
    db = SessionLocal()
    try:
        upsert_lrs_attestation(
            db,
            {
                "attestation_id": "TEST-BAD-ZEROS",
                "attested_on": "2026-08-06",
                "score": 40,
                "max_score": 40,
                "band": "Governed velocity",
                "authority_zeros": "1",
                "clocks_zeros": 0,
                "formal_signoff_complete": True,
            },
            write_governance_file=False,
        )
        db.commit()
        posture = lrs_honesty_posture(db)
        assert posture["leader_claim_allowed"] is False
        assert "Authority zeros" in posture["reason"]
    finally:
        upsert_runtime_config_value(db, RUNTIME_CONFIG_GATEWAY_LEADERSHIP_LRS_ATTESTATION_JSON, "")
        db.commit()
        db.close()


def test_program_leadership_summary_unified_ready():
    honesty = {
        "leader_claim_allowed": True,
        "reason": "ok",
        "attestation": {"score": 40, "max_score": 40, "attestation_id": "T"},
    }
    summary = build_program_leadership_summary(
        honesty=honesty,
        cpli={"score": 17, "max_score": 20, "band": "leader_ready_engineering", "engineering_leader_ready": True, "plane_split_ready": True},
    )
    assert summary["unified_ready"] is True
    assert summary["cpli_engineering_leader_ready"] is True
    assert summary["plane_split_ready"] is True

    blocked = build_program_leadership_summary(
        honesty={"leader_claim_allowed": False, "reason": "missing", "attestation": None},
        cpli={"engineering_leader_ready": True},
    )
    assert blocked["unified_ready"] is False


def test_qbr_program_leadership_present_after_attestation():
    db = SessionLocal()
    try:
        upsert_lrs_attestation(
            db,
            {
                "attestation_id": "TEST-QBR-LRS",
                "attested_on": "2026-08-06",
                "score": 40,
                "max_score": 40,
                "band": "Governed velocity",
                "authority_zeros": 0,
                "clocks_zeros": 0,
                "formal_signoff_complete": True,
            },
            write_governance_file=False,
        )
        db.commit()
        client.post("/platform/control-plane/reconcile?window_hours=24", headers=ADMIN)
        qbr = client.get("/gateway/governance/qbr-snapshot?hours=24", headers=READER)
        assert qbr.status_code == 200, qbr.text
        body = qbr.json()
        assert body["honesty"]["leader_claim_allowed"] is True
        prog = body["program_leadership"]
        assert prog["lrs"]["attestation_id"] == "TEST-QBR-LRS"
        assert "unified_ready" in prog
        assert prog["cpli_max"] == 20
    finally:
        upsert_runtime_config_value(db, RUNTIME_CONFIG_GATEWAY_LEADERSHIP_LRS_ATTESTATION_JSON, "")
        db.commit()
        db.close()
