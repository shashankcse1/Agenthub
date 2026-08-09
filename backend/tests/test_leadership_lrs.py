"""LRS attestation honesty gate for QBR."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.services.leadership_lrs import lrs_honesty_posture, upsert_lrs_attestation

client = TestClient(app)
ADMIN = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": "lrs-admin"}
READER = {"X-Actor-Role": "Auditor", "X-Actor-Id": "lrs-auditor"}


def test_lrs_honesty_default_blocks_claims():
    db = SessionLocal()
    try:
        posture = lrs_honesty_posture(db)
        # Without an attestation row, claims stay blocked (file fallback disabled with Session).
        if not posture.get("attestation"):
            assert posture["leader_claim_allowed"] is False
    finally:
        db.close()


def test_lrs_attestation_enables_qbr_honesty_gate():
    db = SessionLocal()
    try:
        upsert_lrs_attestation(
            db,
            {
                "attestation_id": "TEST-LRS",
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
        posture = lrs_honesty_posture(db)
        assert posture["leader_claim_allowed"] is True
        qbr = client.get("/gateway/governance/qbr-snapshot?hours=24", headers=READER)
        assert qbr.status_code == 200, qbr.text
        assert qbr.json()["honesty"]["leader_claim_allowed"] is True
        assert qbr.json()["honesty"]["lrs"]["attestation_id"] == "TEST-LRS"
    finally:
        # Clear attestation so other tests stay hermetic.
        from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_LEADERSHIP_LRS_ATTESTATION_JSON
        from app.services.runtime_config import upsert_runtime_config_value

        upsert_runtime_config_value(db, RUNTIME_CONFIG_GATEWAY_LEADERSHIP_LRS_ATTESTATION_JSON, "")
        db.commit()
        db.close()
