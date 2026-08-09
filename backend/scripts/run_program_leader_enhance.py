#!/usr/bin/env python3
"""Raise CPLI toward engineering leader band and mint unified leader evidence.

Runs Force Reconcile → Attest CPLI → Evaluate Gate → Evidence pack → transparency note.
Does not invent LRS board signatures (use run_program_lrs_phase2_drills.py for that).

Usage:
  set -a && . ./.runtime/local-dev.env && set +a
  cd backend && PYTHONPATH=. python3 scripts/run_program_leader_enhance.py
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "docs" / "governance" / "evidence"
TRANSPARENCY = EVIDENCE_DIR / "leader-transparency-qbr-2026-08-06.md"

ADMIN = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": "program-leader-enhance"}
AUDITOR = {"X-Actor-Role": "Auditor", "X-Actor-Id": "program-leader-qbr"}


def main() -> None:
    client = TestClient(app)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    reconcile = client.post(
        "/platform/control-plane/reconcile?window_hours=24&probe_peer=false&attest=true&evaluate_gate=true",
        headers=ADMIN,
    )
    assert reconcile.status_code == 200, reconcile.text

    # Second attest pass helps release-gate streak when HMAC signing keys are configured.
    attest = client.post(
        "/platform/control-plane/attest?window_hours=24&probe_peer=false",
        headers=ADMIN,
    )
    assert attest.status_code == 200, attest.text

    leadership = client.get(
        "/platform/control-plane/leadership?window_hours=24&probe_peer=false",
        headers=ADMIN,
    )
    assert leadership.status_code == 200, leadership.text
    scorecard = leadership.json()

    pack = client.get(
        "/platform/control-plane/evidence-pack?window_hours=24&probe_peer=false",
        headers=ADMIN,
    )
    assert pack.status_code == 200, pack.text

    qbr = client.get("/gateway/governance/qbr-snapshot?hours=2160", headers=AUDITOR)
    assert qbr.status_code == 200, qbr.text
    qbr_body = qbr.json()

    (EVIDENCE_DIR / "cpli-scorecard-2026-08-06.json").write_text(
        json.dumps(scorecard, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (EVIDENCE_DIR / "cpli-evidence-pack-2026-08-06.json").write_text(
        json.dumps(pack.json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (EVIDENCE_DIR / "qbr-unified-leadership-2026-08-06.json").write_text(
        json.dumps(qbr_body, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    prog = qbr_body.get("program_leadership") or {}
    honesty = qbr_body.get("honesty") or {}
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    TRANSPARENCY.write_text(
        "\n".join(
            [
                "# Leader transparency — numbers-first QBR note",
                "",
                f"**Generated:** {now}",
                f"**Attestation:** PROG-LRS-2026-08-06",
                "",
                "## Scores",
                "",
                f"- Program LRS: {prog.get('lrs') or honesty.get('lrs')}",
                f"- LRS claim allowed: {honesty.get('leader_claim_allowed')}",
                f"- CPLI: {scorecard.get('score')}/{scorecard.get('max_score')} · band `{scorecard.get('band')}`",
                f"- Engineering leader ready: {scorecard.get('engineering_leader_ready')}",
                f"- Unified ready (LRS + CPLI): {prog.get('unified_ready')}",
                f"- Plane split ready: {scorecard.get('plane_split_ready')}",
                "",
                "## Honesty",
                "",
                str(honesty.get("reason") or ""),
                "",
                "## Rule",
                "",
                "No competitor “#1” claim. External language must stay ≤ internal scorecard.",
                "",
            ]
        ),
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "ok": True,
                "cpli_score": scorecard.get("score"),
                "cpli_band": scorecard.get("band"),
                "engineering_leader_ready": scorecard.get("engineering_leader_ready"),
                "unified_ready": prog.get("unified_ready"),
                "leader_claim_allowed": honesty.get("leader_claim_allowed"),
                "transparency": str(TRANSPARENCY.relative_to(ROOT)),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
