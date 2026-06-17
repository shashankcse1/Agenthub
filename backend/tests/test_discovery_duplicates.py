from datetime import datetime
from typing import Optional, Tuple
from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import DiscoveryRecord

client = TestClient(app)


def _seed_duplicate_group(key: Optional[str] = None) -> Tuple[str, str, str]:
    db = SessionLocal()
    group_key = key or f"aaa-dup-merge-{uuid4().hex[:8]}"
    canonical_id = str(uuid4())
    merge_id = str(uuid4())
    try:
        now = datetime.utcnow()
        canonical = DiscoveryRecord(
            discovered_agent_id=canonical_id,
            canonical_agent_key=group_key,
            source_system="openai",
            source_fingerprint=f"fp-openai-{uuid4()}",
            discovery_confidence=82,
            discovery_status="discovered",
            last_discovered_at=now,
        )
        duplicate = DiscoveryRecord(
            discovered_agent_id=merge_id,
            canonical_agent_key=group_key,
            source_system="anthropic",
            source_fingerprint=f"fp-anthropic-{uuid4()}",
            discovery_confidence=90,
            discovery_status="discovered",
            last_discovered_at=now,
        )
        db.add(canonical)
        db.add(duplicate)
        db.commit()
    finally:
        db.close()
    return group_key, canonical_id, merge_id


def test_discovery_duplicates_groups_cross_source():
    group_key, _, _ = _seed_duplicate_group()

    resp = client.get(
        "/discovery/duplicates",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-dup"},
    )
    assert resp.status_code == 200
    groups = resp.json()
    match = next(
        (
            row
            for row in groups
            if row["canonical_agent_key"] == group_key.lower()
            and set(row.get("source_systems") or []) == {"anthropic", "openai"}
        ),
        None,
    )
    assert match is not None, groups
    assert match["duplicate_count"] >= 2
    assert len(match.get("members") or []) >= 2


def test_discovery_duplicate_merge_marks_non_canonical_records():
    group_key, canonical_id, merge_id = _seed_duplicate_group()

    resp = client.post(
        "/discovery/duplicates/merge",
        json={"canonical_discovered_agent_id": canonical_id},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-merge"},
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["canonical_discovered_agent_id"] == canonical_id
    assert payload["merged_count"] == 1
    assert merge_id in payload["merged_discovered_agent_ids"]
    assert payload["discovery_confidence"] == 90

    db = SessionLocal()
    try:
        canonical = db.query(DiscoveryRecord).filter_by(discovered_agent_id=canonical_id).one()
        merged = db.query(DiscoveryRecord).filter_by(discovered_agent_id=merge_id).one()
        assert canonical.discovery_status == "discovered"
        assert canonical.discovery_confidence == 90
        assert merged.discovery_status == "merged"
        assert merged.merged_into_discovered_agent_id == canonical_id
    finally:
        db.close()

    duplicates = client.get(
        "/discovery/duplicates",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-dup"},
    )
    assert duplicates.status_code == 200
    assert not any(row["canonical_agent_key"] == group_key.lower() for row in duplicates.json())


def test_discovery_duplicate_dismiss_rejects_record():
    group_key, canonical_id, merge_id = _seed_duplicate_group()

    resp = client.post(
        "/discovery/duplicates/dismiss",
        json={"discovered_agent_id": merge_id, "reason": "false_positive"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-dismiss"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "rejected"

    db = SessionLocal()
    try:
        dismissed = db.query(DiscoveryRecord).filter_by(discovered_agent_id=merge_id).one()
        assert dismissed.discovery_status == "rejected"
    finally:
        db.close()

    duplicates = client.get(
        "/discovery/duplicates",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-dup"},
    )
    assert duplicates.status_code == 200
    assert not any(row["canonical_agent_key"] == group_key.lower() for row in duplicates.json())
    assert canonical_id
