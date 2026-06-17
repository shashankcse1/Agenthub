"""Cross-source discovery duplicate grouping and merge/dedup workflows."""

from __future__ import annotations

from typing import Iterable, Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import DiscoveryRecord
from app.services.audit import create_audit_event


def normalize_discovery_agent_key(key: str) -> str:
    normalized = str(key or "").strip().lower()
    if not normalized:
        return ""
    return normalized.split(":", 1)[-1] if ":" in normalized else normalized


def _active_duplicate_candidates(records: Iterable[DiscoveryRecord]) -> list[DiscoveryRecord]:
    return [
        record
        for record in records
        if record.discovery_status == "discovered" and not record.promoted_to_agent_id
    ]


def build_duplicate_groups(records: Iterable[DiscoveryRecord]) -> list[dict]:
    groups: dict[str, list[DiscoveryRecord]] = {}
    for record in _active_duplicate_candidates(records):
        normalized = normalize_discovery_agent_key(record.canonical_agent_key)
        if not normalized:
            continue
        groups.setdefault(normalized, []).append(record)

    duplicates = []
    for normalized_key, members in groups.items():
        if len(members) < 2:
            continue
        source_systems = sorted({str(record.source_system or "") for record in members if record.source_system})
        if len(source_systems) < 2:
            continue
        max_confidence = max(record.discovery_confidence for record in members)
        duplicates.append(
            {
                "canonical_agent_key": normalized_key,
                "duplicate_count": len(members),
                "source_systems": source_systems,
                "discovered_agent_ids": [record.discovered_agent_id for record in members],
                "max_confidence": max_confidence,
                "review_priority": "high" if max_confidence >= 85 else "normal",
                "members": [
                    {
                        "discovered_agent_id": record.discovered_agent_id,
                        "source_system": record.source_system,
                        "discovery_confidence": record.discovery_confidence,
                        "canonical_agent_key": record.canonical_agent_key,
                    }
                    for record in sorted(
                        members,
                        key=lambda item: (-item.discovery_confidence, item.source_system or ""),
                    )
                ],
            }
        )
    duplicates.sort(key=lambda item: (-item["duplicate_count"], -item["max_confidence"]))
    return duplicates


def _group_members_for_record(db: Session, record: DiscoveryRecord) -> list[DiscoveryRecord]:
    normalized = normalize_discovery_agent_key(record.canonical_agent_key)
    if not normalized:
        return [record]
    candidates = (
        db.query(DiscoveryRecord)
        .filter(
            DiscoveryRecord.discovery_status == "discovered",
            DiscoveryRecord.promoted_to_agent_id.is_(None),
        )
        .all()
    )
    members = [
        candidate
        for candidate in candidates
        if normalize_discovery_agent_key(candidate.canonical_agent_key) == normalized
    ]
    return members


def merge_discovery_duplicate_group(
    db: Session,
    *,
    canonical_discovered_agent_id: str,
    actor_id: str,
    merge_discovered_agent_ids: Optional[list[str]] = None,
) -> dict:
    canonical = db.query(DiscoveryRecord).filter_by(discovered_agent_id=canonical_discovered_agent_id).first()
    if not canonical:
        raise HTTPException(status_code=404, detail="Canonical discovery record not found")
    if canonical.discovery_status != "discovered" or canonical.promoted_to_agent_id:
        raise HTTPException(status_code=400, detail="Canonical record is not eligible for merge")

    group_members = _group_members_for_record(db, canonical)
    if len(group_members) < 2:
        raise HTTPException(status_code=400, detail="Record is not part of a duplicate group")

    source_systems = {str(record.source_system or "") for record in group_members if record.source_system}
    if len(source_systems) < 2:
        raise HTTPException(status_code=400, detail="Duplicate group must span multiple sources")

    merge_ids = {
        item.strip()
        for item in (merge_discovered_agent_ids or [])
        if isinstance(item, str) and item.strip()
    }
    if not merge_ids:
        merge_ids = {
            record.discovered_agent_id
            for record in group_members
            if record.discovered_agent_id != canonical.discovered_agent_id
        }

    if canonical.discovered_agent_id in merge_ids:
        raise HTTPException(status_code=400, detail="Canonical record cannot be merged into itself")

    merge_records = []
    for merge_id in merge_ids:
        record = db.query(DiscoveryRecord).filter_by(discovered_agent_id=merge_id).first()
        if not record:
            raise HTTPException(status_code=404, detail=f"Discovery record not found: {merge_id}")
        if record.discovered_agent_id == canonical.discovered_agent_id:
            continue
        if record.discovery_status != "discovered" or record.promoted_to_agent_id:
            raise HTTPException(status_code=400, detail=f"Record not eligible for merge: {merge_id}")
        if normalize_discovery_agent_key(record.canonical_agent_key) != normalize_discovery_agent_key(
            canonical.canonical_agent_key
        ):
            raise HTTPException(status_code=400, detail=f"Record is not in the same duplicate group: {merge_id}")
        merge_records.append(record)

    if not merge_records:
        raise HTTPException(status_code=400, detail="No duplicate records selected for merge")

    max_confidence = max([canonical.discovery_confidence, *(record.discovery_confidence for record in merge_records)])
    canonical.discovery_confidence = max_confidence

    merged_ids: list[str] = []
    for record in merge_records:
        record.discovery_status = "merged"
        record.merged_into_discovered_agent_id = canonical.discovered_agent_id
        merged_ids.append(record.discovered_agent_id)
        create_audit_event(
            db,
            actor_id=actor_id,
            action_type="discovery.duplicate.merge",
            resource_type="discovery_record",
            resource_id=record.discovered_agent_id,
            trace_id=f"trace-merge-{canonical.discovered_agent_id}",
        )

    create_audit_event(
        db,
        actor_id=actor_id,
        action_type="discovery.duplicate.merge",
        resource_type="discovery_record",
        resource_id=canonical.discovered_agent_id,
        trace_id=f"trace-merge-{canonical.discovered_agent_id}",
    )

    return {
        "canonical_discovered_agent_id": canonical.discovered_agent_id,
        "canonical_agent_key": normalize_discovery_agent_key(canonical.canonical_agent_key),
        "merged_discovered_agent_ids": merged_ids,
        "merged_count": len(merged_ids),
        "discovery_confidence": canonical.discovery_confidence,
        "status": "merged",
    }


def dismiss_discovery_duplicate(
    db: Session,
    *,
    discovered_agent_id: str,
    actor_id: str,
    reason: str = "",
) -> dict:
    record = db.query(DiscoveryRecord).filter_by(discovered_agent_id=discovered_agent_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Discovery record not found")
    if record.discovery_status != "discovered" or record.promoted_to_agent_id:
        raise HTTPException(status_code=400, detail="Record is not eligible for dismiss")

    record.discovery_status = "rejected"
    create_audit_event(
        db,
        actor_id=actor_id,
        action_type="discovery.duplicate.dismiss",
        resource_type="discovery_record",
        resource_id=record.discovered_agent_id,
        trace_id=f"trace-dismiss-{record.discovered_agent_id}",
    )
    return {
        "discovered_agent_id": record.discovered_agent_id,
        "status": record.discovery_status,
        "reason": reason.strip(),
    }
