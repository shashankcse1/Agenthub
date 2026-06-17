from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.logging_utils import get_logger, sanitize_fields
from app.models import DiscoveryConnection, DiscoveryRecord
from app.services.audit import create_audit_event
from app.services.discovery_connection_service import (
    build_connection_runtime,
    schedule_next_sync,
)
from app.services.discovery_connectors.registry import fetch_for_runtime
from app.services import discovery_sync as internal_sync
from app.services.discovery_connectors.types import DiscoveryCandidate

logger = get_logger(__name__)


def _upsert_candidate(
    db: Session,
    *,
    source_id: str,
    connection_id: str,
    candidate: DiscoveryCandidate,
) -> DiscoveryRecord:
    now = datetime.utcnow()
    fingerprint = f"{connection_id}:{candidate.source_fingerprint}"
    existing = (
        db.query(DiscoveryRecord)
        .filter(
            DiscoveryRecord.source_system == source_id,
            DiscoveryRecord.source_fingerprint == fingerprint,
        )
        .first()
    )
    if existing:
        existing.canonical_agent_key = candidate.canonical_agent_key
        existing.discovery_confidence = candidate.confidence
        existing.last_discovered_at = now
        return existing

    record = DiscoveryRecord(
        discovered_agent_id=str(uuid4()),
        canonical_agent_key=candidate.canonical_agent_key,
        source_system=source_id,
        source_fingerprint=fingerprint,
        discovery_confidence=candidate.confidence,
        discovery_status="discovered",
        last_discovered_at=now,
    )
    db.add(record)
    return record


def sync_discovery_connection(
    db: Session,
    connection: DiscoveryConnection,
    *,
    actor_id: str,
    trace_prefix: str = "discovery.connection.sync",
) -> tuple[int, Optional[str]]:
    error: Optional[str] = None
    discovered_count = 0
    now = datetime.utcnow()
    try:
        runtime = build_connection_runtime(db, connection)
        candidates = fetch_for_runtime(db, runtime)
        for candidate in candidates:
            _upsert_candidate(
                db,
                source_id=connection.source_id,
                connection_id=connection.connection_id,
                candidate=candidate,
            )
        discovered_count = len(candidates)
        connection.last_sync_status = "success"
        connection.last_sync_error = ""
    except Exception as exc:
        error = str(exc)
        connection.last_sync_status = "failed"
        connection.last_sync_error = error[:2000]
        logger.warning(
            "discovery_connection_sync_failed %s",
            sanitize_fields(
                {
                    "connection_id": connection.connection_id,
                    "source_id": connection.source_id,
                    "error": error,
                }
            ),
        )

    connection.last_sync_at = now
    connection.last_discovered_count = discovered_count
    schedule_next_sync(connection, from_time=now)

    create_audit_event(
        db,
        actor_id=actor_id,
        action_type=trace_prefix,
        resource_type="discovery_connection",
        resource_id=connection.connection_id,
        trace_id=f"trace-{connection.connection_id}-{uuid4()}",
    )
    return discovered_count, error


def sync_discovery_source_live(
    db: Session,
    source_id: str,
    *,
    actor_id: str,
) -> tuple[int, int, int]:
    connections = (
        db.query(DiscoveryConnection)
        .filter(
            DiscoveryConnection.source_id == source_id,
            DiscoveryConnection.enabled.is_(True),
            DiscoveryConnection.status == "active",
        )
        .order_by(DiscoveryConnection.connection_name.asc())
        .all()
    )

    if connections:
        total = 0
        succeeded = 0
        failed = 0
        for connection in connections:
            count, error = sync_discovery_connection(db, connection, actor_id=actor_id)
            total += count
            if error:
                failed += 1
            else:
                succeeded += 1
        return total, succeeded, failed

    records = internal_sync.sync_discovery_source_records(db, source_id)
    for record in records:
        _upsert_candidate(
            db,
            source_id=source_id,
            connection_id="internal",
            candidate=DiscoveryCandidate(
                canonical_agent_key=record.canonical_agent_key,
                source_fingerprint=record.source_fingerprint,
                confidence=record.discovery_confidence,
                metadata={"live": False, "internal": True},
            ),
        )
    if records:
        return len(records), 1, 0

    return 0, 0, 0


def run_due_discovery_syncs(db: Session, *, actor_id: str = "discovery-scheduler") -> dict[str, int]:
    now = datetime.utcnow()
    due = (
        db.query(DiscoveryConnection)
        .filter(
            DiscoveryConnection.enabled.is_(True),
            DiscoveryConnection.status == "active",
            DiscoveryConnection.next_sync_at <= now,
        )
        .order_by(DiscoveryConnection.next_sync_at.asc())
        .limit(100)
        .all()
    )
    processed = 0
    succeeded = 0
    failed = 0
    discovered = 0
    for connection in due:
        count, error = sync_discovery_connection(
            db,
            connection,
            actor_id=actor_id,
            trace_prefix="discovery.connection.scheduled_sync",
        )
        processed += 1
        discovered += count
        if error:
            failed += 1
        else:
            succeeded += 1
    if processed:
        db.commit()
    return {
        "processed": processed,
        "succeeded": succeeded,
        "failed": failed,
        "discovered": discovered,
    }
