from __future__ import annotations

import json
from datetime import datetime
from typing import Optional
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import GatewayFineTuningJobRecord, OpenAIFileRecord
from app.policy_constants import ROLE_AGENT_OWNER
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_FINE_TUNING_LIVE_ENABLED
from app.services.gateway_fine_tuning_upstream import (
    apply_upstream_job_payload,
    cancel_upstream_fine_tuning_job,
    create_upstream_fine_tuning_job,
    ensure_upstream_training_file,
    fetch_upstream_fine_tuning_job,
    resolve_fine_tuning_credential,
)
from app.services.runtime_config import get_runtime_config

FINE_TUNING_TERMINAL_STATUSES = {"succeeded", "failed", "cancelled"}
FINE_TUNING_CANCELLABLE_STATUSES = {"queued", "running", "validating", "validating_files"}


def _parse_metadata(raw: str) -> dict:
    try:
        parsed = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _serialize_job(record: GatewayFineTuningJobRecord, *, live_mode: bool = False) -> dict:
    metadata = _parse_metadata(record.metadata_json)
    payload = {
        "id": record.job_id,
        "object": "fine_tuning.job",
        "created_at": int(record.created_at.timestamp()),
        "model": record.model,
        "training_file_id": record.training_file_id,
        "fine_tuned_model": record.fine_tuned_model,
        "status": record.status,
        "finished_at": int(record.finished_at.timestamp()) if record.finished_at else None,
        "environment": record.environment,
        "live_mode": live_mode,
        "upstream_job_id": metadata.get("upstream_job_id"),
    }
    return payload


def _live_enabled(db: Session) -> bool:
    return get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_FINE_TUNING_LIVE_ENABLED, "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _enforce_owner_scope(actor_role: str, actor_id: str, owner_id: str) -> None:
    if actor_role == ROLE_AGENT_OWNER and owner_id != actor_id:
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only access own fine-tuning jobs.",
                "actor_role": actor_role,
                "policy_version": "v1",
                "decision_trace_id": "authz-gateway-fine-tuning-scope-check",
            },
        )


def _validate_training_file(db: Session, training_file_id: str, actor_id: str, actor_role: str) -> OpenAIFileRecord:
    row = db.query(OpenAIFileRecord).filter_by(file_id=training_file_id).first()
    if row is None or row.status == "deleted":
        raise HTTPException(status_code=404, detail="Training file not found")
    if actor_role == ROLE_AGENT_OWNER and row.actor_id != actor_id:
        raise HTTPException(status_code=403, detail="Training file is not accessible for this actor")
    return row


def _simulate_completion(record: GatewayFineTuningJobRecord) -> None:
    if record.status in FINE_TUNING_TERMINAL_STATUSES:
        return
    record.status = "succeeded"
    record.fine_tuned_model = f"ft:{record.model}:{record.job_id[:12]}"
    record.finished_at = datetime.utcnow()


def _sync_upstream_job(db: Session, record: GatewayFineTuningJobRecord) -> None:
    metadata = _parse_metadata(record.metadata_json)
    upstream_job_id = str(metadata.get("upstream_job_id") or "").strip()
    if not upstream_job_id:
        return
    if record.status in FINE_TUNING_TERMINAL_STATUSES:
        return
    credential = resolve_fine_tuning_credential(db, model=record.model, environment=record.environment)
    if credential is None:
        return
    payload = fetch_upstream_fine_tuning_job(credential, upstream_job_id=upstream_job_id)
    apply_upstream_job_payload(record, payload)
    metadata["upstream_status"] = payload.get("status")
    record.metadata_json = json.dumps(metadata, separators=(",", ":"))


def _submit_upstream_job(
    db: Session,
    *,
    record: GatewayFineTuningJobRecord,
    file_record: OpenAIFileRecord,
) -> None:
    credential = resolve_fine_tuning_credential(db, model=record.model, environment=record.environment)
    if credential is None:
        metadata = _parse_metadata(record.metadata_json)
        metadata["upstream_error"] = "Inference credentials not configured for live fine-tuning"
        record.metadata_json = json.dumps(metadata, separators=(",", ":"))
        record.status = "failed"
        record.finished_at = datetime.utcnow()
        return

    upstream_training_file = ensure_upstream_training_file(db, file_record=file_record, credential=credential)
    payload = create_upstream_fine_tuning_job(
        credential,
        model=record.model,
        training_file_id=upstream_training_file,
    )
    metadata = _parse_metadata(record.metadata_json)
    metadata["upstream_job_id"] = str(payload.get("id") or "").strip()
    metadata["upstream_training_file_id"] = upstream_training_file
    metadata["upstream_status"] = payload.get("status")
    record.metadata_json = json.dumps(metadata, separators=(",", ":"))
    apply_upstream_job_payload(record, payload)


def create_fine_tuning_job(
    db: Session,
    *,
    actor_id: str,
    actor_role: str,
    model: str,
    training_file_id: str,
    environment: str,
    metadata: dict,
) -> dict:
    file_record = _validate_training_file(db, training_file_id, actor_id, actor_role)
    job_id = f"ftjob_{uuid4().hex[:24]}"
    live_mode = _live_enabled(db)
    merged_metadata = dict(metadata or {})
    merged_metadata["live_mode_requested"] = live_mode
    record = GatewayFineTuningJobRecord(
        job_id=job_id,
        actor_id=actor_id,
        environment=environment,
        model=model.strip(),
        training_file_id=training_file_id.strip(),
        status="queued",
        metadata_json=json.dumps(merged_metadata, separators=(",", ":")),
    )
    db.add(record)
    db.flush()

    if live_mode:
        _submit_upstream_job(db, record=record, file_record=file_record)
    else:
        _simulate_completion(record)
    db.flush()

    return _serialize_job(record, live_mode=live_mode)


def list_fine_tuning_jobs(
    db: Session,
    *,
    actor_id: str,
    actor_role: str,
    limit: int,
    offset: int,
) -> list[dict]:
    live_mode = _live_enabled(db)
    query = db.query(GatewayFineTuningJobRecord)
    if actor_role == ROLE_AGENT_OWNER:
        query = query.filter(GatewayFineTuningJobRecord.actor_id == actor_id)
    rows = query.order_by(GatewayFineTuningJobRecord.created_at.desc()).offset(offset).limit(limit).all()
    if live_mode:
        for row in rows:
            if row.status not in FINE_TUNING_TERMINAL_STATUSES:
                try:
                    _sync_upstream_job(db, row)
                except HTTPException:
                    pass
    return [_serialize_job(row, live_mode=live_mode) for row in rows]


def get_fine_tuning_job(
    db: Session,
    *,
    job_id: str,
    actor_id: str,
    actor_role: str,
) -> dict:
    record = db.query(GatewayFineTuningJobRecord).filter_by(job_id=job_id).first()
    if record is None:
        raise HTTPException(status_code=404, detail="Fine-tuning job not found")
    _enforce_owner_scope(actor_role, actor_id, record.actor_id)
    live_mode = _live_enabled(db)
    if live_mode:
        if record.status not in FINE_TUNING_TERMINAL_STATUSES:
            _sync_upstream_job(db, record)
    elif not live_mode:
        _simulate_completion(record)
    return _serialize_job(record, live_mode=live_mode)


def cancel_fine_tuning_job(
    db: Session,
    *,
    job_id: str,
    actor_id: str,
    actor_role: str,
) -> dict:
    record = db.query(GatewayFineTuningJobRecord).filter_by(job_id=job_id).first()
    if record is None:
        raise HTTPException(status_code=404, detail="Fine-tuning job not found")
    _enforce_owner_scope(actor_role, actor_id, record.actor_id)

    if record.status in FINE_TUNING_TERMINAL_STATUSES:
        raise HTTPException(status_code=409, detail=f"Job cannot be cancelled from status {record.status}")
    if record.status not in FINE_TUNING_CANCELLABLE_STATUSES:
        raise HTTPException(status_code=409, detail=f"Invalid cancel transition from status {record.status}")

    live_mode = _live_enabled(db)
    metadata = _parse_metadata(record.metadata_json)
    upstream_job_id = str(metadata.get("upstream_job_id") or "").strip()
    if live_mode and upstream_job_id:
        credential = resolve_fine_tuning_credential(db, model=record.model, environment=record.environment)
        if credential is not None:
            payload = cancel_upstream_fine_tuning_job(credential, upstream_job_id=upstream_job_id)
            apply_upstream_job_payload(record, payload)

    record.status = "cancelled"
    record.finished_at = datetime.utcnow()
    return {"id": record.job_id, "object": "fine_tuning.job", "status": "cancelled", "live_mode": live_mode}
