from __future__ import annotations

import json
from typing import Any, Optional

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import OpenAIFileRecord
from app.services.gateway_inference import (
    ResolvedInferenceCredential,
    inference_timeout_seconds,
    resolve_inference_credential,
    should_attempt_upstream,
)


def _resolve_gateway_cursor_token(db: Session) -> str:
    from app.routers.gateway import _resolve_gateway_cursor_api_token

    return _resolve_gateway_cursor_api_token(db)


def resolve_fine_tuning_credential(
    db: Session,
    *,
    model: str,
    environment: str,
) -> Optional[ResolvedInferenceCredential]:
    credential = resolve_inference_credential(
        db,
        model_name=model,
        environment=environment,
        agent_id=None,
        resolve_gateway_cursor_token=_resolve_gateway_cursor_token,
    )
    if credential is None or not should_attempt_upstream(credential):
        return None
    return ResolvedInferenceCredential(
        provider_type=credential.provider_type,
        api_key=credential.api_key,
        base_url=str(credential.base_url or "").rstrip("/"),
        upstream_model=credential.upstream_model or model,
        credential_source=credential.credential_source,
    )


def _auth_headers(credential: ResolvedInferenceCredential) -> dict[str, str]:
    if credential.provider_type == "anthropic":
        return {
            "x-api-key": credential.api_key,
            "anthropic-version": "2023-06-01",
        }
    return {"Authorization": f"Bearer {credential.api_key}"}


def _parse_metadata(raw: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _map_upstream_status(raw: str) -> str:
    normalized = str(raw or "").strip().lower()
    mapping = {
        "validating_files": "validating",
        "queued": "queued",
        "running": "running",
        "succeeded": "succeeded",
        "failed": "failed",
        "cancelled": "cancelled",
    }
    return mapping.get(normalized, normalized or "queued")


def ensure_upstream_training_file(
    db: Session,
    *,
    file_record: OpenAIFileRecord,
    credential: ResolvedInferenceCredential,
) -> str:
    metadata = _parse_metadata(file_record.metadata_json)
    upstream_file_id = str(metadata.get("upstream_file_id") or "").strip()
    if upstream_file_id:
        return upstream_file_id

    # Minimal JSONL placeholder for operator-driven live fine-tuning when local file metadata only exists.
    jsonl_body = (
        json.dumps({"messages": [{"role": "user", "content": "fine-tune sample"}]}, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    files_url = f"{credential.base_url}/files"
    try:
        response = httpx.post(
            files_url,
            headers={**_auth_headers(credential), "Content-Type": "multipart/form-data"},
            files={
                "file": (file_record.filename or "training.jsonl", jsonl_body, "application/jsonl"),
            },
            data={"purpose": "fine-tune"},
            timeout=inference_timeout_seconds(),
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Upstream file upload failed: {exc}") from exc

    if response.status_code >= 400:
        detail = response.text[:500]
        raise HTTPException(status_code=502, detail=f"Upstream file upload rejected: {detail}")

    payload = response.json()
    upstream_file_id = str(payload.get("id") or "").strip()
    if not upstream_file_id:
        raise HTTPException(status_code=502, detail="Upstream file upload returned no file id")

    metadata["upstream_file_id"] = upstream_file_id
    file_record.metadata_json = json.dumps(metadata, separators=(",", ":"))
    db.flush()
    return upstream_file_id


def create_upstream_fine_tuning_job(
    credential: ResolvedInferenceCredential,
    *,
    model: str,
    training_file_id: str,
) -> dict[str, Any]:
    url = f"{credential.base_url}/fine_tuning/jobs"
    body = {"model": model, "training_file": training_file_id}
    try:
        response = httpx.post(
            url,
            headers={**_auth_headers(credential), "Content-Type": "application/json"},
            json=body,
            timeout=inference_timeout_seconds(),
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Upstream fine-tuning create failed: {exc}") from exc

    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Upstream fine-tuning create rejected: {response.text[:500]}")

    payload = response.json()
    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail="Upstream fine-tuning create returned invalid payload")
    return payload


def fetch_upstream_fine_tuning_job(
    credential: ResolvedInferenceCredential,
    *,
    upstream_job_id: str,
) -> dict[str, Any]:
    url = f"{credential.base_url}/fine_tuning/jobs/{upstream_job_id}"
    try:
        response = httpx.get(
            url,
            headers=_auth_headers(credential),
            timeout=inference_timeout_seconds(),
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Upstream fine-tuning retrieve failed: {exc}") from exc

    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Upstream fine-tuning retrieve rejected: {response.text[:500]}")

    payload = response.json()
    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail="Upstream fine-tuning retrieve returned invalid payload")
    return payload


def cancel_upstream_fine_tuning_job(
    credential: ResolvedInferenceCredential,
    *,
    upstream_job_id: str,
) -> dict[str, Any]:
    url = f"{credential.base_url}/fine_tuning/jobs/{upstream_job_id}/cancel"
    try:
        response = httpx.post(
            url,
            headers=_auth_headers(credential),
            timeout=inference_timeout_seconds(),
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Upstream fine-tuning cancel failed: {exc}") from exc

    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Upstream fine-tuning cancel rejected: {response.text[:500]}")

    payload = response.json()
    return payload if isinstance(payload, dict) else {"status": "cancelled"}


def apply_upstream_job_payload(record, payload: dict[str, Any]) -> None:
    status = _map_upstream_status(str(payload.get("status") or ""))
    record.status = status
    fine_tuned = payload.get("fine_tuned_model")
    if fine_tuned:
        record.fine_tuned_model = str(fine_tuned)
    finished_at = payload.get("finished_at")
    if finished_at is not None:
        try:
            from datetime import datetime

            record.finished_at = datetime.utcfromtimestamp(int(finished_at))
        except (TypeError, ValueError, OSError):
            pass
