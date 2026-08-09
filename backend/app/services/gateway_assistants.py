from __future__ import annotations

import json
from datetime import datetime
from typing import Callable, Generator, Optional
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import (
    GatewayAssistantRecord,
    GatewayAssistantThreadMessageRecord,
    GatewayAssistantThreadRecord,
    GatewayAssistantThreadRunRecord,
)
from app.policy_constants import ROLE_AGENT_OWNER
from app.services.gateway_inference import (
    ResolvedInferenceCredential,
    execute_chat_completion,
    resolve_inference_credential,
    should_attempt_upstream,
    stream_chat_completion,
)


def _resolve_gateway_cursor_token(db: Session) -> str:
    from app.routers.gateway import _resolve_gateway_cursor_api_token

    return _resolve_gateway_cursor_api_token(db)


def _parse_metadata(raw: str) -> dict:
    try:
        parsed = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _serialize_assistant(record: GatewayAssistantRecord) -> dict:
    return {
        "id": record.assistant_id,
        "object": "assistant",
        "created_at": int(record.created_at.timestamp()),
        "name": record.name,
        "model": record.model,
        "instructions": record.instructions,
        "metadata": _parse_metadata(record.metadata_json),
        "environment": record.environment,
    }


def _serialize_thread(record: GatewayAssistantThreadRecord) -> dict:
    return {
        "id": record.thread_id,
        "object": "thread",
        "created_at": int(record.created_at.timestamp()),
        "metadata": _parse_metadata(record.metadata_json),
        "environment": record.environment,
    }


def _serialize_message(record: GatewayAssistantThreadMessageRecord) -> dict:
    return {
        "id": record.message_id,
        "object": "thread.message",
        "created_at": int(record.created_at.timestamp()),
        "thread_id": record.thread_id,
        "role": record.role,
        "content": [{"type": "text", "text": record.content}],
        "metadata": _parse_metadata(record.metadata_json),
    }


def _serialize_run(record: GatewayAssistantThreadRunRecord) -> dict:
    return {
        "id": record.run_id,
        "object": "thread.run",
        "created_at": int(record.created_at.timestamp()),
        "thread_id": record.thread_id,
        "assistant_id": record.assistant_id,
        "status": record.status,
        "model": record.model,
        "completed_at": int(record.completed_at.timestamp()) if record.completed_at else None,
        "response_text": record.response_text,
    }


def _enforce_owner_scope(actor_role: str, actor_id: str, owner_id: str, resource_label: str) -> None:
    if actor_role == ROLE_AGENT_OWNER and owner_id != actor_id:
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": f"Agent Owner can only access own {resource_label}.",
                "actor_role": actor_role,
                "required_scope": f"{resource_label}.actor_id == actor_id",
                "policy_version": "v1",
                "decision_trace_id": f"authz-gateway-{resource_label}-scope-check",
            },
        )


def create_assistant(
    db: Session,
    *,
    actor_id: str,
    name: str,
    model: str,
    instructions: str,
    metadata: dict,
    environment: str,
) -> dict:
    assistant_id = f"asst_{uuid4().hex[:24]}"
    record = GatewayAssistantRecord(
        assistant_id=assistant_id,
        actor_id=actor_id,
        environment=environment,
        name=name.strip(),
        model=model.strip(),
        instructions=instructions or "",
        metadata_json=json.dumps(metadata or {}, separators=(",", ":")),
        status="active",
    )
    db.add(record)
    db.flush()
    return _serialize_assistant(record)


def list_assistants(
    db: Session,
    *,
    actor_id: str,
    actor_role: str,
    limit: int,
    offset: int,
) -> list[dict]:
    query = db.query(GatewayAssistantRecord).filter(GatewayAssistantRecord.status != "deleted")
    if actor_role == ROLE_AGENT_OWNER:
        query = query.filter(GatewayAssistantRecord.actor_id == actor_id)
    rows = query.order_by(GatewayAssistantRecord.created_at.desc()).offset(offset).limit(limit).all()
    return [_serialize_assistant(row) for row in rows]


def get_assistant(
    db: Session,
    *,
    assistant_id: str,
    actor_id: str,
    actor_role: str,
) -> dict:
    record = db.query(GatewayAssistantRecord).filter_by(assistant_id=assistant_id).first()
    if record is None or record.status == "deleted":
        raise HTTPException(status_code=404, detail="Assistant not found")
    _enforce_owner_scope(actor_role, actor_id, record.actor_id, "assistant")
    return _serialize_assistant(record)


def delete_assistant(
    db: Session,
    *,
    assistant_id: str,
    actor_id: str,
    actor_role: str,
) -> dict:
    record = db.query(GatewayAssistantRecord).filter_by(assistant_id=assistant_id).first()
    if record is None or record.status == "deleted":
        raise HTTPException(status_code=404, detail="Assistant not found")
    _enforce_owner_scope(actor_role, actor_id, record.actor_id, "assistant")
    record.status = "deleted"
    record.deleted_at = datetime.utcnow()
    return {"id": record.assistant_id, "object": "assistant.deleted", "deleted": True}


def create_thread(
    db: Session,
    *,
    actor_id: str,
    metadata: dict,
    environment: str,
) -> dict:
    thread_id = f"thread_{uuid4().hex[:24]}"
    record = GatewayAssistantThreadRecord(
        thread_id=thread_id,
        actor_id=actor_id,
        environment=environment,
        metadata_json=json.dumps(metadata or {}, separators=(",", ":")),
        status="active",
    )
    db.add(record)
    db.flush()
    return _serialize_thread(record)


def get_thread(
    db: Session,
    *,
    thread_id: str,
    actor_id: str,
    actor_role: str,
) -> dict:
    record = db.query(GatewayAssistantThreadRecord).filter_by(thread_id=thread_id).first()
    if record is None:
        raise HTTPException(status_code=404, detail="Thread not found")
    _enforce_owner_scope(actor_role, actor_id, record.actor_id, "thread")
    return _serialize_thread(record)


def create_thread_message(
    db: Session,
    *,
    thread_id: str,
    actor_id: str,
    actor_role: str,
    role: str,
    content: str,
    metadata: dict,
) -> dict:
    thread = db.query(GatewayAssistantThreadRecord).filter_by(thread_id=thread_id).first()
    if thread is None:
        raise HTTPException(status_code=404, detail="Thread not found")
    _enforce_owner_scope(actor_role, actor_id, thread.actor_id, "thread")

    normalized_role = str(role or "user").strip().lower()
    if normalized_role not in {"user", "assistant"}:
        raise HTTPException(status_code=422, detail="role must be user or assistant")

    message_id = f"msg_{uuid4().hex[:24]}"
    record = GatewayAssistantThreadMessageRecord(
        message_id=message_id,
        thread_id=thread_id,
        actor_id=actor_id,
        role=normalized_role,
        content=str(content or "").strip(),
        metadata_json=json.dumps(metadata or {}, separators=(",", ":")),
    )
    db.add(record)
    db.flush()
    return _serialize_message(record)


def list_thread_messages(
    db: Session,
    *,
    thread_id: str,
    actor_id: str,
    actor_role: str,
    limit: int,
    offset: int,
) -> list[dict]:
    thread = db.query(GatewayAssistantThreadRecord).filter_by(thread_id=thread_id).first()
    if thread is None:
        raise HTTPException(status_code=404, detail="Thread not found")
    _enforce_owner_scope(actor_role, actor_id, thread.actor_id, "thread")

    rows = (
        db.query(GatewayAssistantThreadMessageRecord)
        .filter_by(thread_id=thread_id)
        .order_by(GatewayAssistantThreadMessageRecord.created_at.asc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [_serialize_message(row) for row in rows]


def _prepare_thread_run_context(
    db: Session,
    *,
    thread_id: str,
    assistant_id: str,
    actor_id: str,
    actor_role: str,
    environment: str,
    model_override: Optional[str],
    additional_instructions: str,
    ensure_inference_credentials: Callable[..., None],
) -> tuple[str, list[dict], str, str]:
    thread = db.query(GatewayAssistantThreadRecord).filter_by(thread_id=thread_id).first()
    if thread is None:
        raise HTTPException(status_code=404, detail="Thread not found")
    _enforce_owner_scope(actor_role, actor_id, thread.actor_id, "thread")

    assistant = db.query(GatewayAssistantRecord).filter_by(assistant_id=assistant_id).first()
    if assistant is None or assistant.status == "deleted":
        raise HTTPException(status_code=404, detail="Assistant not found")
    _enforce_owner_scope(actor_role, actor_id, assistant.actor_id, "assistant")

    model_name = str(model_override or assistant.model).strip() or assistant.model
    ensure_inference_credentials(db, agent_id=None, environment=environment, model_name=model_name)

    messages_rows = (
        db.query(GatewayAssistantThreadMessageRecord)
        .filter_by(thread_id=thread_id)
        .order_by(GatewayAssistantThreadMessageRecord.created_at.asc())
        .all()
    )
    chat_messages: list[dict] = []
    system_parts = [assistant.instructions.strip()]
    if additional_instructions.strip():
        system_parts.append(additional_instructions.strip())
    if any(part for part in system_parts):
        chat_messages.append({"role": "system", "content": "\n\n".join(part for part in system_parts if part)})

    for row in messages_rows:
        chat_messages.append({"role": row.role, "content": row.content})

    if not any(str(item.get("role") or "").lower() == "user" for item in chat_messages):
        raise HTTPException(status_code=422, detail="Thread must contain at least one user message before running")

    prompt_preview = next(
        (str(item.get("content") or "") for item in reversed(chat_messages) if str(item.get("role") or "").lower() == "user"),
        "",
    )
    return model_name, chat_messages, prompt_preview, assistant_id


def _persist_completed_thread_run(
    db: Session,
    *,
    thread_id: str,
    assistant_id: str,
    actor_id: str,
    environment: str,
    model_name: str,
    response_text: str,
    finish_reason: str,
    usage: dict,
    run_id: Optional[str] = None,
) -> dict:
    resolved_run_id = str(run_id or f"run_{uuid4().hex[:24]}")
    trace_id = f"trace-gateway-assistant-run-{resolved_run_id}"
    run_record = GatewayAssistantThreadRunRecord(
        run_id=resolved_run_id,
        thread_id=thread_id,
        assistant_id=assistant_id,
        actor_id=actor_id,
        environment=environment,
        model=model_name,
        status="completed",
        response_text=response_text,
        trace_id=trace_id,
        metadata_json=json.dumps(
            {
                "finish_reason": finish_reason,
                "usage": usage,
            },
            separators=(",", ":"),
        ),
        completed_at=datetime.utcnow(),
    )
    db.add(run_record)
    db.add(
        GatewayAssistantThreadMessageRecord(
            message_id=f"msg_{uuid4().hex[:24]}",
            thread_id=thread_id,
            actor_id=actor_id,
            role="assistant",
            content=response_text,
            metadata_json=json.dumps({"run_id": resolved_run_id}, separators=(",", ":")),
        )
    )
    db.flush()
    return _serialize_run(run_record)


def _chunk_text_for_stream(text: str, chunk_size: int = 24) -> list[str]:
    normalized = str(text or "")
    if not normalized:
        return [""]
    return [normalized[index : index + chunk_size] for index in range(0, len(normalized), chunk_size)]


def iter_thread_run_sse_chunks(
    db: Session,
    *,
    thread_id: str,
    assistant_id: str,
    actor_id: str,
    actor_role: str,
    environment: str,
    model_override: Optional[str],
    additional_instructions: str,
    ensure_inference_credentials: Callable[..., None],
) -> Generator[str, None, None]:
    model_name, chat_messages, prompt_preview, resolved_assistant_id = _prepare_thread_run_context(
        db,
        thread_id=thread_id,
        assistant_id=assistant_id,
        actor_id=actor_id,
        actor_role=actor_role,
        environment=environment,
        model_override=model_override,
        additional_instructions=additional_instructions,
        ensure_inference_credentials=ensure_inference_credentials,
    )
    inference_credential = resolve_inference_credential(
        db,
        model_name=model_name,
        environment=environment,
        agent_id=None,
        resolve_gateway_cursor_token=_resolve_gateway_cursor_token,
    )

    run_id = f"run_{uuid4().hex[:24]}"
    created_ts = int(datetime.utcnow().timestamp())
    created_payload = {
        "id": run_id,
        "object": "thread.run",
        "created_at": created_ts,
        "thread_id": thread_id,
        "assistant_id": resolved_assistant_id,
        "status": "in_progress",
        "model": model_name,
        "completed_at": None,
        "response_text": "",
    }
    yield f"data: {json.dumps(created_payload, separators=(',', ':'))}\n\n"

    response_text = ""
    finish_reason = "stop"
    usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    if inference_credential is not None and should_attempt_upstream(inference_credential):
        effective = ResolvedInferenceCredential(
            provider_type=inference_credential.provider_type,
            api_key=inference_credential.api_key,
            base_url=inference_credential.base_url,
            upstream_model=inference_credential.upstream_model or model_name,
            credential_source=inference_credential.credential_source,
        )
        try:
            for chunk in stream_chat_completion(effective, messages=chat_messages):
                if chunk == "[DONE]":
                    break
                try:
                    parsed = json.loads(chunk)
                except json.JSONDecodeError:
                    continue
                if not isinstance(parsed, dict):
                    continue
                choices = parsed.get("choices")
                if not isinstance(choices, list) or not choices:
                    continue
                delta = choices[0].get("delta") if isinstance(choices[0], dict) else {}
                piece = str((delta or {}).get("content") or "")
                if not piece:
                    continue
                response_text += piece
                delta_payload = {
                    "id": run_id,
                    "object": "thread.run.delta",
                    "created_at": created_ts,
                    "thread_id": thread_id,
                    "assistant_id": resolved_assistant_id,
                    "status": "in_progress",
                    "model": model_name,
                    "delta": {"response_text": piece},
                }
                yield f"data: {json.dumps(delta_payload, separators=(',', ':'))}\n\n"
            usage = {
                "prompt_tokens": max(1, len(prompt_preview.split())),
                "completion_tokens": max(1, len(response_text.split()) if response_text else 1),
                "total_tokens": max(2, len(prompt_preview.split()) + max(1, len(response_text.split()) if response_text else 1)),
            }
        except HTTPException as exc:
            error_payload = {
                "id": run_id,
                "object": "thread.run",
                "created_at": created_ts,
                "thread_id": thread_id,
                "assistant_id": resolved_assistant_id,
                "status": "failed",
                "model": model_name,
                "error": {"message": str(exc.detail)},
            }
            yield f"data: {json.dumps(error_payload, separators=(',', ':'))}\n\n"
            yield "data: [DONE]\n\n"
            return
    else:
        inference_result = execute_chat_completion(
            db,
            credential=inference_credential,
            model_name=model_name,
            messages=chat_messages,
            prompt_preview=prompt_preview,
        )
        response_text = inference_result.content
        finish_reason = inference_result.finish_reason
        usage = {
            "prompt_tokens": inference_result.usage.prompt_tokens,
            "completion_tokens": inference_result.usage.completion_tokens,
            "total_tokens": inference_result.usage.total_tokens,
        }
        for piece in _chunk_text_for_stream(response_text):
            delta_payload = {
                "id": run_id,
                "object": "thread.run.delta",
                "created_at": created_ts,
                "thread_id": thread_id,
                "assistant_id": resolved_assistant_id,
                "status": "in_progress",
                "model": model_name,
                "delta": {"response_text": piece},
            }
            yield f"data: {json.dumps(delta_payload, separators=(',', ':'))}\n\n"

    result = _persist_completed_thread_run(
        db,
        thread_id=thread_id,
        assistant_id=resolved_assistant_id,
        actor_id=actor_id,
        environment=environment,
        model_name=model_name,
        response_text=response_text,
        finish_reason=finish_reason,
        usage=usage,
        run_id=run_id,
    )
    completed_payload = dict(result)
    completed_payload["object"] = "thread.run"
    yield f"data: {json.dumps(completed_payload, separators=(',', ':'))}\n\n"
    yield "data: [DONE]\n\n"


def create_and_execute_thread_run(
    db: Session,
    *,
    thread_id: str,
    assistant_id: str,
    actor_id: str,
    actor_role: str,
    environment: str,
    model_override: Optional[str],
    additional_instructions: str,
    ensure_inference_credentials: Callable[..., None],
) -> dict:
    model_name, chat_messages, prompt_preview, resolved_assistant_id = _prepare_thread_run_context(
        db,
        thread_id=thread_id,
        assistant_id=assistant_id,
        actor_id=actor_id,
        actor_role=actor_role,
        environment=environment,
        model_override=model_override,
        additional_instructions=additional_instructions,
        ensure_inference_credentials=ensure_inference_credentials,
    )

    inference_credential = resolve_inference_credential(
        db,
        model_name=model_name,
        environment=environment,
        agent_id=None,
        resolve_gateway_cursor_token=_resolve_gateway_cursor_token,
    )
    inference_result = execute_chat_completion(
        db,
        credential=inference_credential,
        model_name=model_name,
        messages=chat_messages,
        prompt_preview=prompt_preview,
    )

    return _persist_completed_thread_run(
        db,
        thread_id=thread_id,
        assistant_id=resolved_assistant_id,
        actor_id=actor_id,
        environment=environment,
        model_name=model_name,
        response_text=inference_result.content,
        finish_reason=inference_result.finish_reason,
        usage={
            "prompt_tokens": inference_result.usage.prompt_tokens,
            "completion_tokens": inference_result.usage.completion_tokens,
            "total_tokens": inference_result.usage.total_tokens,
        },
    )


def get_thread_run(
    db: Session,
    *,
    thread_id: str,
    run_id: str,
    actor_id: str,
    actor_role: str,
) -> dict:
    thread = db.query(GatewayAssistantThreadRecord).filter_by(thread_id=thread_id).first()
    if thread is None:
        raise HTTPException(status_code=404, detail="Thread not found")
    _enforce_owner_scope(actor_role, actor_id, thread.actor_id, "thread")

    record = (
        db.query(GatewayAssistantThreadRunRecord)
        .filter_by(thread_id=thread_id, run_id=run_id)
        .first()
    )
    if record is None:
        raise HTTPException(status_code=404, detail="Thread run not found")
    return _serialize_run(record)
