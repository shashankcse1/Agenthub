from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.router_constants import (
    GATEWAY_ADMIN_OR_AI_OPS_ROLES,
    GATEWAY_READ_ROLES,
    ROLE_AGENT_OWNER,
)
from app.schemas import (
    GatewayRagIngestRequest,
    GatewayRagIngestResponse,
    GatewayRagQueryRequest,
    GatewayRagQueryResponse,
    GatewayVectorStoreOpenAIListResponse,
    GatewayVectorStoreOpenAIResponse,
    GatewayVectorStoreRegisterRequest,
)
from app.security import ActorContext, get_actor_context, require_role
from app.services.audit import create_audit_event
from app.services.gateway_rag import (
    rag_ingest,
    rag_query,
    serialize_openai_vector_store,
)
from app.services.gateway_vector_stores import get_vector_store_by_id, list_vector_stores

router = APIRouter()

_RAG_READ_ROLES = set(GATEWAY_READ_ROLES) | {ROLE_AGENT_OWNER}
_RAG_WRITE_ROLES = set(GATEWAY_ADMIN_OR_AI_OPS_ROLES) | {ROLE_AGENT_OWNER}

_READ_FORBIDDEN = {
    403: {"description": "Actor role is not allowed for vector store read operations."},
}
_WRITE_FORBIDDEN = {
    403: {"description": "Actor role is not allowed for RAG data plane operations."},
}
_NOT_FOUND = {
    404: {"description": "Vector store not found."},
}


@router.get(
    "/v1/vector_stores",
    response_model=GatewayVectorStoreOpenAIListResponse,
    summary="List configured vector stores (OpenAI-compatible)",
    description="Reads vector store registry from runtime config `gateway.vector_stores_json`.",
    responses=_READ_FORBIDDEN,
)
def openai_vector_stores_list(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _RAG_READ_ROLES)
    trace_id = f"trace-gateway-vector-stores-list-{uuid4()}"
    stores = [serialize_openai_vector_store(row) for row in list_vector_stores(db)]
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.vector_store.list",
        resource_type="vector_store",
        resource_id="registry",
        trace_id=trace_id,
    )
    db.commit()
    return {"object": "list", "data": stores}


@router.get(
    "/v1/vector_stores/{store_id}",
    response_model=GatewayVectorStoreOpenAIResponse,
    summary="Get vector store by id (OpenAI-compatible)",
    responses={**_READ_FORBIDDEN, **_NOT_FOUND},
)
def openai_vector_store_get(
    store_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _RAG_READ_ROLES)
    trace_id = f"trace-gateway-vector-store-get-{uuid4()}"
    store = get_vector_store_by_id(db, store_id)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.vector_store.read",
        resource_type="vector_store",
        resource_id=str(store_id),
        trace_id=trace_id,
    )
    db.commit()
    return serialize_openai_vector_store(store)


@router.post(
    "/v1/vector_stores",
    summary="Register vector store (control-plane read-only)",
    description=(
        "Vector stores are managed via runtime config `gateway.vector_stores_json` and "
        "Routing & Gateway → Memory & Context → Platform Configuration. This endpoint validates "
        "intent and returns guidance; it does not mutate the registry."
    ),
    responses={
        **_WRITE_FORBIDDEN,
        409: {"description": "Registry is read-only; configure via runtime config."},
    },
)
def openai_vector_store_register(
    payload: GatewayVectorStoreRegisterRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _RAG_WRITE_ROLES)
    trace_id = f"trace-gateway-vector-store-register-{uuid4()}"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.vector_store.register_attempt",
        resource_type="vector_store",
        resource_id=str(payload.store_id),
        trace_id=trace_id,
        decision_outcome="deny",
    )
    db.commit()
    raise HTTPException(
        status_code=409,
        detail={
            "error_code": "VECTOR_STORE_REGISTRY_READ_ONLY",
            "message": (
                "Vector store registry is control-plane managed via gateway.vector_stores_json. "
                "Use Platform Configuration or PUT /runtime-config/gateway.vector_stores_json."
            ),
            "decision_trace_id": trace_id,
            "store_id": payload.store_id,
        },
    )


@router.post(
    "/rag/ingest",
    response_model=GatewayRagIngestResponse,
    summary="Ingest documents into configured vector store",
    description="Delegates to MCP bridge vector.upsert for mcp_bridge stores.",
    responses={**_WRITE_FORBIDDEN, **_NOT_FOUND, 422: {"description": "Validation or unsupported provider."}},
)
def gateway_rag_ingest(
    payload: GatewayRagIngestRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _RAG_WRITE_ROLES)
    trace_id = f"trace-gateway-rag-ingest-{uuid4()}"
    try:
        result = rag_ingest(
            db,
            store_id=payload.store_id,
            documents=[doc.model_dump() for doc in payload.documents],
            metadata=payload.metadata,
        )
    except HTTPException as exc:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.rag.ingest",
            resource_type="vector_store",
            resource_id=str(payload.store_id),
            trace_id=trace_id,
            decision_outcome="deny" if exc.status_code in {403, 409, 422} else "warn",
        )
        db.commit()
        raise

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.rag.ingest",
        resource_type="vector_store",
        resource_id=str(payload.store_id),
        trace_id=trace_id,
    )
    db.commit()
    return {**result, "trace_id": trace_id}


@router.post(
    "/rag/query",
    response_model=GatewayRagQueryResponse,
    summary="Semantic search against configured vector store",
    description="Delegates to MCP bridge vector.search for mcp_bridge stores.",
    responses={**_WRITE_FORBIDDEN, **_NOT_FOUND, 422: {"description": "Validation or unsupported provider."}},
)
def gateway_rag_query(
    payload: GatewayRagQueryRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _RAG_WRITE_ROLES)
    trace_id = f"trace-gateway-rag-query-{uuid4()}"
    try:
        result = rag_query(
            db,
            store_id=payload.store_id,
            query=payload.query,
            top_k=payload.top_k,
        )
    except HTTPException as exc:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.rag.query",
            resource_type="vector_store",
            resource_id=str(payload.store_id),
            trace_id=trace_id,
            decision_outcome="deny" if exc.status_code in {403, 409, 422} else "warn",
        )
        db.commit()
        raise

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.rag.query",
        resource_type="vector_store",
        resource_id=str(payload.store_id),
        trace_id=trace_id,
    )
    db.commit()
    return {**result, "trace_id": trace_id}
