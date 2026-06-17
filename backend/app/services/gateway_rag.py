from __future__ import annotations

import json
from typing import Any, Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_SEARCH_TOP_K
from app.services.gateway_vector_stores import (
    get_vector_store_by_id,
    resolve_vector_store_api_key,
    vector_store_settings,
)
from app.services.mcp_gateway import call_tool as mcp_call_tool, resolve_mcp_server
from app.services.runtime_config import get_runtime_config_int


def _normalize_tool_result(result: object) -> dict[str, Any]:
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, list):
            for item in content:
                if not isinstance(item, dict):
                    continue
                text = str(item.get("text") or "").strip()
                if not text:
                    continue
                try:
                    parsed = json.loads(text)
                    if isinstance(parsed, dict):
                        return parsed
                    if isinstance(parsed, list):
                        return {"results": parsed}
                except json.JSONDecodeError:
                    return {"text": text}
        if "results" in result or "documents" in result or "matches" in result:
            return result
        return {"result": result}
    if isinstance(result, list):
        return {"results": result}
    if result is None:
        return {}
    return {"result": result}


def _build_store_tool_context(db: Session, store: dict) -> dict[str, Any]:
    settings = vector_store_settings(db)
    api_key = resolve_vector_store_api_key(db, store)
    context: dict[str, Any] = {
        "store_id": store["store_id"],
        "provider_type": store["provider_type"],
        "collection": store["collection_name"],
        "embedding_dimensions": store["embedding_dimensions"],
        "similarity_metric": store["similarity_metric"],
        "connection_url": store.get("connection_url") or None,
        "embedding_model": settings["embedding_model"],
        "secret_configured": bool(api_key),
    }
    if api_key:
        context["credentials"] = {"api_key": api_key}
    return context


def _ensure_store_ready(store: dict) -> None:
    if not store.get("enabled"):
        raise HTTPException(
            status_code=409,
            detail={
                "error_code": "VECTOR_STORE_DISABLED",
                "message": f"Vector store {store['store_id']} is disabled.",
                "decision_trace_id": "gateway-rag-store-disabled",
            },
        )


def _invoke_mcp_vector_tool(
    db: Session,
    store: dict,
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    mcp_server_id = str(store.get("mcp_server_id") or "").strip()
    if not mcp_server_id:
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "VALIDATION_ERROR",
                "message": "mcp_server_id is required for mcp_bridge vector stores.",
                "decision_trace_id": "gateway-rag-mcp-server-missing",
            },
        )
    server = resolve_mcp_server(db, mcp_server_id)
    merged = {**_build_store_tool_context(db, store), **arguments}
    result = mcp_call_tool(db, server, tool_name, merged)
    return _normalize_tool_result(result)


def rag_ingest(
    db: Session,
    *,
    store_id: str,
    documents: list[dict[str, Any]],
    metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    store = get_vector_store_by_id(db, store_id)
    _ensure_store_ready(store)

    if not documents:
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "VALIDATION_ERROR",
                "message": "documents must include at least one item.",
                "decision_trace_id": "gateway-rag-ingest-empty",
            },
        )

    normalized_docs: list[dict[str, Any]] = []
    for idx, doc in enumerate(documents):
        if not isinstance(doc, dict):
            raise HTTPException(
                status_code=422,
                detail={
                    "error_code": "VALIDATION_ERROR",
                    "message": f"documents[{idx}] must be an object.",
                    "decision_trace_id": "gateway-rag-ingest-doc-shape",
                },
            )
        text = str(doc.get("text") or doc.get("content") or "").strip()
        if not text:
            raise HTTPException(
                status_code=422,
                detail={
                    "error_code": "VALIDATION_ERROR",
                    "message": f"documents[{idx}] requires text or content.",
                    "decision_trace_id": "gateway-rag-ingest-doc-text",
                },
            )
        normalized_docs.append(
            {
                "id": str(doc.get("id") or doc.get("document_id") or f"doc-{idx}"),
                "text": text,
                "metadata": doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {},
            }
        )

    if store["provider_type"] != "mcp_bridge":
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "VECTOR_STORE_ADAPTER_UNSUPPORTED",
                "message": (
                    f"Provider type {store['provider_type']} is not supported for RAG ingest in v1. "
                    "Use mcp_bridge and MCP tools vector.upsert."
                ),
                "decision_trace_id": "gateway-rag-ingest-unsupported-provider",
            },
        )

    tool_result = _invoke_mcp_vector_tool(
        db,
        store,
        "vector.upsert",
        {
            "documents": normalized_docs,
            "metadata": metadata if isinstance(metadata, dict) else {},
        },
    )
    ingested = int(tool_result.get("ingested") or tool_result.get("count") or len(normalized_docs))
    return {
        "object": "rag.ingest",
        "store_id": store_id,
        "provider_type": store["provider_type"],
        "ingested": ingested,
        "document_ids": [doc["id"] for doc in normalized_docs],
        "upstream": tool_result,
    }


def rag_query(
    db: Session,
    *,
    store_id: str,
    query: str,
    top_k: Optional[int] = None,
) -> dict[str, Any]:
    store = get_vector_store_by_id(db, store_id)
    _ensure_store_ready(store)

    normalized_query = str(query or "").strip()
    if not normalized_query:
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "VALIDATION_ERROR",
                "message": "query is required.",
                "decision_trace_id": "gateway-rag-query-empty",
            },
        )

    resolved_top_k = top_k
    if resolved_top_k is None:
        resolved_top_k = get_runtime_config_int(db, RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_SEARCH_TOP_K, 8)
    resolved_top_k = max(1, min(100, int(resolved_top_k)))

    if store["provider_type"] != "mcp_bridge":
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "VECTOR_STORE_ADAPTER_UNSUPPORTED",
                "message": (
                    f"Provider type {store['provider_type']} is not supported for RAG query in v1. "
                    "Use mcp_bridge and MCP tool vector.search."
                ),
                "decision_trace_id": "gateway-rag-query-unsupported-provider",
            },
        )

    tool_result = _invoke_mcp_vector_tool(
        db,
        store,
        "vector.search",
        {
            "query": normalized_query,
            "top_k": resolved_top_k,
        },
    )
    matches = tool_result.get("results") or tool_result.get("matches") or tool_result.get("documents") or []
    if not isinstance(matches, list):
        matches = [matches] if matches else []
    return {
        "object": "rag.query",
        "store_id": store_id,
        "provider_type": store["provider_type"],
        "query": normalized_query,
        "top_k": resolved_top_k,
        "matches": matches,
        "match_count": len(matches),
        "upstream": tool_result,
    }


def serialize_openai_vector_store(store: dict) -> dict[str, Any]:
    return {
        "id": store["store_id"],
        "object": "vector_store",
        "name": store.get("collection_name") or store["store_id"],
        "status": "completed" if store.get("enabled") else "expired",
        "provider_type": store["provider_type"],
        "embedding_dimensions": store["embedding_dimensions"],
        "similarity_metric": store["similarity_metric"],
        "mcp_server_id": store.get("mcp_server_id"),
        "metadata": store.get("metadata") or {},
    }
