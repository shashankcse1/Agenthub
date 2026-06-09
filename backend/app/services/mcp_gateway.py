import json
import os
from typing import Optional
from uuid import uuid4

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.runtime_constants import (
    RUNTIME_CONFIG_GATEWAY_MCP_DEFAULT_TIMEOUT_SECONDS,
    RUNTIME_CONFIG_GATEWAY_MCP_SERVERS_JSON,
)
from app.services.runtime_config import get_runtime_config, get_runtime_config_float


_ALLOWED_TRANSPORTS = {"streamable_http", "http"}


def _is_localish_environment() -> bool:
    value = (os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "dev").strip().lower()
    return value in {"dev", "test", "local"}


def _validate_server_record(record: dict, idx: int) -> tuple[bool, str]:
    server_id = str(record.get("server_id") or "").strip()
    base_url = str(record.get("base_url") or "").strip()
    transport = str(record.get("transport") or "streamable_http").strip().lower()

    if not server_id:
        return False, f"gateway.mcp.servers_json[{idx}] missing server_id"
    if not base_url:
        return False, f"gateway.mcp.servers_json[{idx}] missing base_url"
    if transport not in _ALLOWED_TRANSPORTS:
        return False, f"gateway.mcp.servers_json[{idx}] has unsupported transport"

    if not _is_localish_environment() and not base_url.startswith("https://"):
        return False, f"gateway.mcp.servers_json[{idx}] base_url must use https outside local/test/dev"

    allowed_tools = record.get("allowed_tools", [])
    if not isinstance(allowed_tools, list) or any(not isinstance(item, str) for item in allowed_tools):
        return False, f"gateway.mcp.servers_json[{idx}] allowed_tools must be a JSON array of strings"

    enabled = record.get("enabled", True)
    if not isinstance(enabled, bool):
        return False, f"gateway.mcp.servers_json[{idx}] enabled must be boolean"

    return True, ""


def validate_mcp_servers_json(raw: str) -> Optional[str]:
    try:
        parsed = json.loads(raw)
    except Exception:
        return "gateway.mcp.servers_json must be valid JSON"

    if not isinstance(parsed, list):
        return "gateway.mcp.servers_json must be a JSON array"

    seen_server_ids: set[str] = set()
    for idx, item in enumerate(parsed):
        if not isinstance(item, dict):
            return f"gateway.mcp.servers_json[{idx}] must be a JSON object"
        valid, error = _validate_server_record(item, idx)
        if not valid:
            return error
        server_id = str(item.get("server_id") or "").strip()
        if server_id in seen_server_ids:
            return f"gateway.mcp.servers_json duplicate server_id: {server_id}"
        seen_server_ids.add(server_id)

    return None


def _parse_servers_json(raw: str) -> list[dict]:
    try:
        parsed = json.loads(raw or "[]")
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Invalid gateway.mcp.servers_json runtime config") from exc

    if not isinstance(parsed, list):
        raise HTTPException(status_code=500, detail="Invalid gateway.mcp.servers_json runtime config")

    error = validate_mcp_servers_json(raw or "[]")
    if error:
        raise HTTPException(status_code=500, detail=error)

    normalized: list[dict] = []
    for row in parsed:
        allowed_tools = [str(item).strip() for item in row.get("allowed_tools", []) if str(item).strip()]
        normalized.append(
            {
                "server_id": str(row.get("server_id") or "").strip(),
                "base_url": str(row.get("base_url") or "").strip(),
                "transport": str(row.get("transport") or "streamable_http").strip().lower(),
                "enabled": bool(row.get("enabled", True)),
                "allowed_tools": allowed_tools,
                "headers": row.get("headers") if isinstance(row.get("headers"), dict) else {},
                "auth_header": str(row.get("auth_header") or "").strip() or "Authorization",
                "auth_token": str(row.get("auth_token") or "").strip(),
                "tool_name_prefix": str(row.get("tool_name_prefix") or "").strip(),
            }
        )

    return normalized


def list_mcp_servers(db: Session) -> list[dict]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_MCP_SERVERS_JSON, "[]")
    rows = _parse_servers_json(raw)
    return [
        {
            "server_id": row["server_id"],
            "base_url": row["base_url"],
            "transport": row["transport"],
            "enabled": row["enabled"],
            "allowed_tools": row["allowed_tools"],
        }
        for row in rows
    ]


def resolve_mcp_server(db: Session, server_id: str) -> dict:
    normalized_server_id = str(server_id or "").strip()
    for row in _parse_servers_json(get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_MCP_SERVERS_JSON, "[]")):
        if row["server_id"] == normalized_server_id:
            if not row["enabled"]:
                raise HTTPException(status_code=403, detail=f"MCP server {normalized_server_id} is disabled")
            return row
    raise HTTPException(status_code=404, detail=f"MCP server {normalized_server_id} not found")


def _build_rpc_headers(server: dict) -> dict[str, str]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    custom_headers = server.get("headers") or {}
    for key, value in custom_headers.items():
        if not key:
            continue
        headers[str(key)] = str(value)

    auth_token = str(server.get("auth_token") or "").strip()
    if auth_token:
        auth_header = str(server.get("auth_header") or "Authorization").strip() or "Authorization"
        headers[auth_header] = auth_token

    return headers


def _rpc_request(db: Session, server: dict, method: str, params: dict) -> dict:
    timeout_seconds = get_runtime_config_float(db, RUNTIME_CONFIG_GATEWAY_MCP_DEFAULT_TIMEOUT_SECONDS, 8.0)
    if timeout_seconds <= 0:
        timeout_seconds = 8.0

    payload = {
        "jsonrpc": "2.0",
        "id": f"rpc-{uuid4()}",
        "method": method,
        "params": params,
    }

    try:
        resp = httpx.post(
            server["base_url"],
            json=payload,
            headers=_build_rpc_headers(server),
            timeout=timeout_seconds,
        )
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail=f"MCP server {server['server_id']} timed out") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Failed to reach MCP server {server['server_id']}") from exc

    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"MCP server {server['server_id']} returned HTTP {resp.status_code}")

    try:
        parsed = resp.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"MCP server {server['server_id']} returned non-JSON response") from exc

    if not isinstance(parsed, dict):
        raise HTTPException(status_code=502, detail=f"MCP server {server['server_id']} returned unexpected response")

    error = parsed.get("error")
    if isinstance(error, dict):
        message = str(error.get("message") or "MCP upstream error")
        raise HTTPException(status_code=502, detail=f"MCP server {server['server_id']} error: {message}")

    return parsed


def list_tools(db: Session, server: dict, tool_name_prefix: Optional[str] = None) -> list[dict]:
    rpc = _rpc_request(db, server, "tools/list", {})
    result = rpc.get("result") if isinstance(rpc.get("result"), dict) else {}
    tools = result.get("tools") if isinstance(result, dict) else []
    if not isinstance(tools, list):
        return []

    normalized_prefix = str(tool_name_prefix or server.get("tool_name_prefix") or "").strip()

    normalized_tools: list[dict] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = str(tool.get("name") or "").strip()
        if not name:
            continue
        if normalized_prefix and not name.startswith(normalized_prefix):
            continue
        normalized_tools.append(tool)
    return normalized_tools


def call_tool(db: Session, server: dict, tool_name: str, arguments: dict) -> object:
    normalized_name = str(tool_name or "").strip()
    if not normalized_name:
        raise HTTPException(status_code=422, detail="tool_name is required")

    allowed_tools = server.get("allowed_tools") or []
    if allowed_tools and normalized_name not in allowed_tools:
        raise HTTPException(status_code=403, detail=f"Tool {normalized_name} is not allowed for MCP server {server['server_id']}")

    normalized_prefix = str(server.get("tool_name_prefix") or "").strip()
    if normalized_prefix and not normalized_name.startswith(normalized_prefix):
        raise HTTPException(status_code=403, detail=f"Tool {normalized_name} does not match allowed prefix for MCP server {server['server_id']}")

    rpc = _rpc_request(
        db,
        server,
        "tools/call",
        {
            "name": normalized_name,
            "arguments": arguments if isinstance(arguments, dict) else {},
        },
    )
    return rpc.get("result")
