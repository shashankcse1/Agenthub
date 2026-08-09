from __future__ import annotations

import json
import re
from typing import Any, Optional

from fastapi import HTTPException
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.runtime_constants import RUNTIME_CONFIG_ORCHESTRATION_DATA_CONNECTIONS_JSON
from app.services.credential_resolution import load_active_binding_by_id, resolve_binding_for_runtime
from app.services.runtime_config import get_runtime_config

ALLOWED_DATA_CONNECTION_DRIVERS = {"platform", "postgresql"}
DEFAULT_MAX_ROWS = 200
MAX_ROWS_CAP = 500

_CONNECTION_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


def validate_data_connections_json(raw: str) -> Optional[str]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return "orchestration.data_connections_json must be valid JSON"
    if not isinstance(parsed, list):
        return "orchestration.data_connections_json must be a JSON array"

    seen: set[str] = {"platform"}
    for idx, item in enumerate(parsed):
        if not isinstance(item, dict):
            return f"orchestration.data_connections_json[{idx}] must be a JSON object"
        valid, error = _validate_connection_record(item, idx)
        if not valid:
            return error
        connection_id = str(item.get("connection_id") or "").strip()
        if connection_id in seen:
            return f"orchestration.data_connections_json duplicate connection_id: {connection_id}"
        seen.add(connection_id)
    return None


def _validate_connection_record(record: dict, idx: int) -> tuple[bool, str]:
    connection_id = str(record.get("connection_id") or "").strip()
    driver = str(record.get("driver") or "").strip().lower()
    credential_binding_id = str(record.get("credential_binding_id") or "").strip()
    enabled = record.get("enabled", True)
    max_rows = record.get("max_rows", DEFAULT_MAX_ROWS)

    if not connection_id:
        return False, f"orchestration.data_connections_json[{idx}] missing connection_id"
    if not _CONNECTION_ID_PATTERN.match(connection_id):
        return (
            False,
            f"orchestration.data_connections_json[{idx}] connection_id must be lowercase alphanumeric with ._-",
        )
    if driver not in ALLOWED_DATA_CONNECTION_DRIVERS:
        return (
            False,
            f"orchestration.data_connections_json[{idx}] driver must be platform or postgresql",
        )
    if not isinstance(enabled, bool):
        return False, f"orchestration.data_connections_json[{idx}] enabled must be boolean"
    if not isinstance(max_rows, int) or max_rows < 1 or max_rows > MAX_ROWS_CAP:
        return False, f"orchestration.data_connections_json[{idx}] max_rows must be 1-{MAX_ROWS_CAP}"

    if driver == "postgresql" and enabled and not credential_binding_id:
        return (
            False,
            f"orchestration.data_connections_json[{idx}] credential_binding_id is required for enabled postgresql connections",
        )
    return True, ""


def parse_data_connections_json(raw: str) -> list[dict]:
    try:
        parsed = json.loads(raw or "[]")
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=500, detail="Invalid orchestration.data_connections_json runtime config"
        ) from exc
    if not isinstance(parsed, list):
        raise HTTPException(status_code=500, detail="orchestration.data_connections_json must be a JSON array")
    return [item for item in parsed if isinstance(item, dict)]


def _platform_connection() -> dict:
    return {
        "connection_id": "platform",
        "label": "Platform database (read-only)",
        "driver": "platform",
        "enabled": True,
        "max_rows": DEFAULT_MAX_ROWS,
        "credential_binding_id": None,
    }


def _serialize_connection_item(item: dict) -> dict:
    max_rows = item.get("max_rows", DEFAULT_MAX_ROWS)
    if not isinstance(max_rows, int):
        max_rows = DEFAULT_MAX_ROWS
    max_rows = min(max(max_rows, 1), MAX_ROWS_CAP)
    return {
        "connection_id": str(item.get("connection_id") or "").strip(),
        "label": str(item.get("label") or "").strip() or None,
        "driver": str(item.get("driver") or "").strip().lower(),
        "enabled": bool(item.get("enabled", True)),
        "max_rows": max_rows,
        "credential_binding_id": str(item.get("credential_binding_id") or "").strip() or None,
    }


def list_data_connections(db: Session, *, enabled_only: bool = False) -> list[dict]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_ORCHESTRATION_DATA_CONNECTIONS_JSON, "[]")
    connections = parse_data_connections_json(raw)
    serialized = [_platform_connection()]
    serialized.extend(_serialize_connection_item(item) for item in connections)
    if enabled_only:
        return [row for row in serialized if row.get("enabled")]
    return serialized


def get_data_connection(db: Session, connection_id: str) -> dict:
    normalized = str(connection_id or "").strip()
    if normalized == "platform":
        return _platform_connection()
    for connection in list_data_connections(db):
        if connection["connection_id"] == normalized:
            if not connection.get("enabled"):
                raise HTTPException(status_code=403, detail="Data connection is disabled")
            return connection
    raise HTTPException(status_code=404, detail="Data connection not found")


def execute_read_query(
    db: Session,
    *,
    connection_id: str,
    sql: str,
    parameters: dict[str, Any],
) -> list[dict[str, Any]]:
    connection = get_data_connection(db, connection_id)
    driver = connection["driver"]
    max_rows = int(connection.get("max_rows") or DEFAULT_MAX_ROWS)

    if driver == "platform":
        result = db.execute(text(sql), parameters)
        rows = result.mappings().fetchmany(max_rows + 1)
        if len(rows) > max_rows:
            raise HTTPException(status_code=422, detail=f"Query exceeded max_rows ({max_rows})")
        return [dict(row) for row in rows]

    if driver == "postgresql":
        binding_id = str(connection.get("credential_binding_id") or "").strip()
        if not binding_id:
            raise HTTPException(status_code=422, detail="PostgreSQL data connection missing credential_binding_id")
        binding = load_active_binding_by_id(db, binding_id)
        resolved = resolve_binding_for_runtime(db, binding)
        dsn = str(resolved.secret_value or "").strip()
        if not dsn:
            raise HTTPException(status_code=503, detail="PostgreSQL data connection DSN is empty")
        engine = create_engine(dsn, pool_pre_ping=True)
        try:
            with engine.connect() as conn:
                result = conn.execute(text(sql), parameters)
                rows = result.mappings().fetchmany(max_rows + 1)
                if len(rows) > max_rows:
                    raise HTTPException(status_code=422, detail=f"Query exceeded max_rows ({max_rows})")
                return [dict(row) for row in rows]
        finally:
            engine.dispose()

    raise HTTPException(status_code=422, detail=f"Unsupported data connection driver: {driver}")
