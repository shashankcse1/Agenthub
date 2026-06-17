from __future__ import annotations

import asyncio
import json
import re
from collections import defaultdict
from datetime import datetime
from typing import Any, Callable, Optional
from urllib.parse import urlparse
from uuid import uuid4

from sqlalchemy.orm import Session

from app.api_errors import validation_error
from app.runtime_constants import (
    RUNTIME_CONFIG_ORCHESTRATION_HTTP_ALLOWED_HOSTS_JSON,
    RUNTIME_CONFIG_ORCHESTRATION_MAX_NODES_PER_FLOW,
    RUNTIME_CONFIG_ORCHESTRATION_PROD_RUN_REQUIRES_APPROVAL,
    RUNTIME_CONFIG_ORCHESTRATION_PROD_RUN_REQUIRES_ACCESS_CERTIFICATION,
)
from app.services.gateway_vector_stores import list_vector_stores
from app.services.gateway_notification_channels import (
    list_notification_channels,
    validate_recipient_template,
)
from app.services.runtime_config import get_runtime_config, get_runtime_config_int

FLOW_STATUSES = {"draft", "active", "disabled", "deprecated"}
FLOW_ENVIRONMENTS = {"dev", "staging", "prod"}
TRIGGER_TYPES = {"schedule", "webhook", "manual"}
APPROVAL_STATUSES = {"pending", "approved", "rejected"}
HTTP_AUTH_TYPES = {"none", "bearer", "basic", "api_key", "oidc_client_credentials", "workload_identity"}

GRAPH_NODE_TYPES = {
    "llm_chat",
    "mcp_tool",
    "http_request",
    "condition",
    "schedule_trigger",
    "webhook_trigger",
    "memory_read",
    "memory_write",
    "vector_query",
    "vector_ingest",
    "embedding_create",
    "rag_query",
    "wait_delay",
    "guardrail_evaluate",
    "email_send",
    "sms_send",
    "human_approval",
    "parallel_fork",
    "parallel_join",
}

LLM_CHAT_RESPONSE_FORMATS = {"text", "json_object"}
LLM_CHAT_CACHE_MODES = {"inherit", "bypass", "force"}

MAX_PARALLEL_BRANCHES = 5
MIN_PARALLEL_BRANCHES = 2

INLINE_SECRET_FIELD_PATTERN = re.compile(
    r"(api[_-]?key|secret|password|token|authorization|bearer)",
    re.IGNORECASE,
)

CRON_PATTERN = re.compile(
    r"^(\*|[0-9,\-/]+)\s+(\*|[0-9,\-/]+)\s+(\*|[0-9,\-/]+)\s+(\*|[0-9,\-/]+)\s+(\*|[0-9,\-/]+)$"
)

JSON_PATH_PATTERN = re.compile(r"^\$(?:(?:\.\w+)|(?:\[\d+\]))+$")

NODE_TYPE_CATALOG: list[dict[str, Any]] = [
    {
        "type": "llm_chat",
        "label": "LLM Chat",
        "description": "Gateway chat completion using catalog model and prompt template.",
        "required_config_fields": ["model_id", "prompt_template"],
        "optional_config_fields": [
            "binding_id",
            "temperature",
            "route_id",
            "prompt_registry_id",
            "max_tokens",
            "response_format",
            "cache_mode",
        ],
    },
    {
        "type": "mcp_tool",
        "label": "MCP Tool Call",
        "description": "Invoke a tool from the gateway MCP server registry.",
        "required_config_fields": ["server_id", "tool_name"],
        "optional_config_fields": ["arguments_json", "binding_id"],
    },
    {
        "type": "http_request",
        "label": "HTTP Request",
        "description": "Outbound HTTP to allowlisted hosts only; auth via credential binding refs — no inline secrets.",
        "required_config_fields": ["url", "method"],
        "optional_config_fields": [
            "headers_json",
            "body_template",
            "auth_type",
            "auth_binding_id",
            "auth_header_name",
        ],
    },
    {
        "type": "condition",
        "label": "Condition",
        "description": "If/else branch on a safe expression or JSON path from a prior step output.",
        "required_config_fields": ["expression"],
        "optional_config_fields": [
            "source_node_id",
            "json_path",
            "operator",
            "compare_value",
            "true_branch",
            "false_branch",
        ],
    },
    {
        "type": "schedule_trigger",
        "label": "Schedule Trigger",
        "description": "Cron schedule stored in flow trigger configuration.",
        "required_config_fields": ["cron_expression"],
        "optional_config_fields": [],
    },
    {
        "type": "webhook_trigger",
        "label": "Webhook Trigger",
        "description": "Incoming webhook path with signed token binding ref.",
        "required_config_fields": ["webhook_path_ref"],
        "optional_config_fields": ["token_binding_id"],
    },
    {
        "type": "memory_read",
        "label": "Memory Read",
        "description": "Read gateway memory for a scope.",
        "required_config_fields": ["scope_type", "scope_id", "memory_tier"],
        "optional_config_fields": ["label_filter"],
    },
    {
        "type": "memory_write",
        "label": "Memory Write",
        "description": "Write gateway memory for a scope.",
        "required_config_fields": ["scope_type", "scope_id", "memory_tier", "content_template"],
        "optional_config_fields": ["label"],
    },
    {
        "type": "vector_query",
        "label": "Vector Search",
        "description": "Semantic search against a configured vector store registry entry.",
        "required_config_fields": ["store_id", "query"],
        "optional_config_fields": ["top_k"],
    },
    {
        "type": "vector_ingest",
        "label": "Vector Ingest",
        "description": "Ingest text into a configured vector store (mcp_bridge and supported backends).",
        "required_config_fields": ["store_id", "content_template"],
        "optional_config_fields": ["document_id"],
    },
    {
        "type": "embedding_create",
        "label": "Create Embedding",
        "description": "Gateway embedding creation using catalog model and input template.",
        "required_config_fields": ["model_id", "input_template"],
        "optional_config_fields": ["binding_id"],
    },
    {
        "type": "rag_query",
        "label": "RAG Query",
        "description": "Retrieval-augmented query against a configured vector store registry entry.",
        "required_config_fields": ["store_id", "query_template"],
        "optional_config_fields": ["top_k", "binding_id"],
    },
    {
        "type": "wait_delay",
        "label": "Wait / Delay",
        "description": "Pause flow execution for a configured number of seconds.",
        "required_config_fields": ["delay_seconds"],
        "optional_config_fields": [],
    },
    {
        "type": "guardrail_evaluate",
        "label": "Guardrail Evaluate",
        "description": "Evaluate gateway guardrail policy against an input template.",
        "required_config_fields": ["key_id", "input_template"],
        "optional_config_fields": ["guardrail_policy_id"],
    },
    {
        "type": "email_send",
        "label": "Send Email",
        "description": "Send email via a gateway notification channel registry entry with live provider delivery.",
        "required_config_fields": ["channel_id", "to_template", "subject_template", "body_template"],
        "optional_config_fields": ["from_override"],
    },
    {
        "type": "sms_send",
        "label": "Send SMS",
        "description": "Send SMS via a gateway notification channel registry entry with live provider delivery.",
        "required_config_fields": ["channel_id", "to_template", "body_template"],
        "optional_config_fields": ["from_override"],
    },
    {
        "type": "human_approval",
        "label": "Human Approval",
        "description": "Creates an approval gate; prod runs require dual approval.",
        "required_config_fields": ["approval_title"],
        "optional_config_fields": [
            "required_role",
            "instructions",
            "approver_source",
            "source_node_id",
            "approver_role_json_path",
            "approver_id_json_path",
        ],
    },
    {
        "type": "parallel_fork",
        "label": "Parallel Fork",
        "description": "Split flow into parallel branches that run concurrently before merging.",
        "required_config_fields": ["group_id"],
        "optional_config_fields": ["branch_count"],
    },
    {
        "type": "parallel_join",
        "label": "Parallel Join",
        "description": "Merge parallel branches and continue serial execution.",
        "required_config_fields": ["group_id", "fork_node_id"],
        "optional_config_fields": [],
    },
]

NODE_REQUIRED_FIELDS: dict[str, set[str]] = {
    item["type"]: set(item["required_config_fields"]) for item in NODE_TYPE_CATALOG
}


def list_node_types() -> list[dict[str, Any]]:
    return [dict(item) for item in NODE_TYPE_CATALOG]


def _parse_json_object(raw: str, *, field_name: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise validation_error(
            message=f"{field_name} must be valid JSON",
            decision_trace_id="orchestration-json-invalid",
            field=field_name,
        ) from exc
    if not isinstance(parsed, dict):
        raise validation_error(
            message=f"{field_name} must be a JSON object",
            decision_trace_id="orchestration-json-shape",
            field=field_name,
        )
    return parsed


def _parse_graph(raw: str) -> dict[str, Any]:
    graph = _parse_json_object(raw, field_name="graph_json")
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise validation_error(
            message="graph_json must include nodes and edges arrays",
            decision_trace_id="orchestration-graph-shape",
        )
    return {"nodes": nodes, "edges": edges}


def _json_path_value(data: Any, json_path: str) -> Any:
    path = str(json_path or "").strip()
    if not path or path == "$":
        return data
    if not path.startswith("$"):
        return None
    current: Any = data
    remainder = path[1:]
    if remainder.startswith("."):
        remainder = remainder[1:]
    if not remainder:
        return current
    tokens = re.split(r"\.(?![^\[]*\])", remainder)
    for token in tokens:
        if not token:
            continue
        key = token
        index: Optional[int] = None
        bracket = re.match(r"^([^\[]+)\[(\d+)\]$", token)
        if bracket:
            key = bracket.group(1)
            index = int(bracket.group(2))
        if key and isinstance(current, dict):
            current = current.get(key)
        elif key:
            return None
        if index is not None:
            if isinstance(current, list) and 0 <= index < len(current):
                current = current[index]
            else:
                return None
    return current


def evaluate_condition(config: dict[str, Any], step_outputs: dict[str, Any]) -> bool:
    source_node_id = str(config.get("source_node_id") or "").strip()
    json_path = str(config.get("json_path") or "").strip()
    operator = str(config.get("operator") or "==").strip()
    compare_value = config.get("compare_value")

    if source_node_id and json_path:
        left = _json_path_value(step_outputs.get(source_node_id), json_path)
    else:
        left = config.get("expression")

    if operator == "exists":
        return left is not None and left != ""
    if operator == "contains":
        return str(compare_value or "") in str(left or "")
    if operator == "==":
        return str(left) == str(compare_value)
    if operator == "!=":
        return str(left) != str(compare_value)
    if operator == ">":
        try:
            return float(left) > float(compare_value)
        except (TypeError, ValueError):
            return False
    if operator == "<":
        try:
            return float(left) < float(compare_value)
        except (TypeError, ValueError):
            return False
    return True


def _scan_inline_secrets(value: Any, path: str = "") -> list[str]:
    violations: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            key_path = f"{path}.{key}" if path else str(key)
            if INLINE_SECRET_FIELD_PATTERN.search(str(key)):
                allowed_ref_keys = {
                    "binding_id",
                    "auth_binding_id",
                    "auth_type",
                    "secret_provider_id",
                    "cp_ref",
                    "token_binding_id",
                    "webhook_path_ref",
                    "max_tokens",
                }
                if str(key) not in allowed_ref_keys and nested not in (None, "", []):
                    if not (str(key).endswith("_ref") or str(key).endswith("_binding_id")):
                        violations.append(key_path)
            violations.extend(_scan_inline_secrets(nested, key_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            violations.extend(_scan_inline_secrets(item, f"{path}[{index}]"))
    elif isinstance(value, str) and value.strip():
        key_name = path.rsplit(".", 1)[-1] if path else ""
        if key_name in {"auth_type", "method", "operator"}:
            return violations
        lowered = value.lower()
        if lowered.startswith("sk-") or lowered.startswith("bearer "):
            violations.append(path or "value")
    return violations


def _load_http_allowlist(db: Session) -> list[str]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_ORCHESTRATION_HTTP_ALLOWED_HOSTS_JSON, "[]")
    try:
        parsed = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item).strip().lower() for item in parsed if str(item).strip()]


def _validate_http_url(db: Session, url: str) -> Optional[str]:
    parsed = urlparse(str(url or "").strip())
    if parsed.scheme not in {"http", "https"}:
        return "HTTP node URL must use http or https scheme"
    host = (parsed.hostname or "").lower()
    if not host:
        return "HTTP node URL must include a host"
    allowlist = _load_http_allowlist(db)
    if not allowlist:
        return "HTTP outbound hosts are denied by default; configure orchestration.http_allowed_hosts_json"
    if host not in allowlist and not any(host.endswith(f".{allowed}") for allowed in allowlist):
        return f"HTTP host '{host}' is not in orchestration.http_allowed_hosts_json allowlist"
    return None


def _vector_store_exists(db: Session, store_id: str) -> bool:
    normalized = str(store_id or "").strip()
    if not normalized:
        return False
    return any(str(store.get("store_id") or "").strip() == normalized for store in list_vector_stores(db))


def _notification_channel_valid(db: Session, channel_id: str) -> bool:
    normalized = str(channel_id or "").strip()
    if not normalized:
        return False
    for channel in list_notification_channels(db):
        if str(channel.get("channel_id") or "").strip() != normalized:
            continue
        if not channel.get("enabled"):
            return False
        return bool(str(channel.get("credential_binding_id") or "").strip())
    return False


def _validate_trigger(trigger_type: str, trigger_config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    normalized = str(trigger_type or "manual").strip().lower()
    if normalized not in TRIGGER_TYPES:
        errors.append(f"trigger_type must be one of: {', '.join(sorted(TRIGGER_TYPES))}")
        return errors

    if normalized == "schedule":
        cron = str(trigger_config.get("cron_expression") or "").strip()
        if not cron:
            errors.append("schedule trigger requires cron_expression in trigger_config_json")
        elif not CRON_PATTERN.match(cron):
            errors.append("cron_expression must be a valid 5-field cron expression")

    if normalized == "webhook":
        path_ref = str(trigger_config.get("webhook_path_ref") or trigger_config.get("path_ref") or "").strip()
        if not path_ref:
            errors.append("webhook trigger requires webhook_path_ref in trigger_config_json")
        token_ref = trigger_config.get("token_binding_id")
        if token_ref is not None and str(token_ref).strip():
            errors.extend(_scan_inline_secrets({"token_binding_id": token_ref}, "trigger_config_json"))

    return errors


def _validate_node_config(db: Session, node_type: str, config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if node_type not in GRAPH_NODE_TYPES:
        errors.append(f"unsupported node type: {node_type}")
        return errors

    required = NODE_REQUIRED_FIELDS.get(node_type, set())
    for field in sorted(required):
        value = config.get(field)
        if value is None or str(value).strip() == "":
            errors.append(f"node type '{node_type}' requires config.{field}")

    errors.extend(_scan_inline_secrets(config, "config"))

    if node_type == "http_request":
        url_error = _validate_http_url(db, str(config.get("url") or ""))
        if url_error:
            errors.append(url_error)
        auth_type = str(config.get("auth_type") or "none").strip().lower()
        if auth_type and auth_type not in HTTP_AUTH_TYPES:
            errors.append(
                f"http_request auth_type must be one of: {', '.join(sorted(HTTP_AUTH_TYPES))}"
            )
        if auth_type not in {"", "none"}:
            binding_id = str(config.get("auth_binding_id") or "").strip()
            if not binding_id:
                errors.append("http_request requires config.auth_binding_id when auth_type is set")
            if auth_type == "api_key":
                header_name = str(config.get("auth_header_name") or "").strip()
                if not header_name:
                    errors.append("http_request api_key auth requires config.auth_header_name")
            headers_raw = config.get("headers_json")
            if headers_raw not in (None, "", {}):
                try:
                    headers = json.loads(headers_raw) if isinstance(headers_raw, str) else headers_raw
                except json.JSONDecodeError:
                    headers = None
                if isinstance(headers, dict):
                    for key in headers:
                        if INLINE_SECRET_FIELD_PATTERN.search(str(key)):
                            errors.append(
                                "http_request must not embed credentials in headers_json; use auth_binding_id"
                            )
                            break

    if node_type == "schedule_trigger":
        cron = str(config.get("cron_expression") or "").strip()
        if cron and not CRON_PATTERN.match(cron):
            errors.append("schedule_trigger cron_expression must be a valid 5-field cron expression")

    if node_type == "condition":
        json_path = str(config.get("json_path") or "").strip()
        if json_path and not JSON_PATH_PATTERN.match(json_path):
            errors.append("condition json_path must start with $ and use dot or bracket notation (e.g. $.status or $.items[0].id)")
        operator = str(config.get("operator") or "").strip()
        if operator and operator not in {"==", "!=", ">", "<", "contains", "exists"}:
            errors.append("condition operator must be one of: ==, !=, >, <, contains, exists")
        source_node_id = str(config.get("source_node_id") or "").strip()
        if json_path and not source_node_id:
            errors.append("condition requires config.source_node_id when json_path is set")

    if node_type == "parallel_fork":
        group_id = str(config.get("group_id") or "").strip()
        if not group_id:
            errors.append("parallel_fork requires config.group_id")
        branch_count = config.get("branch_count")
        if branch_count is not None:
            try:
                count = int(branch_count)
            except (TypeError, ValueError):
                errors.append("parallel_fork branch_count must be an integer")
            else:
                if count < MIN_PARALLEL_BRANCHES or count > MAX_PARALLEL_BRANCHES:
                    errors.append(
                        f"parallel_fork branch_count must be between {MIN_PARALLEL_BRANCHES} and {MAX_PARALLEL_BRANCHES}"
                    )

    if node_type == "parallel_join":
        group_id = str(config.get("group_id") or "").strip()
        fork_node_id = str(config.get("fork_node_id") or "").strip()
        if not group_id:
            errors.append("parallel_join requires config.group_id")
        if not fork_node_id:
            errors.append("parallel_join requires config.fork_node_id")

    if node_type == "llm_chat":
        route_id = config.get("route_id")
        if route_id is not None and not str(route_id).strip():
            errors.append("llm_chat route_id must be a non-empty string when set")
        prompt_registry_id = config.get("prompt_registry_id")
        if prompt_registry_id is not None and not str(prompt_registry_id).strip():
            errors.append("llm_chat prompt_registry_id must be a non-empty string when set")
        max_tokens = config.get("max_tokens")
        if max_tokens is not None and str(max_tokens).strip():
            try:
                parsed = int(max_tokens)
            except (TypeError, ValueError):
                errors.append("llm_chat max_tokens must be an integer")
            else:
                if parsed < 1:
                    errors.append("llm_chat max_tokens must be at least 1")
        response_format = str(config.get("response_format") or "").strip().lower()
        if response_format and response_format not in LLM_CHAT_RESPONSE_FORMATS:
            errors.append(
                f"llm_chat response_format must be one of: {', '.join(sorted(LLM_CHAT_RESPONSE_FORMATS))}"
            )
        cache_mode = str(config.get("cache_mode") or "inherit").strip().lower()
        if cache_mode and cache_mode not in LLM_CHAT_CACHE_MODES:
            errors.append(
                f"llm_chat cache_mode must be one of: {', '.join(sorted(LLM_CHAT_CACHE_MODES))}"
            )

    if node_type in {"vector_query", "vector_ingest", "rag_query"}:
        store_id = str(config.get("store_id") or "").strip()
        if store_id and not _vector_store_exists(db, store_id):
            errors.append(
                f"{node_type} store_id '{store_id}' is not in gateway.vector_stores_json — configure in Routing & Gateway"
            )
        if node_type in {"vector_query", "rag_query"}:
            top_k = config.get("top_k")
            if top_k is not None and str(top_k).strip():
                try:
                    parsed = int(top_k)
                except (TypeError, ValueError):
                    errors.append(f"{node_type} top_k must be an integer")
                else:
                    if parsed < 1 or parsed > 100:
                        errors.append(f"{node_type} top_k must be between 1 and 100")

    if node_type == "wait_delay":
        delay_seconds = config.get("delay_seconds")
        if delay_seconds is not None and str(delay_seconds).strip():
            try:
                parsed = int(delay_seconds)
            except (TypeError, ValueError):
                errors.append("wait_delay delay_seconds must be an integer")
            else:
                if parsed < 1 or parsed > 3600:
                    errors.append("wait_delay delay_seconds must be between 1 and 3600")

    if node_type in {"email_send", "sms_send"}:
        channel_id = str(config.get("channel_id") or "").strip()
        if channel_id and not _notification_channel_valid(db, channel_id):
            errors.append(
                f"{node_type} channel_id '{channel_id}' is not an enabled entry in "
                "gateway.notification_channels_json with credential_binding_id — configure in Routing & Gateway"
            )
        to_template = str(config.get("to_template") or "")
        to_error = validate_recipient_template(to_template, field_name="to_template")
        if to_error:
            errors.append(to_error)
        body_template = str(config.get("body_template") or "")
        body_error = validate_recipient_template(body_template, field_name="body_template")
        if body_error:
            errors.append(body_error)
        if node_type == "email_send":
            subject_template = str(config.get("subject_template") or "")
            subject_error = validate_recipient_template(subject_template, field_name="subject_template")
            if subject_error:
                errors.append(subject_error)

    return errors


def _build_graph_indexes(
    nodes: list[Any], edges: list[Any]
) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]], dict[str, list[str]]]:
    nodes_by_id: dict[str, dict[str, Any]] = {}
    outgoing: dict[str, list[str]] = defaultdict(list)
    incoming: dict[str, list[str]] = defaultdict(list)
    for node in nodes:
        if isinstance(node, dict):
            node_id = str(node.get("id") or "").strip()
            if node_id:
                nodes_by_id[node_id] = node
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        source = str(edge.get("source") or "").strip()
        target = str(edge.get("target") or "").strip()
        if source and target:
            outgoing[source].append(target)
            incoming[target].append(source)
    return nodes_by_id, outgoing, incoming


def _validate_parallel_topology(
    nodes: list[Any], edges: list[Any], node_ids: set[str]
) -> list[str]:
    errors: list[str] = []
    nodes_by_id, outgoing, incoming = _build_graph_indexes(nodes, edges)

    fork_nodes = [
        node for node in nodes if isinstance(node, dict) and str(node.get("type") or "") == "parallel_fork"
    ]
    join_nodes = [
        node for node in nodes if isinstance(node, dict) and str(node.get("type") or "") == "parallel_join"
    ]

    join_by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for join in join_nodes:
        config = join.get("config") if isinstance(join.get("config"), dict) else {}
        group_id = str(config.get("group_id") or "").strip()
        if group_id:
            join_by_group[group_id].append(join)

    for fork in fork_nodes:
        fork_id = str(fork.get("id") or "").strip()
        config = fork.get("config") if isinstance(fork.get("config"), dict) else {}
        group_id = str(config.get("group_id") or "").strip()
        if not group_id:
            continue

        matching_joins = join_by_group.get(group_id, [])
        if not matching_joins:
            errors.append(f"parallel_fork '{fork_id}' requires a matching parallel_join with group_id '{group_id}'")
            continue
        if len(matching_joins) > 1:
            errors.append(f"parallel_fork '{fork_id}' has multiple parallel_join nodes for group_id '{group_id}'")
            continue

        join = matching_joins[0]
        join_id = str(join.get("id") or "").strip()
        join_config = join.get("config") if isinstance(join.get("config"), dict) else {}
        fork_ref = str(join_config.get("fork_node_id") or "").strip()
        if fork_ref and fork_ref != fork_id:
            errors.append(
                f"parallel_join '{join_id}' fork_node_id must reference parallel_fork '{fork_id}'"
            )

        branch_heads = [target for target in outgoing.get(fork_id, []) if target != join_id]
        if len(branch_heads) < MIN_PARALLEL_BRANCHES:
            errors.append(
                f"parallel_fork '{fork_id}' must fan out to at least {MIN_PARALLEL_BRANCHES} branches"
            )
        if len(branch_heads) > MAX_PARALLEL_BRANCHES:
            errors.append(
                f"parallel_fork '{fork_id}' exceeds max parallel branches ({MAX_PARALLEL_BRANCHES})"
            )

        configured_branch_count = config.get("branch_count")
        if configured_branch_count is not None:
            try:
                expected = int(configured_branch_count)
            except (TypeError, ValueError):
                pass
            else:
                if expected != len(branch_heads):
                    errors.append(
                        f"parallel_fork '{fork_id}' branch_count ({expected}) does not match "
                        f"actual outgoing branches ({len(branch_heads)})"
                    )

        for branch_head in branch_heads:
            branch_nodes = _collect_branch_node_ids(branch_head, join_id, outgoing)
            if not branch_nodes and branch_head != join_id:
                errors.append(
                    f"parallel_fork '{fork_id}' branch starting at '{branch_head}' is empty — add at least one step"
                )

        for branch_head in branch_heads:
            if branch_head not in node_ids:
                errors.append(f"parallel_fork '{fork_id}' branch references unknown node '{branch_head}'")
            elif branch_head == join_id:
                errors.append(f"parallel_fork '{fork_id}' cannot connect directly to its parallel_join")

        # Each branch head must have a path to the join node.
        for branch_head in branch_heads:
            visited: set[str] = set()
            queue = [branch_head]
            reached_join = False
            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)
                if current == join_id:
                    reached_join = True
                    break
                if current == fork_id:
                    errors.append(f"parallel branch from '{fork_id}' contains a cycle through '{current}'")
                    break
                for successor in outgoing.get(current, []):
                    if successor not in visited:
                        queue.append(successor)
            if not reached_join:
                errors.append(
                    f"parallel branch starting at '{branch_head}' from fork '{fork_id}' must reach join '{join_id}'"
                )

        # Join should only be reached from branch tails (no stray incoming from outside the group).
        for source in incoming.get(join_id, []):
            if source == fork_id:
                errors.append(f"parallel_join '{join_id}' must not connect directly from its fork")

    orphan_joins = [
        join
        for join in join_nodes
        if str((join.get("config") or {}).get("group_id") or "").strip()
        not in {
            str((fork.get("config") or {}).get("group_id") or "").strip()
            for fork in fork_nodes
            if isinstance(fork.get("config"), dict)
        }
    ]
    for join in orphan_joins:
        join_id = str(join.get("id") or "").strip()
        group_id = str((join.get("config") or {}).get("group_id") or "").strip()
        if group_id:
            errors.append(f"parallel_join '{join_id}' has no matching parallel_fork for group_id '{group_id}'")

    return errors


def _validate_graph_cycles(
    nodes: list[Any], edges: list[Any], node_ids: set[str]
) -> list[str]:
    """Detect cycles in the overall DAG (parallel fork→join segments are acyclic by branch rules)."""
    if not node_ids:
        return []
    _, outgoing, incoming = _build_graph_indexes(nodes, edges)
    in_degree = {node_id: len(incoming.get(node_id, [])) for node_id in node_ids}
    queue = [node_id for node_id, degree in in_degree.items() if degree == 0]
    visited = 0
    while queue:
        current = queue.pop(0)
        visited += 1
        for successor in outgoing.get(current, []):
            if successor not in in_degree:
                continue
            in_degree[successor] -= 1
            if in_degree[successor] == 0:
                queue.append(successor)
    if visited == len(node_ids):
        return []
    cyclic = sorted(node_id for node_id, degree in in_degree.items() if degree > 0)
    if not cyclic:
        return ["graph contains a cycle — remove circular edges between steps"]
    preview = ", ".join(cyclic[:5])
    suffix = "…" if len(cyclic) > 5 else ""
    return [f"graph contains a cycle involving node(s): {preview}{suffix}"]


def validate_flow_definition(
    db: Session,
    *,
    trigger_type: str,
    trigger_config_json: str,
    graph_json: str,
    environment: str,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []

    env = str(environment or "dev").strip().lower()
    if env not in FLOW_ENVIRONMENTS:
        errors.append(f"environment must be one of: {', '.join(sorted(FLOW_ENVIRONMENTS))}")

    trigger_config = _parse_json_object(trigger_config_json, field_name="trigger_config_json")
    errors.extend(_validate_trigger(trigger_type, trigger_config))

    graph = _parse_graph(graph_json)
    nodes = graph["nodes"]
    edges = graph["edges"]

    max_nodes = get_runtime_config_int(db, RUNTIME_CONFIG_ORCHESTRATION_MAX_NODES_PER_FLOW, 50)
    if len(nodes) > max_nodes:
        errors.append(f"graph exceeds orchestration.max_nodes_per_flow ({max_nodes})")

    node_ids: set[str] = set()
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            errors.append(f"nodes[{index}] must be an object")
            continue
        node_id = str(node.get("id") or "").strip()
        node_type = str(node.get("type") or "").strip()
        if not node_id:
            errors.append(f"nodes[{index}] requires id")
        elif node_id in node_ids:
            errors.append(f"duplicate node id: {node_id}")
        else:
            node_ids.add(node_id)
        config = node.get("config") if isinstance(node.get("config"), dict) else {}
        errors.extend(_scan_inline_secrets(node, f"nodes[{index}]"))
        errors.extend(_validate_node_config(db, node_type, config))

    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            errors.append(f"edges[{index}] must be an object")
            continue
        source = str(edge.get("source") or "").strip()
        target = str(edge.get("target") or "").strip()
        if not source or not target:
            errors.append(f"edges[{index}] requires source and target")
        elif node_ids and (source not in node_ids or target not in node_ids):
            errors.append(f"edges[{index}] references unknown node id")

    errors.extend(_validate_parallel_topology(nodes, edges, node_ids))
    errors.extend(_validate_graph_cycles(nodes, edges, node_ids))

    if env == "prod" and not nodes:
        warnings.append("prod flows should include at least one node before promotion")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "max_nodes_per_flow": max_nodes,
        "http_allowlist_configured": bool(_load_http_allowlist(db)),
    }


def prod_run_requires_approval(db: Session) -> bool:
    raw = get_runtime_config(db, RUNTIME_CONFIG_ORCHESTRATION_PROD_RUN_REQUIRES_APPROVAL, "true").strip().lower()
    return raw not in {"0", "false", "no"}


def flow_has_human_approval_nodes(graph_json: str) -> bool:
    try:
        graph = _parse_graph(graph_json)
    except Exception:
        return False
    return any(
        isinstance(node, dict) and str(node.get("type") or "") == "human_approval"
        for node in graph.get("nodes", [])
    )


def serialize_flow(row: Any) -> dict[str, Any]:
    return {
        "flow_id": row.flow_id,
        "flow_name": row.flow_name,
        "description": row.description,
        "status": row.status,
        "environment": row.environment,
        "tenant_id": row.tenant_id,
        "trigger_type": row.trigger_type,
        "trigger_config_json": row.trigger_config_json,
        "graph_json": row.graph_json,
        "access_policy_json": getattr(row, "access_policy_json", None) or "{}",
        "approval_stage_state_json": getattr(row, "approval_stage_state_json", None) or "{}",
        "approval_status": row.approval_status,
        "metadata_version": row.metadata_version,
        "created_by": row.created_by,
        "updated_by": row.updated_by,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def serialize_run(row: Any, *, flow_name: Optional[str] = None) -> dict[str, Any]:
    payload = {
        "run_id": row.run_id,
        "flow_id": row.flow_id,
        "status": row.status,
        "started_at": row.started_at,
        "finished_at": row.finished_at,
        "trace_id": row.trace_id,
        "step_results_json": row.step_results_json,
        "error_summary": row.error_summary,
        "execution_state_json": getattr(row, "execution_state_json", None),
    }
    if flow_name is not None:
        payload["flow_name"] = flow_name
    return payload


def _stub_node_output(node_type: str, config: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    if node_type == "llm_chat":
        return {
            "simulated": True,
            "model_id": config.get("model_id"),
            "route_id": config.get("route_id"),
            "prompt_registry_id": config.get("prompt_registry_id"),
            "max_tokens": config.get("max_tokens"),
            "response_format": config.get("response_format") or "text",
            "cache_mode": config.get("cache_mode") or "inherit",
            "message": "Stub LLM response for orchestration Phase 1",
        }
    if node_type == "mcp_tool":
        return {
            "simulated": True,
            "server_id": config.get("server_id"),
            "tool_name": config.get("tool_name"),
        }
    if node_type == "http_request":
        return {
            "simulated": True,
            "url": config.get("url"),
            "method": config.get("method"),
            "status_code": 200,
            "status": 200,
            "data": {"approved": True, "email": "stub@example.com"},
            "body_preview": '{"approved":true}',
            "dry_run": dry_run,
        }
    if node_type == "condition":
        return {"simulated": True, "expression": config.get("expression"), "matched": True}
    if node_type in {"memory_read", "memory_write"}:
        return {
            "simulated": True,
            "scope_type": config.get("scope_type"),
            "scope_id": config.get("scope_id"),
            "memory_tier": config.get("memory_tier"),
        }
    if node_type == "vector_query":
        return {
            "simulated": True,
            "store_id": config.get("store_id"),
            "query": config.get("query"),
            "top_k": config.get("top_k"),
            "matches": [],
            "match_count": 0,
        }
    if node_type == "vector_ingest":
        return {
            "simulated": True,
            "store_id": config.get("store_id"),
            "document_id": config.get("document_id"),
            "ingested": 1,
        }
    if node_type == "embedding_create":
        return {
            "simulated": True,
            "embedding_dims": 1536,
            "model_id": config.get("model_id"),
        }
    if node_type == "rag_query":
        return {
            "simulated": True,
            "source": "rag_query",
            "store_id": config.get("store_id"),
            "query_template": config.get("query_template"),
            "top_k": config.get("top_k"),
            "matches": [],
            "chunks": [],
            "match_count": 0,
        }
    if node_type == "wait_delay":
        return {
            "simulated": True,
            "delay_seconds": config.get("delay_seconds"),
            "waited": True,
        }
    if node_type == "guardrail_evaluate":
        return {
            "simulated": True,
            "passed": True,
            "violations": [],
        }
    if node_type == "email_send":
        return {
            "simulated": True,
            "channel_id": config.get("channel_id"),
            "to": config.get("to_template"),
            "subject": config.get("subject_template"),
            "body": config.get("body_template"),
            "from_override": config.get("from_override"),
            "delivery_status": "simulated",
        }
    if node_type == "sms_send":
        return {
            "simulated": True,
            "channel_id": config.get("channel_id"),
            "to": config.get("to_template"),
            "body": config.get("body_template"),
            "from_override": config.get("from_override"),
            "delivery_status": "simulated",
        }
    if node_type == "human_approval":
        return {
            "simulated": True,
            "approval_gate_id": f"gate-{uuid4().hex[:12]}",
            "approval_title": config.get("approval_title"),
            "status": "pending" if dry_run else "approved_stub",
        }
    if node_type == "parallel_fork":
        return {
            "simulated": True,
            "execution_mode": "parallel",
            "group_id": config.get("group_id"),
        }
    if node_type == "parallel_join":
        return {
            "simulated": True,
            "execution_mode": "merge",
            "group_id": config.get("group_id"),
            "fork_node_id": config.get("fork_node_id"),
            "merged": True,
        }
    return {"simulated": True, "note": "trigger or passthrough node"}


def _execute_single_stub_node(
    node: dict[str, Any],
    *,
    dry_run: bool,
    trace_id: str,
    step_outputs: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    node_id = str(node.get("id") or "")
    node_type = str(node.get("type") or "")
    config = node.get("config") if isinstance(node.get("config"), dict) else {}
    output = _stub_node_output(node_type, config, dry_run=dry_run)
    if node_type == "condition" and step_outputs is not None:
        output["matched"] = evaluate_condition(config, step_outputs)
    return {
        "node_id": node_id,
        "node_type": node_type,
        "status": "simulated" if dry_run else "completed",
        "trace_id": trace_id,
        "output": output,
    }


def _collect_branch_node_ids(
    branch_head: str,
    join_id: str,
    outgoing: dict[str, list[str]],
) -> list[str]:
    ordered: list[str] = []
    visited: set[str] = set()
    queue = [branch_head]
    while queue:
        current = queue.pop(0)
        if current in visited or current == join_id:
            continue
        visited.add(current)
        ordered.append(current)
        for successor in outgoing.get(current, []):
            if successor != join_id and successor not in visited:
                queue.append(successor)
    return ordered


def _mark_branch_skipped(
    branch_head: str,
    condition_node_id: str,
    outgoing: dict[str, list[str]],
    incoming: dict[str, list[str]],
    completed: set[str],
) -> None:
    head = str(branch_head or "").strip()
    if not head:
        return
    to_skip: set[str] = set()
    queue = [head]
    while queue:
        node_id = queue.pop(0)
        if node_id in to_skip:
            continue
        preds = incoming.get(node_id, [])
        external = [pred for pred in preds if pred != condition_node_id and pred not in to_skip]
        if external:
            continue
        to_skip.add(node_id)
        for successor in outgoing.get(node_id, []):
            queue.append(successor)
    completed.update(to_skip)


def _execute_parallel_branches(
    fork_id: str,
    join_id: str,
    nodes_by_id: dict[str, dict[str, Any]],
    outgoing: dict[str, list[str]],
    *,
    trace_id: str,
    node_executor: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    step_outputs: dict[str, Any],
) -> list[list[dict[str, Any]]]:
    branch_heads = [target for target in outgoing.get(fork_id, []) if target != join_id]
    results: list[list[dict[str, Any]]] = []
    for branch_head in branch_heads:
        branch_ids = _collect_branch_node_ids(branch_head, join_id, outgoing)
        branch_outputs = dict(step_outputs)
        branch_steps: list[dict[str, Any]] = []
        for node_id in branch_ids:
            node = nodes_by_id.get(node_id)
            if not node:
                continue
            step = node_executor(node, branch_outputs)
            branch_steps.append(step)
        for step in branch_steps:
            node_id = str(step.get("node_id") or "")
            if node_id:
                step_outputs[node_id] = step.get("output")
        results.append(branch_steps)
    return results


def _execute_flow_graph(
    *,
    graph_json: str,
    dry_run: bool,
    trace_id: str,
    node_executor: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    step_outputs: Optional[dict[str, Any]] = None,
    fail_on_node_error: bool = False,
    initial_completed: Optional[set[str]] = None,
    initial_step_results: Optional[list[dict[str, Any]]] = None,
    resume_from_node_id: Optional[str] = None,
) -> tuple[str, list[dict[str, Any]], Optional[str]]:
    graph = _parse_graph(graph_json)
    nodes = [node for node in graph["nodes"] if isinstance(node, dict)]
    edges = [edge for edge in graph["edges"] if isinstance(edge, dict)]
    nodes_by_id, outgoing, incoming = _build_graph_indexes(nodes, edges)

    outputs = step_outputs if step_outputs is not None else {}
    step_results: list[dict[str, Any]] = list(initial_step_results or [])
    error_summary: Optional[str] = None
    completed: set[str] = set(initial_completed or set())
    skipped_joins: set[str] = set()
    awaiting_approval = False

    entry_nodes = [node_id for node_id in nodes_by_id if not incoming.get(node_id)]
    if not entry_nodes and nodes_by_id:
        entry_nodes = [next(iter(nodes_by_id))]

    if resume_from_node_id:
        resume_id = str(resume_from_node_id).strip()
        ready = [successor for successor in outgoing.get(resume_id, []) if successor not in completed]
    else:
        ready = [node_id for node_id in entry_nodes if node_id not in completed]
    while ready:
        node_id = ready.pop(0)
        if node_id in completed or node_id in skipped_joins:
            continue
        node = nodes_by_id.get(node_id)
        if not node:
            completed.add(node_id)
            continue

        node_type = str(node.get("type") or "")
        config = node.get("config") if isinstance(node.get("config"), dict) else {}

        if node_type == "parallel_fork":
            join_candidates = [
                target
                for target in nodes_by_id
                if str(nodes_by_id[target].get("type") or "") == "parallel_join"
                and str((nodes_by_id[target].get("config") or {}).get("group_id") or "").strip()
                == str(config.get("group_id") or "").strip()
            ]
            join_id = join_candidates[0] if join_candidates else ""
            branch_results = (
                _execute_parallel_branches(
                    node_id,
                    join_id,
                    nodes_by_id,
                    outgoing,
                    trace_id=trace_id,
                    node_executor=node_executor,
                    step_outputs=outputs,
                )
                if join_id
                else []
            )
            fork_result = node_executor(node, outputs)
            fork_result["output"] = {
                **fork_result.get("output", {}),
                "branch_count": len(branch_results),
                "branches": branch_results,
            }
            step_results.append(fork_result)
            completed.add(node_id)

            for branch in branch_results:
                for branch_step in branch:
                    completed.add(branch_step["node_id"])
                    step_results.append(branch_step)
                    if fail_on_node_error and branch_step.get("status") == "failed":
                        error_summary = f"Node {branch_step.get('node_id')} failed during parallel execution"
                        ready.clear()
                        break
                if error_summary:
                    break

            if error_summary:
                break

            if join_id and join_id in nodes_by_id:
                join_node = nodes_by_id[join_id]
                join_result = node_executor(join_node, outputs)
                join_result["output"] = {
                    **join_result.get("output", {}),
                    "branch_count": len(branch_results),
                }
                step_results.append(join_result)
                completed.add(join_id)
                skipped_joins.add(join_id)
                for successor in outgoing.get(join_id, []):
                    if successor not in completed:
                        ready.append(successor)
            continue

        if node_type == "parallel_join":
            completed.add(node_id)
            continue

        step_result = node_executor(node, outputs)
        step_results.append(step_result)
        if step_result.get("status") == "awaiting_approval":
            awaiting_approval = True
            break
        completed.add(node_id)
        if fail_on_node_error and step_result.get("status") == "failed":
            error_summary = f"Node {step_result.get('node_id')} failed"
            break

        if node_type == "condition":
            matched = bool((step_result.get("output") or {}).get("matched"))
            true_branch = str(config.get("true_branch") or "").strip()
            false_branch = str(config.get("false_branch") or "").strip()
            if true_branch or false_branch:
                chosen = true_branch if matched else false_branch
                skipped = false_branch if matched else true_branch
                if skipped:
                    _mark_branch_skipped(skipped, node_id, outgoing, incoming, completed)
                if chosen and chosen in nodes_by_id:
                    ready.append(chosen)
                else:
                    for successor in outgoing.get(node_id, []):
                        if successor in completed or successor in skipped_joins:
                            continue
                        preds = incoming.get(successor, [])
                        if all(pred in completed or pred in skipped_joins for pred in preds):
                            ready.append(successor)
                continue

        for successor in outgoing.get(node_id, []):
            if successor in completed or successor in skipped_joins:
                continue
            preds = incoming.get(successor, [])
            if all(pred in completed or pred in skipped_joins for pred in preds):
                ready.append(successor)

    if awaiting_approval:
        return "awaiting_approval", step_results, error_summary
    status = "failed" if error_summary else "completed"
    if dry_run and not error_summary:
        status = "dry_run_completed"
    return status, step_results, error_summary


def execute_flow_stub(
    *,
    flow_id: str,
    graph_json: str,
    dry_run: bool,
    trace_id: str,
) -> tuple[str, list[dict[str, Any]], Optional[str]]:
    def stub_executor(node: dict[str, Any], outputs: dict[str, Any]) -> dict[str, Any]:
        return _execute_single_stub_node(
            node,
            dry_run=dry_run,
            trace_id=trace_id,
            step_outputs=outputs,
        )

    status, step_results, error_summary = _execute_flow_graph(
        graph_json=graph_json,
        dry_run=dry_run,
        trace_id=trace_id,
        node_executor=stub_executor,
    )
    return status, step_results, error_summary


def prod_run_requires_access_certification(db: Session) -> bool:
    raw = get_runtime_config(
        db,
        RUNTIME_CONFIG_ORCHESTRATION_PROD_RUN_REQUIRES_ACCESS_CERTIFICATION,
        "true",
    ).strip().lower()
    return raw not in {"0", "false", "no"}


def security_policy_snapshot(db: Session) -> dict[str, Any]:
    return {
        "http_allowed_hosts": _load_http_allowlist(db),
        "max_nodes_per_flow": get_runtime_config_int(db, RUNTIME_CONFIG_ORCHESTRATION_MAX_NODES_PER_FLOW, 50),
        "prod_run_requires_approval": prod_run_requires_approval(db),
        "prod_run_requires_access_certification": prod_run_requires_access_certification(db),
        "max_parallel_branches": MAX_PARALLEL_BRANCHES,
    }
