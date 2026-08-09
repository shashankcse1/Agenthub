from __future__ import annotations

import asyncio
import contextvars
import json
import re
import time
from typing import Any, Callable, Optional
from urllib.parse import urlparse
from uuid import uuid4

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import OrchestrationFlowDefinition, OrchestrationRunApprovalGate, VirtualKey
from app.runtime_constants import (
    RUNTIME_CONFIG_ORCHESTRATION_LIVE_EXECUTOR_ENABLED,
    RUNTIME_CONFIG_ORCHESTRATION_LIVE_EXECUTOR_MAX_WAIT_SECONDS,
    RUNTIME_CONFIG_ORCHESTRATION_LIVE_EXECUTOR_PROD_ENABLED,
)
from app.schemas import KeyGuardrailEvaluateRequest
from app.security import ActorContext
from app.services.gateway_inference import (
    execute_chat_completion,
    inference_simulation_enabled,
    invoke_embeddings,
    resolve_inference_credential,
)
from app.services.gateway_memory import create_memory_record, list_memory_records, serialize_memory_record
from app.services.gateway_notification_channels import validate_recipient_template
from app.services.gateway_notification_delivery import deliver_email, deliver_sms
from app.services.gateway_rag import rag_ingest, rag_query
from app.services.mcp_gateway import call_tool as mcp_call_tool, resolve_mcp_server
from app.services.credential_resolution import load_active_binding_by_id, resolve_binding_for_runtime
from app.services.orchestration_flows import (
    AIRTABLE_API_BASE,
    ASANA_API_BASE,
    CLICKUP_API_BASE,
    GITHUB_API_BASE,
    GITLAB_API_BASE,
    BITBUCKET_API_BASE,
    BOX_API_BASE,
    CALENDLY_API_BASE,
    DROPBOX_API_BASE,
    GOOGLE_SHEETS_API_BASE,
    GOOGLE_DRIVE_API_BASE,
    GOOGLE_CALENDAR_API_BASE,
    HUBSPOT_API_BASE,
    MICROSOFT_GRAPH_API_BASE,
    SENDGRID_API_BASE,
    SLACK_API_BASE,
    STRIPE_API_BASE,
    TWILIO_API_BASE,
    ZOOM_API_BASE,
    INTERCOM_API_BASE,
    INTERCOM_API_VERSION,
    LINEAR_API_BASE,
    MONDAY_API_BASE,
    MAX_SUBFLOW_DEPTH,
    NOTION_API_BASE,
    NOTION_API_VERSION,
    DATADOG_ALERT_TYPES,
    DATADOG_API_BASE,
    OPSGENIE_API_BASE,
    PAGERDUTY_EVENTS_API_BASE,
    SENTRY_API_BASE,
    SENTRY_LEVELS,
    STATUSPAGE_API_BASE,
    STATUSPAGE_IMPACTS,
    STATUSPAGE_STATUSES,
    TELEGRAM_API_BASE,
    TRELLO_API_BASE,
    _execute_flow_graph,
    _execute_single_stub_node,
    _json_path_value,
    _stub_node_output,
    _validate_http_url,
    build_preset_api_url,
    evaluate_aggregate,
    evaluate_append_items,
    evaluate_array_ops,
    evaluate_base64_ops,
    evaluate_boolean_logic,
    evaluate_coalesce,
    evaluate_compact_object,
    evaluate_compare,
    evaluate_condition,
    clamp_while_max_iterations,
    evaluate_chunk_text,
    evaluate_compress,
    evaluate_csv_parse,
    evaluate_date_time,
    evaluate_dedupe,
    evaluate_deep_merge,
    evaluate_filter,
    evaluate_flatten_json,
    evaluate_form_urlencoded,
    evaluate_jwt_decode,
    evaluate_foreach_map,
    evaluate_hash_digest,
    evaluate_hmac_verify,
    evaluate_html_extract,
    evaluate_html_strip,
    evaluate_html_to_markdown,
    evaluate_markdown_to_html,
    evaluate_item_exists,
    evaluate_json_parse,
    evaluate_json_query,
    evaluate_json_stringify,
    evaluate_json_to_csv,
    evaluate_limit,
    evaluate_math_ops,
    evaluate_noop,
    evaluate_number_format,
    evaluate_object_diff,
    evaluate_omit_fields,
    evaluate_pick_fields,
    evaluate_random,
    evaluate_regex_extract,
    evaluate_rename_keys,
    evaluate_sort,
    evaluate_split_in_batches,
    evaluate_split_out,
    evaluate_split_text,
    evaluate_static_data,
    evaluate_stop_and_error,
    evaluate_string_ops,
    evaluate_switch,
    evaluate_text_template,
    evaluate_timezone_convert,
    evaluate_type_of,
    evaluate_unflatten_json,
    evaluate_url_ops,
    evaluate_uuid_gen,
    evaluate_wait_until,
    evaluate_xml_parse,
    evaluate_xml_stringify,
    execute_flow_stub,
    merge_step_outputs,
    resolve_connector_operation_preset,
    resolve_safe_template,
)
from app.services.orchestration_http_auth import apply_http_auth_headers
from app.services.runtime_config import get_runtime_config, get_runtime_config_int

_subflow_depth: contextvars.ContextVar[int] = contextvars.ContextVar("orch_subflow_depth", default=0)


def live_executor_enabled(db: Session, *, environment: str) -> bool:
    enabled = get_runtime_config(db, RUNTIME_CONFIG_ORCHESTRATION_LIVE_EXECUTOR_ENABLED, "false").strip().lower()
    if enabled not in {"1", "true", "yes", "on"}:
        return False
    env = str(environment or "dev").strip().lower()
    if env == "prod":
        prod_enabled = get_runtime_config(
            db, RUNTIME_CONFIG_ORCHESTRATION_LIVE_EXECUTOR_PROD_ENABLED, "false"
        ).strip().lower()
        return prod_enabled in {"1", "true", "yes", "on"}
    return True


def live_executor_policy_snapshot(db: Session) -> dict[str, Any]:
    return {
        "live_executor_enabled": get_runtime_config(
            db, RUNTIME_CONFIG_ORCHESTRATION_LIVE_EXECUTOR_ENABLED, "false"
        ),
        "live_executor_prod_enabled": get_runtime_config(
            db, RUNTIME_CONFIG_ORCHESTRATION_LIVE_EXECUTOR_PROD_ENABLED, "false"
        ),
        "live_executor_max_wait_seconds": get_runtime_config_int(
            db, RUNTIME_CONFIG_ORCHESTRATION_LIVE_EXECUTOR_MAX_WAIT_SECONDS, 30
        ),
        "notify_nodes_remain_simulated": False,
        "human_approval_live_enabled": True,
    }


def _resolve_gateway_cursor_token(db: Session) -> str:
    from app.routers.gateway import _resolve_gateway_cursor_api_token

    return _resolve_gateway_cursor_api_token(db)


def resolve_orchestration_template(
    template: str,
    *,
    step_outputs: dict[str, Any],
    run_input: str = "",
    item: Any = None,
) -> str:
    """Canonical Flow Studio template resolver (thin wrapper over resolve_safe_template).

    Supports `{{input}}`, `{{steps['id'].output[.path]}}`, and optional `{{item[.path]}}`.
    No eval/exec. Helicone properties and prompt-registry `{{var}}` are separate layers.
    """
    return resolve_safe_template(
        template,
        step_outputs=step_outputs,
        run_input=run_input,
        item=item,
    )


def _evaluate_guardrail(
    db: Session,
    *,
    key_id: str,
    input_text: str,
    environment: str,
) -> dict[str, Any]:
    from app.routers.gateway import _guardrail_decision, _parse_guardrail_policy

    key = db.query(VirtualKey).filter_by(key_id=key_id).first()
    if key is None:
        raise HTTPException(status_code=404, detail=f"Virtual key {key_id} not found")
    policy = _parse_guardrail_policy(key.guardrail_policy or "{}")
    payload = KeyGuardrailEvaluateRequest(
        environment=environment,
        stage="input",
        input_tokens=max(1, len(str(input_text or "").split())),
        output_tokens=0,
        requests_last_minute=1,
        simulated_input_text=input_text,
    )
    decision, reasons, applied = _guardrail_decision(key, policy, payload)
    passed = decision == "allow"
    return {
        "live": True,
        "passed": passed,
        "decision": decision,
        "violations": reasons,
        "applied_guardrails": applied,
        "key_id": key_id,
    }


def _resolve_human_approver(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> tuple[Optional[str], Optional[str]]:
    approver_source = str(config.get("approver_source") or "static").strip().lower()
    if approver_source == "json_path":
        source_node_id = str(config.get("source_node_id") or "").strip()
        source_output = step_outputs.get(source_node_id)
        role_path = str(config.get("approver_role_json_path") or "").strip()
        id_path = str(config.get("approver_id_json_path") or "").strip()
        resolved_role = (
            str(_json_path_value(source_output, role_path)).strip() if role_path else None
        )
        resolved_id = str(_json_path_value(source_output, id_path)).strip() if id_path else None
        return (resolved_id or None, resolved_role or None)
    required_role = str(config.get("required_role") or "").strip() or None
    return None, required_role


def _execute_live_node(
    db: Session,
    ctx: ActorContext,
    node: dict[str, Any],
    *,
    environment: str,
    trace_id: str,
    step_outputs: dict[str, Any],
    run_input: str,
    flow_id: str,
    run_id: str,
) -> dict[str, Any]:
    node_id = str(node.get("id") or "")
    node_type = str(node.get("type") or "")
    config = node.get("config") if isinstance(node.get("config"), dict) else {}

    try:
        if node_type == "llm_chat":
            from app.services.orchestration_llm_gateway import execute_orchestration_llm_chat

            output = execute_orchestration_llm_chat(
                db,
                config=config,
                step_outputs=step_outputs,
                run_input=run_input,
                environment=environment,
                trace_id=trace_id,
                actor_id=ctx.actor_id,
                tenant_id=None,
                credential_resolver=_resolve_gateway_cursor_token,
            )
            binding_id = str(config.get("binding_id") or "").strip() or None
            credential = resolve_inference_credential(
                db,
                agent_id=binding_id,
                environment=environment,
                model_name=str(output.get("model_id") or "gpt-4o-mini"),
                resolve_gateway_cursor_token=_resolve_gateway_cursor_token,
            )
            output["simulated"] = inference_simulation_enabled() and credential is None and not output.get("cache_hit")
        elif node_type == "embedding_create":
            model_id = str(config.get("model_id") or "text-embedding-3-small").strip()
            input_text = resolve_orchestration_template(
                str(config.get("input_template") or "{{input}}"),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            binding_id = str(config.get("binding_id") or "").strip() or None
            credential = resolve_inference_credential(
                db,
                agent_id=binding_id,
                environment=environment,
                model_name=model_id,
                resolve_gateway_cursor_token=_resolve_gateway_cursor_token,
            )
            if credential is None or not credential.api_key.strip():
                if inference_simulation_enabled():
                    output = {
                        "live": False,
                        "simulated": True,
                        "model_id": model_id,
                        "embedding_dims": 1536,
                    }
                else:
                    raise HTTPException(status_code=503, detail="Embedding credentials are not configured")
            else:
                result = invoke_embeddings(credential, inputs=[input_text])
                dims = len(result.embeddings[0]) if result.embeddings else 0
                output = {
                    "live": True,
                    "simulated": False,
                    "model_id": model_id,
                    "embedding_dims": dims,
                    "embedding": result.embeddings[0] if result.embeddings else [],
                }
        elif node_type in {"rag_query", "vector_query"}:
            store_id = str(config.get("store_id") or "").strip()
            query_key = "query_template" if node_type == "rag_query" else "query"
            query = resolve_orchestration_template(
                str(config.get(query_key) or config.get("query_template") or "{{input}}"),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            top_k_raw = config.get("top_k")
            top_k = int(top_k_raw) if top_k_raw not in (None, "") else None
            payload = rag_query(db, store_id=store_id, query=query, top_k=top_k)
            output = {"live": True, "simulated": False, **payload}
        elif node_type == "vector_ingest":
            store_id = str(config.get("store_id") or "").strip()
            content = resolve_orchestration_template(
                str(config.get("content_template") or "{{input}}"),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            document_id_raw = resolve_orchestration_template(
                str(config.get("document_id") or f"orch-doc-{uuid4().hex[:8]}"),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            document_id = document_id_raw or f"orch-doc-{uuid4().hex[:8]}"
            payload = rag_ingest(
                db,
                store_id=store_id,
                documents=[{"id": document_id, "text": content}],
            )
            output = {"live": True, "simulated": False, "store_id": store_id, **payload}
        elif node_type == "guardrail_evaluate":
            key_id = str(config.get("key_id") or "").strip()
            input_text = resolve_orchestration_template(
                str(config.get("input_template") or "{{input}}"),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            output = _evaluate_guardrail(db, key_id=key_id, input_text=input_text, environment=environment)
        elif node_type == "memory_write":
            content = resolve_orchestration_template(
                str(config.get("content_template") or "{{input}}"),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            resolved_scope_id = resolve_orchestration_template(
                str(config.get("scope_id") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            row = create_memory_record(
                db,
                actor_id=ctx.actor_id,
                memory_tier=str(config.get("memory_tier") or "short_term"),
                scope_type=str(config.get("scope_type") or "session"),
                scope_id=resolved_scope_id or trace_id,
                label=str(config.get("label") or f"orch-{node_id}"),
                content=content,
                metadata_json=json.dumps({"source": "orchestration", "node_id": node_id}),
                environment=environment,
                memory_id=str(uuid4()),
            )
            db.flush()
            output = {"live": True, "simulated": False, **serialize_memory_record(row)}
        elif node_type == "memory_read":
            resolved_scope_id = resolve_orchestration_template(
                str(config.get("scope_id") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            rows, total = list_memory_records(
                db,
                memory_tier=str(config.get("memory_tier") or "").strip() or None,
                scope_type=str(config.get("scope_type") or "").strip() or None,
                scope_id=resolved_scope_id or None,
                limit=int(config.get("limit") or 10),
            )
            output = {
                "live": True,
                "simulated": False,
                "records": [serialize_memory_record(row) for row in rows],
                "total": total,
            }
        elif node_type == "mcp_tool":
            server_id = str(config.get("server_id") or "").strip()
            tool_name = str(config.get("tool_name") or "").strip()
            server = dict(resolve_mcp_server(db, server_id))
            binding_id = str(config.get("binding_id") or "").strip()
            if binding_id:
                binding = load_active_binding_by_id(db, binding_id)
                resolved = resolve_binding_for_runtime(db, binding)
                token = str(resolved.secret_value or "").strip()
                if not token:
                    raise HTTPException(
                        status_code=422,
                        detail=f"MCP credential binding '{binding_id}' has no secret/token",
                    )
                # Optional override of the MCP server registry auth_token.
                server["auth_token"] = token
            arguments_raw = config.get("arguments_json") or "{}"
            arguments = json.loads(arguments_raw) if isinstance(arguments_raw, str) else arguments_raw
            if not isinstance(arguments, dict):
                arguments = {}
            resolved_args = {
                key: resolve_orchestration_template(str(value), step_outputs=step_outputs, run_input=run_input)
                if isinstance(value, str)
                else value
                for key, value in arguments.items()
            }
            result = mcp_call_tool(db, server, tool_name, resolved_args)
            output = {
                "live": True,
                "simulated": False,
                "server_id": server_id,
                "tool_name": tool_name,
                "binding_id": binding_id or None,
                "result": result,
            }
        elif node_type == "wait_delay":
            delay_raw = config.get("delay_seconds") or 1
            delay_seconds = max(1, min(3600, int(delay_raw)))
            max_wait = get_runtime_config_int(db, RUNTIME_CONFIG_ORCHESTRATION_LIVE_EXECUTOR_MAX_WAIT_SECONDS, 30)
            slept = min(delay_seconds, max_wait)
            time.sleep(slept)
            output = {
                "live": True,
                "simulated": False,
                "delay_seconds": delay_seconds,
                "waited_seconds": slept,
                "capped": slept < delay_seconds,
            }
        elif node_type == "wait_until":
            planned = evaluate_wait_until(config, step_outputs, run_input=run_input)
            if planned.get("error"):
                raise HTTPException(status_code=422, detail=str(planned["error"]))
            max_wait = get_runtime_config_int(db, RUNTIME_CONFIG_ORCHESTRATION_LIVE_EXECUTOR_MAX_WAIT_SECONDS, 30)
            to_sleep = min(int(planned.get("wait_seconds") or 0), max_wait)
            if to_sleep > 0:
                time.sleep(to_sleep)
            output = {
                "live": True,
                "simulated": False,
                **planned,
                "waited_seconds": to_sleep,
                "capped": to_sleep < int(planned.get("wait_seconds") or 0)
                or bool(planned.get("capped")),
            }
        elif node_type == "condition":
            matched = evaluate_condition(config, step_outputs)
            output = {
                "live": True,
                "simulated": False,
                "expression": config.get("expression"),
                "matched": matched,
            }
        elif node_type in {"while_loop", "do_while"}:
            # Graph walker expands iterations; this records gate metadata for the loop node.
            matched = evaluate_condition(config, step_outputs)
            try:
                delay_ms = int(config.get("delay_between_iterations_ms") or 0)
            except (TypeError, ValueError):
                delay_ms = 0
            delay_ms = max(0, min(5000, delay_ms))
            output = {
                "live": True,
                "simulated": False,
                "mode": node_type,
                "matched": matched,
                "index": 0,
                "iteration": 1,
                "expression": config.get("expression"),
                "body_branch": config.get("body_branch"),
                "exit_branch": config.get("exit_branch"),
                "max_iterations": clamp_while_max_iterations(config.get("max_iterations")),
                "collect_results": str(config.get("collect_results") or "").strip().lower()
                in {"1", "true", "yes", "on"},
                "delay_between_iterations_ms": delay_ms,
            }
        elif node_type == "switch":
            switched = evaluate_switch(config, step_outputs)
            output = {"live": True, "simulated": False, **switched}
        elif node_type == "filter":
            filtered = evaluate_filter(config, step_outputs)
            output = {"live": True, "simulated": False, **filtered}
        elif node_type == "merge_data":
            merged = merge_step_outputs(config, step_outputs)
            output = {"live": True, "simulated": False, **merged}
        elif node_type == "split_in_batches":
            split = evaluate_split_in_batches(config, step_outputs)
            output = {"live": True, "simulated": False, **split}
        elif node_type == "limit":
            limited = evaluate_limit(config, step_outputs)
            output = {"live": True, "simulated": False, **limited}
        elif node_type == "aggregate":
            aggregated = evaluate_aggregate(config, step_outputs)
            output = {"live": True, "simulated": False, **aggregated}
        elif node_type == "foreach_map":
            mapped = evaluate_foreach_map(config, step_outputs, run_input=run_input)
            output = {"live": True, "simulated": False, **mapped}
        elif node_type == "sort":
            sorted_out = evaluate_sort(config, step_outputs)
            output = {"live": True, "simulated": False, **sorted_out}
        elif node_type == "dedupe":
            deduped = evaluate_dedupe(config, step_outputs)
            output = {"live": True, "simulated": False, **deduped}
        elif node_type == "json_parse":
            parsed = evaluate_json_parse(config, step_outputs, run_input=run_input)
            output = {"live": True, "simulated": False, **parsed}
        elif node_type == "date_time":
            dated = evaluate_date_time(config, step_outputs, run_input=run_input)
            output = {"live": True, "simulated": False, **dated}
        elif node_type == "string_ops":
            stringed = evaluate_string_ops(config, step_outputs, run_input=run_input)
            output = {"live": True, "simulated": False, **stringed}
        elif node_type == "compare":
            compared = evaluate_compare(config, step_outputs, run_input=run_input)
            output = {"live": True, "simulated": False, **compared}
        elif node_type == "csv_parse":
            csv_out = evaluate_csv_parse(config, step_outputs, run_input=run_input)
            output = {"live": True, "simulated": False, **csv_out}
        elif node_type == "static_data":
            static_out = evaluate_static_data(config, step_outputs, run_input=run_input)
            output = {"live": True, "simulated": False, **static_out}
        elif node_type == "math_ops":
            math_out = evaluate_math_ops(config, step_outputs, run_input=run_input)
            if math_out.get("error"):
                raise HTTPException(status_code=422, detail=str(math_out["error"]))
            output = {"live": True, "simulated": False, **math_out}
        elif node_type == "uuid_gen":
            uuid_out = evaluate_uuid_gen(config)
            output = {"live": True, "simulated": False, **uuid_out}
        elif node_type == "hash_digest":
            hashed = evaluate_hash_digest(config, step_outputs, run_input=run_input)
            if hashed.get("error"):
                raise HTTPException(status_code=422, detail=str(hashed["error"]))
            output = {"live": True, "simulated": False, **hashed}
        elif node_type == "stop_and_error":
            stopped = evaluate_stop_and_error(config, step_outputs, run_input=run_input)
            raise HTTPException(status_code=422, detail=str(stopped.get("message") or "Stopped by stop_and_error"))
        elif node_type == "noop":
            output = {"live": True, "simulated": False, **evaluate_noop(config, step_outputs)}
        elif node_type == "json_to_csv":
            output = {"live": True, "simulated": False, **evaluate_json_to_csv(config, step_outputs)}
        elif node_type == "split_out":
            output = {"live": True, "simulated": False, **evaluate_split_out(config, step_outputs)}
        elif node_type == "pick_fields":
            output = {"live": True, "simulated": False, **evaluate_pick_fields(config, step_outputs)}
        elif node_type == "rename_keys":
            output = {"live": True, "simulated": False, **evaluate_rename_keys(config, step_outputs)}
        elif node_type == "boolean_logic":
            output = {"live": True, "simulated": False, **evaluate_boolean_logic(config, step_outputs)}
        elif node_type == "html_strip":
            output = {
                "live": True,
                "simulated": False,
                **evaluate_html_strip(config, step_outputs, run_input=run_input),
            }
        elif node_type == "url_ops":
            output = {
                "live": True,
                "simulated": False,
                **evaluate_url_ops(config, step_outputs, run_input=run_input),
            }
        elif node_type == "base64_ops":
            b64 = evaluate_base64_ops(config, step_outputs, run_input=run_input)
            if b64.get("error"):
                raise HTTPException(status_code=422, detail=str(b64["error"]))
            output = {"live": True, "simulated": False, **b64}
        elif node_type == "coalesce":
            output = {
                "live": True,
                "simulated": False,
                **evaluate_coalesce(config, step_outputs, run_input=run_input),
            }
        elif node_type == "omit_fields":
            output = {"live": True, "simulated": False, **evaluate_omit_fields(config, step_outputs)}
        elif node_type == "append_items":
            output = {"live": True, "simulated": False, **evaluate_append_items(config, step_outputs)}
        elif node_type == "number_format":
            formatted = evaluate_number_format(config, step_outputs, run_input=run_input)
            if formatted.get("error"):
                raise HTTPException(status_code=422, detail=str(formatted["error"]))
            output = {"live": True, "simulated": False, **formatted}
        elif node_type == "regex_extract":
            extracted = evaluate_regex_extract(config, step_outputs, run_input=run_input)
            if extracted.get("error"):
                raise HTTPException(status_code=422, detail=str(extracted["error"]))
            output = {"live": True, "simulated": False, **extracted}
        elif node_type == "text_template":
            output = {
                "live": True,
                "simulated": False,
                **evaluate_text_template(config, step_outputs, run_input=run_input),
            }
        elif node_type == "timezone_convert":
            tz_out = evaluate_timezone_convert(config, step_outputs, run_input=run_input)
            if tz_out.get("error"):
                raise HTTPException(status_code=422, detail=str(tz_out["error"]))
            output = {"live": True, "simulated": False, **tz_out}
        elif node_type == "item_exists":
            output = {"live": True, "simulated": False, **evaluate_item_exists(config, step_outputs)}
        elif node_type == "flatten_json":
            output = {"live": True, "simulated": False, **evaluate_flatten_json(config, step_outputs)}
        elif node_type == "json_stringify":
            stringified = evaluate_json_stringify(config, step_outputs)
            if stringified.get("error"):
                raise HTTPException(status_code=422, detail=str(stringified["error"]))
            output = {"live": True, "simulated": False, **stringified}
        elif node_type == "type_of":
            output = {"live": True, "simulated": False, **evaluate_type_of(config, step_outputs)}
        elif node_type == "xml_parse":
            parsed_xml = evaluate_xml_parse(config, step_outputs)
            if parsed_xml.get("error"):
                raise HTTPException(status_code=422, detail=str(parsed_xml["error"]))
            output = {"live": True, "simulated": False, **parsed_xml}
        elif node_type == "unflatten_json":
            output = {"live": True, "simulated": False, **evaluate_unflatten_json(config, step_outputs)}
        elif node_type == "chunk_text":
            output = {"live": True, "simulated": False, **evaluate_chunk_text(config, step_outputs)}
        elif node_type == "form_urlencoded":
            form_out = evaluate_form_urlencoded(config, step_outputs)
            if form_out.get("error"):
                raise HTTPException(status_code=422, detail=str(form_out["error"]))
            output = {"live": True, "simulated": False, **form_out}
        elif node_type == "deep_merge":
            output = {"live": True, "simulated": False, **evaluate_deep_merge(config, step_outputs)}
        elif node_type == "jwt_decode":
            jwt_out = evaluate_jwt_decode(config, step_outputs)
            if jwt_out.get("error"):
                raise HTTPException(status_code=422, detail=str(jwt_out["error"]))
            output = {"live": True, "simulated": False, **jwt_out}
        elif node_type == "html_extract":
            html_out = evaluate_html_extract(config, step_outputs)
            if html_out.get("error"):
                raise HTTPException(status_code=422, detail=str(html_out["error"]))
            output = {"live": True, "simulated": False, **html_out}
        elif node_type == "split_text":
            output = {"live": True, "simulated": False, **evaluate_split_text(config, step_outputs)}
        elif node_type == "json_query":
            output = {"live": True, "simulated": False, **evaluate_json_query(config, step_outputs)}
        elif node_type == "compress":
            compressed = evaluate_compress(config, step_outputs)
            if compressed.get("error"):
                raise HTTPException(status_code=422, detail=str(compressed["error"]))
            output = {"live": True, "simulated": False, **compressed}
        elif node_type == "random":
            random_out = evaluate_random(config, step_outputs)
            if random_out.get("error"):
                raise HTTPException(status_code=422, detail=str(random_out["error"]))
            output = {"live": True, "simulated": False, **random_out}
        elif node_type == "hmac_verify":
            hmac_out = evaluate_hmac_verify(config, step_outputs, run_input=run_input)
            if hmac_out.get("error"):
                raise HTTPException(status_code=422, detail=str(hmac_out["error"]))
            output = {"live": True, "simulated": False, **hmac_out}
        elif node_type == "xml_stringify":
            xml_out = evaluate_xml_stringify(config, step_outputs)
            if xml_out.get("error"):
                raise HTTPException(status_code=422, detail=str(xml_out["error"]))
            output = {"live": True, "simulated": False, **xml_out}
        elif node_type == "object_diff":
            output = {"live": True, "simulated": False, **evaluate_object_diff(config, step_outputs)}
        elif node_type == "html_to_markdown":
            md_out = evaluate_html_to_markdown(config, step_outputs)
            if md_out.get("error"):
                raise HTTPException(status_code=422, detail=str(md_out["error"]))
            output = {"live": True, "simulated": False, **md_out}
        elif node_type == "markdown_to_html":
            html_out = evaluate_markdown_to_html(config, step_outputs, run_input=run_input)
            if html_out.get("error"):
                raise HTTPException(status_code=422, detail=str(html_out["error"]))
            output = {"live": True, "simulated": False, **html_out}
        elif node_type == "array_ops":
            array_out = evaluate_array_ops(config, step_outputs)
            if array_out.get("error"):
                raise HTTPException(status_code=422, detail=str(array_out["error"]))
            output = {"live": True, "simulated": False, **array_out}
        elif node_type == "compact_object":
            compact_out = evaluate_compact_object(config, step_outputs)
            if compact_out.get("error"):
                raise HTTPException(status_code=422, detail=str(compact_out["error"]))
            output = {"live": True, "simulated": False, **compact_out}
        elif node_type == "pagerduty_event":
            binding_id = str(config.get("auth_binding_id") or "").strip()
            if not binding_id:
                raise HTTPException(status_code=422, detail="pagerduty_event requires auth_binding_id")
            binding = load_active_binding_by_id(db, binding_id)
            if binding is None:
                raise HTTPException(status_code=404, detail=f"Credential binding '{binding_id}' not found")
            resolved = resolve_binding_for_runtime(db, binding)
            routing_key = str(resolved.secret_value or "").strip()
            if not routing_key:
                raise HTTPException(status_code=422, detail="pagerduty_event binding has no routing key secret")
            host_error = _validate_http_url(db, PAGERDUTY_EVENTS_API_BASE)
            if host_error:
                raise HTTPException(status_code=403, detail=host_error)
            summary = resolve_orchestration_template(
                str(config.get("summary_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip() or "Orchestration alert"
            source = resolve_orchestration_template(
                str(config.get("source_template") or "orchestration"),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip() or "orchestration"
            component = resolve_orchestration_template(
                str(config.get("component_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            severity = str(config.get("severity") or "info").strip().lower() or "info"
            if severity not in {"critical", "error", "warning", "info"}:
                severity = "info"
            details_raw = config.get("custom_details_json") or "{}"
            details_text = resolve_orchestration_template(
                str(details_raw),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            try:
                custom_details = json.loads(details_text) if isinstance(details_text, str) else details_text
            except json.JSONDecodeError as exc:
                raise HTTPException(status_code=422, detail="custom_details_json must be valid JSON") from exc
            if not isinstance(custom_details, dict):
                custom_details = {}
            payload = {
                "routing_key": routing_key,
                "event_action": "trigger",
                "payload": {
                    "summary": summary[:1024],
                    "severity": severity,
                    "source": source[:255],
                    "custom_details": custom_details,
                },
            }
            if component:
                payload["payload"]["component"] = component[:255]
            response = httpx.post(
                f"{PAGERDUTY_EVENTS_API_BASE}/v2/enqueue",
                json=payload,
                timeout=30.0,
            )
            output = {
                "live": True,
                "simulated": False,
                "provider": "pagerduty",
                "severity": severity,
                "summary": summary,
                "status_code": response.status_code,
                "delivery_status": "sent" if response.status_code < 300 else "failed",
                "body_preview": (response.text or "")[:512],
            }
            if response.status_code >= 300:
                raise HTTPException(
                    status_code=422,
                    detail=f"PagerDuty Events API returned HTTP {response.status_code}",
                )
        elif node_type == "opsgenie_alert":
            binding_id = str(config.get("auth_binding_id") or "").strip()
            if not binding_id:
                raise HTTPException(status_code=422, detail="opsgenie_alert requires auth_binding_id")
            binding = load_active_binding_by_id(db, binding_id)
            if binding is None:
                raise HTTPException(status_code=404, detail=f"Credential binding '{binding_id}' not found")
            resolved = resolve_binding_for_runtime(db, binding)
            genie_key = str(resolved.secret_value or "").strip()
            if not genie_key:
                raise HTTPException(status_code=422, detail="opsgenie_alert binding has no GenieKey secret")
            host_error = _validate_http_url(db, OPSGENIE_API_BASE)
            if host_error:
                raise HTTPException(status_code=403, detail=host_error)
            message = resolve_orchestration_template(
                str(config.get("summary_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip() or "Orchestration alert"
            description = resolve_orchestration_template(
                str(config.get("description_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            alias = resolve_orchestration_template(
                str(config.get("alias_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            source = resolve_orchestration_template(
                str(config.get("source_template") or "orchestration"),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip() or "orchestration"
            tags_text = resolve_orchestration_template(
                str(config.get("tags_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            tags = [part.strip()[:64] for part in tags_text.split(",") if part.strip()][:16]
            priority = str(config.get("priority") or "P3").strip().upper() or "P3"
            if priority not in {"P1", "P2", "P3", "P4", "P5"}:
                priority = "P3"
            details_raw = config.get("custom_details_json") or "{}"
            details_text = resolve_orchestration_template(
                str(details_raw),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            try:
                details = json.loads(details_text) if isinstance(details_text, str) else details_text
            except json.JSONDecodeError as exc:
                raise HTTPException(status_code=422, detail="custom_details_json must be valid JSON") from exc
            if not isinstance(details, dict):
                details = {}
            payload = {
                "message": message[:130],
                "priority": priority,
                "source": source[:100],
                "details": {str(k)[:64]: str(v)[:512] for k, v in list(details.items())[:32]},
            }
            if description:
                payload["description"] = description[:15000]
            if alias:
                payload["alias"] = alias[:512]
            if tags:
                payload["tags"] = tags
            response = httpx.post(
                f"{OPSGENIE_API_BASE}/v2/alerts",
                headers={
                    "Authorization": f"GenieKey {genie_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=30.0,
            )
            output = {
                "live": True,
                "simulated": False,
                "provider": "opsgenie",
                "priority": priority,
                "message": message,
                "status_code": response.status_code,
                "delivery_status": "sent" if response.status_code < 300 else "failed",
                "body_preview": (response.text or "")[:512],
            }
            if response.status_code >= 300:
                raise HTTPException(
                    status_code=422,
                    detail=f"Opsgenie Alerts API returned HTTP {response.status_code}",
                )
        elif node_type == "datadog_event":
            binding_id = str(config.get("auth_binding_id") or "").strip()
            if not binding_id:
                raise HTTPException(status_code=422, detail="datadog_event requires auth_binding_id")
            binding = load_active_binding_by_id(db, binding_id)
            if binding is None:
                raise HTTPException(status_code=404, detail=f"Credential binding '{binding_id}' not found")
            resolved = resolve_binding_for_runtime(db, binding)
            dd_api_key = str(resolved.secret_value or "").strip()
            if not dd_api_key:
                raise HTTPException(status_code=422, detail="datadog_event binding has no DD-API-KEY secret")
            host_error = _validate_http_url(db, DATADOG_API_BASE)
            if host_error:
                raise HTTPException(status_code=403, detail=host_error)
            title = resolve_orchestration_template(
                str(config.get("summary_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip() or "Orchestration event"
            text = resolve_orchestration_template(
                str(config.get("description_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            alert_type = str(config.get("alert_type") or "info").strip().lower() or "info"
            if alert_type not in DATADOG_ALERT_TYPES:
                alert_type = "info"
            tags_text = resolve_orchestration_template(
                str(config.get("tags_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            tags = [part.strip()[:128] for part in tags_text.split(",") if part.strip()][:32]
            source_type_name = resolve_orchestration_template(
                str(config.get("source_type_name") or "orchestration"),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip() or "orchestration"
            payload = {
                "title": title[:100],
                "alert_type": alert_type,
                "source_type_name": source_type_name[:100],
            }
            if text:
                payload["text"] = text[:4000]
            if tags:
                payload["tags"] = tags
            response = httpx.post(
                f"{DATADOG_API_BASE}/api/v1/events",
                headers={
                    "DD-API-KEY": dd_api_key,
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=30.0,
            )
            output = {
                "live": True,
                "simulated": False,
                "provider": "datadog",
                "alert_type": alert_type,
                "title": title,
                "status_code": response.status_code,
                "delivery_status": "sent" if response.status_code < 300 else "failed",
                "body_preview": (response.text or "")[:512],
            }
            if response.status_code >= 300:
                raise HTTPException(
                    status_code=422,
                    detail=f"Datadog Events API returned HTTP {response.status_code}",
                )
        elif node_type == "sentry_event":
            binding_id = str(config.get("auth_binding_id") or "").strip()
            if not binding_id:
                raise HTTPException(status_code=422, detail="sentry_event requires auth_binding_id")
            binding = load_active_binding_by_id(db, binding_id)
            if binding is None:
                raise HTTPException(status_code=404, detail=f"Credential binding '{binding_id}' not found")
            resolved = resolve_binding_for_runtime(db, binding)
            auth_token = str(resolved.secret_value or "").strip()
            if not auth_token:
                raise HTTPException(status_code=422, detail="sentry_event binding has no auth token secret")
            host_error = _validate_http_url(db, SENTRY_API_BASE)
            if host_error:
                raise HTTPException(status_code=403, detail=host_error)
            organization_slug = resolve_orchestration_template(
                str(config.get("organization_slug") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            project_slug = resolve_orchestration_template(
                str(config.get("project_slug") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            if not organization_slug or not project_slug:
                raise HTTPException(
                    status_code=422,
                    detail="sentry_event requires organization_slug and project_slug",
                )
            if "/" in organization_slug or "://" in organization_slug or "/" in project_slug or "://" in project_slug:
                raise HTTPException(
                    status_code=422,
                    detail="sentry_event organization_slug/project_slug must be slugs",
                )
            message = resolve_orchestration_template(
                str(config.get("summary_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip() or "Orchestration event"
            level = str(config.get("level") or "error").strip().lower() or "error"
            if level not in SENTRY_LEVELS:
                level = "error"
            tags_text = resolve_orchestration_template(
                str(config.get("tags_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            normalized_tags: dict[str, str] = {}
            for part in tags_text.split(","):
                token = part.strip()
                if not token:
                    continue
                if "=" in token:
                    raw_key, raw_value = token.split("=", 1)
                    key = raw_key.strip()[:64]
                    value = raw_value.strip()[:128] or "true"
                else:
                    key = token[:64]
                    value = "true"
                if key:
                    normalized_tags[key] = value
                if len(normalized_tags) >= 16:
                    break
            fingerprint_text = resolve_orchestration_template(
                str(config.get("fingerprint_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            fingerprint = [part.strip()[:128] for part in fingerprint_text.split(",") if part.strip()][:8]
            payload = {
                "message": message[:1000],
                "level": level,
                "platform": "other",
                "logger": "orchestration",
                "tags": normalized_tags,
            }
            if fingerprint:
                payload["fingerprint"] = fingerprint
            response = httpx.post(
                f"{SENTRY_API_BASE}/api/0/projects/{organization_slug}/{project_slug}/store/",
                headers={
                    "Authorization": f"Bearer {auth_token}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=30.0,
            )
            output = {
                "live": True,
                "simulated": False,
                "provider": "sentry",
                "level": level,
                "message": message,
                "organization_slug": organization_slug,
                "project_slug": project_slug,
                "status_code": response.status_code,
                "delivery_status": "sent" if response.status_code < 300 else "failed",
                "body_preview": (response.text or "")[:512],
            }
            if response.status_code >= 300:
                raise HTTPException(
                    status_code=422,
                    detail=f"Sentry store API returned HTTP {response.status_code}",
                )
        elif node_type == "statuspage_incident":
            binding_id = str(config.get("auth_binding_id") or "").strip()
            if not binding_id:
                raise HTTPException(status_code=422, detail="statuspage_incident requires auth_binding_id")
            binding = load_active_binding_by_id(db, binding_id)
            if binding is None:
                raise HTTPException(status_code=404, detail=f"Credential binding '{binding_id}' not found")
            resolved = resolve_binding_for_runtime(db, binding)
            api_key = str(resolved.secret_value or "").strip()
            if not api_key:
                raise HTTPException(status_code=422, detail="statuspage_incident binding has no API key secret")
            host_error = _validate_http_url(db, STATUSPAGE_API_BASE)
            if host_error:
                raise HTTPException(status_code=403, detail=host_error)
            page_id = resolve_orchestration_template(
                str(config.get("page_id") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            if not page_id or "/" in page_id or "://" in page_id:
                raise HTTPException(status_code=422, detail="statuspage_incident requires a valid page_id")
            name = resolve_orchestration_template(
                str(config.get("name_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip() or "Orchestration incident"
            body = resolve_orchestration_template(
                str(config.get("body_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            status = str(config.get("status") or "investigating").strip().lower() or "investigating"
            if status not in STATUSPAGE_STATUSES:
                status = "investigating"
            impact = str(config.get("impact") or "minor").strip().lower() or "minor"
            if impact not in STATUSPAGE_IMPACTS:
                impact = "minor"
            components_text = resolve_orchestration_template(
                str(config.get("component_ids_csv") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            component_ids = [part.strip()[:64] for part in components_text.split(",") if part.strip()][:32]
            incident_payload: dict[str, Any] = {
                "name": name[:255],
                "status": status,
                "impact_override": impact,
            }
            if body:
                incident_payload["body"] = body[:10000]
            if component_ids:
                incident_payload["component_ids"] = component_ids
            response = httpx.post(
                f"{STATUSPAGE_API_BASE}/v1/pages/{page_id}/incidents",
                headers={
                    "Authorization": f"OAuth {api_key}",
                    "Content-Type": "application/json",
                },
                json={"incident": incident_payload},
                timeout=30.0,
            )
            output = {
                "live": True,
                "simulated": False,
                "provider": "statuspage",
                "page_id": page_id,
                "name": name,
                "status": status,
                "impact": impact,
                "status_code": response.status_code,
                "delivery_status": "sent" if response.status_code < 300 else "failed",
                "body_preview": (response.text or "")[:512],
            }
            if response.status_code >= 300:
                raise HTTPException(
                    status_code=422,
                    detail=f"Statuspage API returned HTTP {response.status_code}",
                )
        elif node_type == "graphql_request":
            url = resolve_orchestration_template(
                str(config.get("url") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            host_error = _validate_http_url(db, url)
            if host_error:
                raise HTTPException(status_code=403, detail=host_error)
            query = resolve_orchestration_template(
                str(config.get("query_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            variables_raw = config.get("variables_json") or "{}"
            variables_text = resolve_orchestration_template(
                str(variables_raw),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            try:
                variables = json.loads(variables_text) if isinstance(variables_text, str) else variables_text
            except json.JSONDecodeError as exc:
                raise HTTPException(status_code=422, detail="variables_json must be valid JSON") from exc
            if not isinstance(variables, dict):
                variables = {}
            payload_body: dict[str, Any] = {"query": query, "variables": variables}
            operation_name = resolve_orchestration_template(
                str(config.get("operation_name") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            if operation_name:
                payload_body["operationName"] = operation_name
            auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
            auth_binding_id = str(config.get("auth_binding_id") or "").strip() or None
            auth_header_name = config.get("auth_header_name")
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                **apply_http_auth_headers(
                    db,
                    auth_type=auth_type,
                    auth_binding_id=auth_binding_id,
                    auth_header_name=str(auth_header_name) if auth_header_name is not None else None,
                ),
            }
            response = httpx.post(url, headers=headers, json=payload_body, timeout=30.0)
            parsed_data: Any = {"raw": (response.text or "")[:2048]}
            try:
                candidate = response.json()
                if isinstance(candidate, (dict, list)):
                    parsed_data = candidate
            except Exception:
                pass
            output = {
                "live": True,
                "simulated": False,
                "provider": "graphql",
                "url": url,
                "status_code": response.status_code,
                "status": response.status_code,
                "data": parsed_data,
            }
            if response.status_code >= 300:
                raise HTTPException(
                    status_code=422,
                    detail=f"GraphQL request returned HTTP {response.status_code}",
                )
        elif node_type == "telegram_notify":
            binding_id = str(config.get("auth_binding_id") or "").strip()
            if not binding_id:
                raise HTTPException(status_code=422, detail="telegram_notify requires auth_binding_id")
            binding = load_active_binding_by_id(db, binding_id)
            if binding is None:
                raise HTTPException(status_code=404, detail=f"Credential binding '{binding_id}' not found")
            resolved = resolve_binding_for_runtime(db, binding)
            token = str(resolved.secret_value or "").strip()
            if not token:
                raise HTTPException(status_code=422, detail="telegram_notify binding has no secret/token")
            chat_id = resolve_orchestration_template(
                str(config.get("chat_id_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            text = resolve_orchestration_template(
                str(config.get("text_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            if not chat_id:
                raise HTTPException(status_code=422, detail="telegram_notify requires chat_id_template")
            url = f"{TELEGRAM_API_BASE}/bot{token}/sendMessage"
            host_error = _validate_http_url(db, TELEGRAM_API_BASE)
            if host_error:
                raise HTTPException(status_code=403, detail=host_error)
            payload_body: dict[str, Any] = {"chat_id": chat_id, "text": text}
            parse_mode = str(config.get("parse_mode") or "").strip()
            if parse_mode in {"Markdown", "MarkdownV2", "HTML"}:
                payload_body["parse_mode"] = parse_mode
            response = httpx.post(url, json=payload_body, timeout=30.0)
            output = {
                "live": True,
                "simulated": False,
                "provider": "telegram",
                "chat_id": chat_id,
                "status_code": response.status_code,
                "delivery_status": "sent" if response.status_code < 300 else "failed",
                "body_preview": (response.text or "")[:512],
            }
            if response.status_code >= 300:
                raise HTTPException(
                    status_code=422,
                    detail=f"Telegram API returned HTTP {response.status_code}",
                )
        elif node_type == "execute_subflow":
            target_flow_id = resolve_orchestration_template(
                str(config.get("target_flow_id") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            if not target_flow_id:
                raise HTTPException(status_code=422, detail="execute_subflow requires target_flow_id")
            if target_flow_id == flow_id:
                raise HTTPException(status_code=422, detail="execute_subflow cannot call its own flow")
            depth = _subflow_depth.get()
            if depth >= MAX_SUBFLOW_DEPTH:
                raise HTTPException(
                    status_code=422,
                    detail=f"execute_subflow depth exceeded (max {MAX_SUBFLOW_DEPTH})",
                )
            child = db.query(OrchestrationFlowDefinition).filter_by(flow_id=target_flow_id).first()
            if child is None:
                raise HTTPException(status_code=404, detail=f"Subflow '{target_flow_id}' not found")
            child_input = resolve_orchestration_template(
                str(config.get("input_template") or "{{input}}"),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            token = _subflow_depth.set(depth + 1)
            try:
                child_status, child_steps, child_error, child_live, _state = execute_flow(
                    db,
                    ctx,
                    flow_id=child.flow_id,
                    run_id=f"{run_id}-sub-{uuid4().hex[:8]}",
                    graph_json=child.graph_json,
                    environment=environment,
                    dry_run=False,
                    trace_id=f"{trace_id}-sub",
                    run_input=child_input,
                )
            finally:
                _subflow_depth.reset(token)
            if child_status == "failed":
                raise HTTPException(
                    status_code=422,
                    detail=child_error or f"Subflow '{target_flow_id}' failed",
                )
            last_outputs = {
                str(step.get("node_id")): step.get("output")
                for step in child_steps
                if isinstance(step, dict) and step.get("node_id")
            }
            output = {
                "live": True,
                "simulated": False,
                "nested": True,
                "target_flow_id": target_flow_id,
                "status": child_status,
                "step_count": len(child_steps),
                "live_executor_used": child_live,
                "error_summary": child_error,
                "steps": child_steps[-20:],
                "outputs": last_outputs,
            }
        elif node_type == "respond_to_webhook":
            status_code = 200
            try:
                status_code = int(config.get("status_code") or 200)
            except (TypeError, ValueError):
                status_code = 200
            status_code = max(100, min(599, status_code))
            content_type = str(config.get("content_type") or "application/json").strip() or "application/json"
            source_node_id = str(config.get("source_node_id") or "").strip()
            if source_node_id and source_node_id in step_outputs:
                body: Any = step_outputs.get(source_node_id)
            else:
                body_raw = resolve_orchestration_template(
                    str(config.get("body_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                body = body_raw
                if content_type.startswith("application/json"):
                    try:
                        body = json.loads(body_raw)
                    except json.JSONDecodeError:
                        body = body_raw
            output = {
                "live": True,
                "simulated": False,
                "webhook_response": True,
                "status_code": status_code,
                "content_type": content_type,
                "body": body,
            }
        elif node_type in {
            "http_request",
            "github_api",
            "gitlab_api",
            "bitbucket_api",
            "jira_api",
            "confluence_api",
            "linear_api",
            "notion_api",
            "hubspot_api",
            "zendesk_api",
            "freshdesk_api",
            "salesforce_api",
            "servicenow_api",
            "airtable_api",
            "asana_api",
            "clickup_api",
            "intercom_api",
            "monday_api",
            "pipedrive_api",
            "shopify_api",
            "stripe_api",
            "box_api",
            "dropbox_api",
            "calendly_api",
            "microsoft_graph_api",
            "google_sheets_api",
            "google_drive_api",
            "google_calendar_api",
            "slack_api",
            "zoom_api",
            "twilio_api",
            "sendgrid_api",
            "freshservice_api",
            "okta_api",
            "auth0_api",
            "azure_devops_api",
            "snowflake_api",
            "databricks_api",
            "bigquery_api",
            "splunk_api",
            "elasticsearch_api",
            "redis_api",
            "mongodb_api",
            "postgres_api",
            "mysql_api",
            "s3_api",
            "pinecone_api",
            "weaviate_api",
            "qdrant_api",
            "supabase_api",
            "kafka_api",
            "milvus_api",
            "chroma_api",
            "neo4j_api",
            "rabbitmq_api",
            "opensearch_api",
            "clickhouse_api",
            "dynamodb_api",
            "nats_api",
            "cassandra_api",
            "couchbase_api",
            "influxdb_api",
            "firebase_api",
            "airbyte_api",
            "presto_api",
            "trino_api",
            "redshift_api",
            "athena_api",
            "pulsar_api",
            "scylladb_api",
            "sqs_api",
            "sns_api",
            "kinesis_api",
            "eventbridge_api",
            "lambda_api",
            "stepfunctions_api",
            "cloudwatch_api",
            "xray_api",
            "glue_api",
            "sagemaker_api",
            "bedrock_api",
            "comprehend_api",
            "textract_api",
            "rekognition_api",
            "translate_api",
            "polly_api",
            "transcribe_api",
            "lex_api",
            "ecs_api",
            "eks_api",
            "secretsmanager_api",
            "ssm_api",
            "cognito_api",
            "iam_api",
            "kms_api",
            "sts_api",
            "apigateway_api",
            "cloudformation_api",
            "rds_api",
            "elb_api",
            "cloudfront_api",
            "route53_api",
            "cloudtrail_api",
            "config_api",
            "guardduty_api",
            "securityhub_api",
            "inspector_api",
            "macie_api",
            "waf_api",
            "shield_api",
            "acm_api",
            "networkfirewall_api",
            "ecr_api",
            "efs_api",
            "detective_api",
            "accessanalyzer_api",
            "fargate_api",
            "batch_api",
            "elasticache_api",
            "memorydb_api",
            "emr_api",
            "firehose_api",
            "msk_api",
            "appsync_api",
            "amazon_mq_api",
            "neptune_api",
            "documentdb_api",
            "fsx_api",
            "kendra_api",
            "personalize_api",
            "forecast_api",
            "mediaconvert_api",
            "transfer_api",
            "datasync_api",
            "backup_api",
            "lightsail_api",
            "elasticbeanstalk_api",
            "workspaces_api",
            "appstream_api",
            "mediastore_api",
            "outposts_api",
            "storagegateway_api",
            "directconnect_api",
            "transitgateway_api",
            "ec2_api",
            "autoscaling_api",
            "organizations_api",
            "ram_api",
            "codebuild_api",
            "codepipeline_api",
            "codedeploy_api",
            "codecommit_api",
            "cloud9_api",
            "amplify_api",
            "fis_api",
            "resiliencehub_api",
            "wellarchitected_api",
            "support_api",
            "trustedadvisor_api",
            "controltower_api",
            "servicecatalog_api",
            "lakeformation_api",
            "ses_api",
            "pinpoint_api",
            "connect_api",
            "chime_api",
            "ivs_api",
            "gamelift_api",
            "braket_api",
            "qldb_api",
            "timestream_api",
            "appconfig_api",
            "grafana_api",
            "prometheus_api",
            "location_api",
            "emrserverless_api",
            "iot_api",
            "greengrass_api",
            "iotanalytics_api",
            "freertos_api",
            "datazone_api",
            "cleanrooms_api",
            "entityresolution_api",
            "supplychain_api",
            "amp_api",
            "managedgrafana_api",
            "opensearchserverless_api",
            "mwaa_api",
            "appflow_api",
            "databrew_api",
            "healthlake_api",
            "medicalimaging_api",
            "omics_api",
            "finspace_api",
            "lookoutmetrics_api",
            "lookoutvision_api",
            "evidently_api",
            "rum_api",
            "trello_api",
        }:
            if node_type == "github_api":
                owner = resolve_orchestration_template(
                    str(config.get("owner_template") or config.get("owner") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                repo = resolve_orchestration_template(
                    str(config.get("repo_template") or config.get("repo") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                issue_number = resolve_orchestration_template(
                    str(config.get("issue_number_template") or config.get("issue_number") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                preset_method, preset_path = resolve_connector_operation_preset(
                    node_type, config, owner=owner, repo=repo, issue_number=issue_number
                )
                path = resolve_orchestration_template(
                    str(config.get("path_template") or preset_path or "/"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=GITHUB_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or preset_method or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
                provider = "github"
            elif node_type == "gitlab_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/user"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=GITLAB_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "gitlab"
            elif node_type == "bitbucket_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/user"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=BITBUCKET_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "bitbucket"
            elif node_type == "stripe_api":
                preset_method, preset_path = resolve_connector_operation_preset(node_type, config)
                path = resolve_orchestration_template(
                    str(config.get("path_template") or preset_path or "/v1/balance"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=STRIPE_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or preset_method or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json"}
                provider = "stripe"
            elif node_type == "box_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/users/me"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=BOX_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "box"
            elif node_type == "dropbox_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/2/users/get_current_account"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=DROPBOX_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or "POST").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "dropbox"
            elif node_type == "calendly_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/users/me"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=CALENDLY_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "calendly"
            elif node_type == "microsoft_graph_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/me"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(
                    base_url=MICROSOFT_GRAPH_API_BASE,
                    path_template=path,
                    query_template=query,
                )
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "microsoft_graph"
            elif node_type == "google_sheets_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/spreadsheets"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(
                    base_url=GOOGLE_SHEETS_API_BASE,
                    path_template=path,
                    query_template=query,
                )
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "google_sheets"
            elif node_type == "google_drive_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/files"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(
                    base_url=GOOGLE_DRIVE_API_BASE,
                    path_template=path,
                    query_template=query,
                )
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "google_drive"
            elif node_type == "google_calendar_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/users/me/calendarList"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(
                    base_url=GOOGLE_CALENDAR_API_BASE,
                    path_template=path,
                    query_template=query,
                )
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "google_calendar"
            elif node_type == "slack_api":
                preset_method, preset_path = resolve_connector_operation_preset(node_type, config)
                path = resolve_orchestration_template(
                    str(config.get("path_template") or preset_path or "/auth.test"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=SLACK_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or preset_method or "POST").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "slack"
            elif node_type == "zoom_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/users/me"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=ZOOM_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "zoom"
            elif node_type == "twilio_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/2010-04-01/Accounts.json"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=TWILIO_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "basic").strip().lower() or "basic"
                headers = {"Accept": "application/json"}
                provider = "twilio"
            elif node_type == "sendgrid_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/v3/user/profile"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=SENDGRID_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "sendgrid"
            elif node_type == "linear_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/graphql"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=LINEAR_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or "POST").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "linear"
            elif node_type == "notion_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/v1/users/me"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=NOTION_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                notion_version = (
                    resolve_orchestration_template(
                        str(config.get("notion_version") or NOTION_API_VERSION),
                        step_outputs=step_outputs,
                        run_input=run_input,
                    ).strip()
                    or NOTION_API_VERSION
                )
                headers = {
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Notion-Version": notion_version,
                }
                provider = "notion"
            elif node_type == "hubspot_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/crm/v3/objects/contacts"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=HUBSPOT_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "hubspot"
            elif node_type == "airtable_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/v0/meta/bases"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=AIRTABLE_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "airtable"
            elif node_type == "asana_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/api/1.0/users/me"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=ASANA_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "asana"
            elif node_type == "clickup_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/api/v2/user"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=CLICKUP_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "clickup"
            elif node_type == "intercom_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/me"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=INTERCOM_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                intercom_version = (
                    resolve_orchestration_template(
                        str(config.get("intercom_version") or INTERCOM_API_VERSION),
                        step_outputs=step_outputs,
                        run_input=run_input,
                    ).strip()
                    or INTERCOM_API_VERSION
                )
                headers = {
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Intercom-Version": intercom_version,
                }
                provider = "intercom"
            elif node_type == "monday_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/v2"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=MONDAY_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or "POST").strip().upper()
                auth_type = str(config.get("auth_type") or "bearer").strip().lower() or "bearer"
                headers = {
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "API-Version": "2024-01",
                }
                provider = "monday"
            elif node_type == "trello_api":
                path = resolve_orchestration_template(
                    str(config.get("path_template") or "/1/members/me"),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=TRELLO_API_BASE, path_template=path, query_template=query)
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "api_key").strip().lower() or "api_key"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider = "trello"
            elif node_type in {
                "jira_api",
                "confluence_api",
                "zendesk_api",
                "freshdesk_api",
                "freshservice_api",
                "okta_api",
                "auth0_api",
                "azure_devops_api",
                "snowflake_api",
                "databricks_api",
                "bigquery_api",
                "splunk_api",
                "elasticsearch_api",
                "redis_api",
                "mongodb_api",
                "postgres_api",
                "mysql_api",
                "s3_api",
                "pinecone_api",
                "weaviate_api",
                "qdrant_api",
                "supabase_api",
                "kafka_api",
                "milvus_api",
                "chroma_api",
                "neo4j_api",
                "rabbitmq_api",
                "opensearch_api",
                "clickhouse_api",
                "dynamodb_api",
                "nats_api",
                "cassandra_api",
                "couchbase_api",
                "influxdb_api",
                "firebase_api",
                "airbyte_api",
                "presto_api",
                "trino_api",
                "redshift_api",
                "athena_api",
                "pulsar_api",
                "scylladb_api",
                "sqs_api",
                "sns_api",
                "kinesis_api",
                "eventbridge_api",
                "lambda_api",
                "stepfunctions_api",
                "cloudwatch_api",
                "xray_api",
                "glue_api",
                "sagemaker_api",
                "bedrock_api",
                "comprehend_api",
                "textract_api",
                "rekognition_api",
                "translate_api",
                "polly_api",
                "transcribe_api",
                "lex_api",
                "ecs_api",
                "eks_api",
                "secretsmanager_api",
                "ssm_api",
                "cognito_api",
                "iam_api",
                "kms_api",
                "sts_api",
                "apigateway_api",
                "cloudformation_api",
                "rds_api",
                "elb_api",
                "cloudfront_api",
                "route53_api",
                "cloudtrail_api",
                "config_api",
                "guardduty_api",
                "securityhub_api",
                "inspector_api",
                "macie_api",
                "waf_api",
                "shield_api",
                "acm_api",
                "networkfirewall_api",
                "ecr_api",
                "efs_api",
                "detective_api",
                "accessanalyzer_api",
                "fargate_api",
                "batch_api",
                "elasticache_api",
                "memorydb_api",
                "emr_api",
                "firehose_api",
                "msk_api",
                "appsync_api",
                "amazon_mq_api",
                "neptune_api",
                "documentdb_api",
                "fsx_api",
                "kendra_api",
                "personalize_api",
                "forecast_api",
                "mediaconvert_api",
                "transfer_api",
                "datasync_api",
                "backup_api",
                "lightsail_api",
                "elasticbeanstalk_api",
                "workspaces_api",
                "appstream_api",
                "mediastore_api",
                "outposts_api",
                "storagegateway_api",
                "directconnect_api",
                "transitgateway_api",
                "ec2_api",
                "autoscaling_api",
                "organizations_api",
                "ram_api",
                "codebuild_api",
                "codepipeline_api",
                "codedeploy_api",
                "codecommit_api",
                "cloud9_api",
                "amplify_api",
                "fis_api",
                "resiliencehub_api",
                "wellarchitected_api",
                "support_api",
                "trustedadvisor_api",
                "controltower_api",
                "servicecatalog_api",
                "lakeformation_api",
                "ses_api",
                "pinpoint_api",
                "connect_api",
                "chime_api",
                "ivs_api",
                "gamelift_api",
                "braket_api",
                "qldb_api",
                "timestream_api",
                "appconfig_api",
                "grafana_api",
                "prometheus_api",
                "location_api",
                "emrserverless_api",
                "iot_api",
                "greengrass_api",
                "iotanalytics_api",
                "freertos_api",
                "datazone_api",
                "cleanrooms_api",
                "entityresolution_api",
                "supplychain_api",
                "amp_api",
                "managedgrafana_api",
                "opensearchserverless_api",
                "mwaa_api",
                "appflow_api",
                "databrew_api",
                "healthlake_api",
                "medicalimaging_api",
                "omics_api",
                "finspace_api",
                "lookoutmetrics_api",
                "lookoutvision_api",
                "evidently_api",
                "rum_api",
                "pipedrive_api",
                "shopify_api",
                "salesforce_api",
                "servicenow_api",
            }:
                base_url = resolve_orchestration_template(
                    str(config.get("base_url") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                if base_url and "://" not in base_url:
                    base_url = f"https://{base_url}"
                default_paths = {
                    "zendesk_api": "/api/v2/tickets.json",
                    "freshdesk_api": "/api/v2/tickets",
                    "freshservice_api": "/api/v2/tickets",
                    "okta_api": "/api/v1/users",
                    "auth0_api": "/api/v2/users",
                    "azure_devops_api": "/_apis/projects",
                    "snowflake_api": "/api/v2/statements",
                    "databricks_api": "/api/2.0/clusters/list",
                    "bigquery_api": "/bigquery/v2/projects",
                    "splunk_api": "/services/search/jobs",
                    "elasticsearch_api": "/_search",
                    "redis_api": "/",
                    "mongodb_api": "/action/find",
                    "postgres_api": "/",
                    "mysql_api": "/",
                    "s3_api": "/",
                    "pinecone_api": "/query",
                    "weaviate_api": "/v1/objects",
                    "qdrant_api": "/collections",
                    "supabase_api": "/rest/v1/",
                    "kafka_api": "/topics",
                    "milvus_api": "/v1/vector/search",
                    "chroma_api": "/api/v1/collections",
                    "neo4j_api": "/db/neo4j/tx/commit",
                    "rabbitmq_api": "/api/queues",
                    "opensearch_api": "/_search",
                    "clickhouse_api": "/",
                    "dynamodb_api": "/",
                    "nats_api": "/varz",
                    "cassandra_api": "/v2/keyspaces",
                    "couchbase_api": "/pools/default",
                    "influxdb_api": "/api/v2/query",
                    "firebase_api": "/v1/projects",
                    "airbyte_api": "/api/v1/workspaces",
                    "presto_api": "/v1/statement",
                    "trino_api": "/v1/statement",
                    "redshift_api": "/",
                    "athena_api": "/",
                    "pulsar_api": "/admin/v2/clusters",
                    "scylladb_api": "/",
                    "sqs_api": "/",
                    "sns_api": "/",
                    "kinesis_api": "/",
                    "eventbridge_api": "/",
                    "lambda_api": "/2015-03-31/functions",
                    "stepfunctions_api": "/",
                    "cloudwatch_api": "/",
                    "xray_api": "/",
                    "glue_api": "/",
                    "sagemaker_api": "/",
                    "bedrock_api": "/model",
                    "comprehend_api": "/",
                    "textract_api": "/",
                    "rekognition_api": "/",
                    "translate_api": "/",
                    "polly_api": "/",
                    "transcribe_api": "/",
                    "lex_api": "/",
                    "ecs_api": "/",
                    "eks_api": "/clusters",
                    "secretsmanager_api": "/",
                    "ssm_api": "/",
                    "cognito_api": "/",
                    "iam_api": "/",
                    "kms_api": "/",
                    "sts_api": "/",
                    "apigateway_api": "/restapis",
                    "cloudformation_api": "/",
                    "rds_api": "/",
                    "elb_api": "/",
                    "cloudfront_api": "/2020-05-31/distribution",
                    "route53_api": "/2013-04-01/hostedzone",
                    "cloudtrail_api": "/",
                    "config_api": "/",
                    "guardduty_api": "/detector",
                    "securityhub_api": "/findings",
                    "inspector_api": "/findings/list",
                    "macie_api": "/findings",
                    "waf_api": "/webacl",
                    "shield_api": "/protections",
                    "acm_api": "/",
                    "networkfirewall_api": "/",
                    "ecr_api": "/",
                    "efs_api": "/",
                    "detective_api": "/graph",
                    "accessanalyzer_api": "/analyzer",
                    "fargate_api": "/tasks",
                    "batch_api": "/v1/jobs",
                    "elasticache_api": "/",
                    "memorydb_api": "/",
                    "emr_api": "/",
                    "firehose_api": "/",
                    "msk_api": "/",
                    "appsync_api": "/graphql",
                    "amazon_mq_api": "/",
                    "neptune_api": "/",
                    "documentdb_api": "/",
                    "fsx_api": "/",
                    "kendra_api": "/",
                    "personalize_api": "/",
                    "forecast_api": "/",
                    "mediaconvert_api": "/2017-08-29/jobs",
                    "transfer_api": "/",
                    "datasync_api": "/",
                    "backup_api": "/",
                    "lightsail_api": "/",
                    "elasticbeanstalk_api": "/",
                    "workspaces_api": "/",
                    "appstream_api": "/",
                    "mediastore_api": "/",
                    "outposts_api": "/",
                    "storagegateway_api": "/",
                    "directconnect_api": "/",
                    "transitgateway_api": "/",
                    "ec2_api": "/",
                    "autoscaling_api": "/",
                    "organizations_api": "/",
                    "ram_api": "/",
                    "codebuild_api": "/",
                    "codepipeline_api": "/",
                    "codedeploy_api": "/",
                    "codecommit_api": "/",
                    "cloud9_api": "/",
                    "amplify_api": "/",
                    "fis_api": "/",
                    "resiliencehub_api": "/",
                    "wellarchitected_api": "/",
                    "support_api": "/",
                    "trustedadvisor_api": "/",
                    "controltower_api": "/",
                    "servicecatalog_api": "/",
                    "lakeformation_api": "/",
                    "ses_api": "/",
                    "pinpoint_api": "/",
                    "connect_api": "/",
                    "chime_api": "/",
                    "ivs_api": "/",
                    "gamelift_api": "/",
                    "braket_api": "/",
                    "qldb_api": "/",
                    "timestream_api": "/",
                    "appconfig_api": "/",
                    "grafana_api": "/",
                    "prometheus_api": "/",
                    "location_api": "/",
                    "emrserverless_api": "/",
                    "iot_api": "/",
                    "greengrass_api": "/",
                    "iotanalytics_api": "/",
                    "freertos_api": "/",
                    "datazone_api": "/",
                    "cleanrooms_api": "/",
                    "entityresolution_api": "/",
                    "supplychain_api": "/",
                    "amp_api": "/",
                    "managedgrafana_api": "/",
                    "opensearchserverless_api": "/",
                    "mwaa_api": "/",
                    "appflow_api": "/",
                    "databrew_api": "/",
                    "healthlake_api": "/",
                    "medicalimaging_api": "/",
                    "omics_api": "/",
                    "finspace_api": "/",
                    "lookoutmetrics_api": "/",
                    "lookoutvision_api": "/",
                    "evidently_api": "/",
                    "rum_api": "/",
                    "pipedrive_api": "/api/v1/users/me",
                    "shopify_api": "/admin/api/2024-01/shop.json",
                    "salesforce_api": "/services/data/v59.0/sobjects",
                    "servicenow_api": "/api/now/table/incident",
                    "jira_api": "/",
                    "confluence_api": "/wiki/rest/api/content",
                }
                default_path = default_paths.get(node_type, "/")
                path = resolve_orchestration_template(
                    str(config.get("path_template") or default_path),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                query = resolve_orchestration_template(
                    str(config.get("query_template") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                url = build_preset_api_url(base_url=base_url, path_template=path, query_template=query)
                method = str(config.get("method") or "GET").strip().upper()
                default_auth = (
                    "bearer"
                    if node_type
                    in {
                        "salesforce_api",
                        "pipedrive_api",
                        "shopify_api",
                        "okta_api",
                        "auth0_api",
                        "snowflake_api",
                        "databricks_api",
                        "bigquery_api",
                        "splunk_api",
                        "elasticsearch_api",
                        "redis_api",
                        "mongodb_api",
                        "postgres_api",
                        "mysql_api",
                        "s3_api",
                        "pinecone_api",
                        "weaviate_api",
                        "qdrant_api",
                        "supabase_api",
                        "kafka_api",
                        "milvus_api",
                        "chroma_api",
                        "neo4j_api",
                        "opensearch_api",
                        "clickhouse_api",
                        "dynamodb_api",
                        "nats_api",
                        "cassandra_api",
                        "couchbase_api",
                        "influxdb_api",
                        "firebase_api",
                        "airbyte_api",
                        "presto_api",
                        "trino_api",
                        "redshift_api",
                        "athena_api",
                        "pulsar_api",
                        "scylladb_api",
                        "sqs_api",
                        "sns_api",
                        "kinesis_api",
                        "eventbridge_api",
                        "lambda_api",
                        "stepfunctions_api",
                        "cloudwatch_api",
                        "xray_api",
                        "glue_api",
                        "sagemaker_api",
                        "bedrock_api",
                        "comprehend_api",
                        "textract_api",
                        "rekognition_api",
                        "translate_api",
                        "polly_api",
                        "transcribe_api",
                        "lex_api",
                        "ecs_api",
                        "eks_api",
                        "secretsmanager_api",
                        "ssm_api",
                        "cognito_api",
                        "iam_api",
                        "kms_api",
                        "sts_api",
                        "apigateway_api",
                        "cloudformation_api",
                        "rds_api",
                        "elb_api",
                        "cloudfront_api",
                        "route53_api",
                        "cloudtrail_api",
                        "config_api",
                        "guardduty_api",
                        "securityhub_api",
                        "inspector_api",
                        "macie_api",
                        "waf_api",
                        "shield_api",
                        "acm_api",
                        "networkfirewall_api",
                        "ecr_api",
                        "efs_api",
                        "detective_api",
                        "accessanalyzer_api",
                        "fargate_api",
                        "batch_api",
                        "elasticache_api",
                        "memorydb_api",
                        "emr_api",
                        "firehose_api",
                        "msk_api",
                        "appsync_api",
                        "amazon_mq_api",
                        "neptune_api",
                        "documentdb_api",
                        "fsx_api",
                        "kendra_api",
                        "personalize_api",
                        "forecast_api",
                        "mediaconvert_api",
                        "transfer_api",
                        "datasync_api",
                        "backup_api",
                        "lightsail_api",
                        "elasticbeanstalk_api",
                        "workspaces_api",
                        "appstream_api",
                        "mediastore_api",
                        "outposts_api",
                        "storagegateway_api",
                        "directconnect_api",
                        "transitgateway_api",
                        "ec2_api",
                        "autoscaling_api",
                        "organizations_api",
                        "ram_api",
                        "codebuild_api",
                        "codepipeline_api",
                        "codedeploy_api",
                        "codecommit_api",
                        "cloud9_api",
                        "amplify_api",
                        "fis_api",
                        "resiliencehub_api",
                        "wellarchitected_api",
                        "support_api",
                        "trustedadvisor_api",
                        "controltower_api",
                        "servicecatalog_api",
                        "lakeformation_api",
                        "ses_api",
                        "pinpoint_api",
                        "connect_api",
                        "chime_api",
                        "ivs_api",
                        "gamelift_api",
                        "braket_api",
                        "qldb_api",
                        "timestream_api",
                        "appconfig_api",
                        "grafana_api",
                        "prometheus_api",
                        "location_api",
                        "emrserverless_api",
                        "iot_api",
                        "greengrass_api",
                        "iotanalytics_api",
                        "freertos_api",
                        "datazone_api",
                        "cleanrooms_api",
                        "entityresolution_api",
                        "supplychain_api",
                        "amp_api",
                        "managedgrafana_api",
                        "opensearchserverless_api",
                        "mwaa_api",
                        "appflow_api",
                        "databrew_api",
                        "healthlake_api",
                        "medicalimaging_api",
                        "omics_api",
                        "finspace_api",
                        "lookoutmetrics_api",
                        "lookoutvision_api",
                        "evidently_api",
                        "rum_api",
                    }
                    else "basic"
                )
                auth_type = str(config.get("auth_type") or default_auth).strip().lower() or default_auth
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                provider_map = {
                    "zendesk_api": "zendesk",
                    "freshdesk_api": "freshdesk",
                    "freshservice_api": "freshservice",
                    "okta_api": "okta",
                    "auth0_api": "auth0",
                    "azure_devops_api": "azure_devops",
                    "snowflake_api": "snowflake",
                    "databricks_api": "databricks",
                    "bigquery_api": "bigquery",
                    "splunk_api": "splunk",
                    "elasticsearch_api": "elasticsearch",
                    "redis_api": "redis",
                    "mongodb_api": "mongodb",
                    "postgres_api": "postgres",
                    "mysql_api": "mysql",
                    "s3_api": "s3",
                    "pinecone_api": "pinecone",
                    "weaviate_api": "weaviate",
                    "qdrant_api": "qdrant",
                    "supabase_api": "supabase",
                    "kafka_api": "kafka",
                    "milvus_api": "milvus",
                    "chroma_api": "chroma",
                    "neo4j_api": "neo4j",
                    "rabbitmq_api": "rabbitmq",
                    "opensearch_api": "opensearch",
                    "clickhouse_api": "clickhouse",
                    "dynamodb_api": "dynamodb",
                    "nats_api": "nats",
                    "cassandra_api": "cassandra",
                    "couchbase_api": "couchbase",
                    "influxdb_api": "influxdb",
                    "firebase_api": "firebase",
                    "airbyte_api": "airbyte",
                    "presto_api": "presto",
                    "trino_api": "trino",
                    "redshift_api": "redshift",
                    "athena_api": "athena",
                    "pulsar_api": "pulsar",
                    "scylladb_api": "scylladb",
                    "sqs_api": "sqs",
                    "sns_api": "sns",
                    "kinesis_api": "kinesis",
                    "eventbridge_api": "eventbridge",
                    "lambda_api": "lambda",
                    "stepfunctions_api": "stepfunctions",
                    "cloudwatch_api": "cloudwatch",
                    "xray_api": "xray",
                    "glue_api": "glue",
                    "sagemaker_api": "sagemaker",
                    "bedrock_api": "bedrock",
                    "comprehend_api": "comprehend",
                    "textract_api": "textract",
                    "rekognition_api": "rekognition",
                    "translate_api": "translate",
                    "polly_api": "polly",
                    "transcribe_api": "transcribe",
                    "lex_api": "lex",
                    "ecs_api": "ecs",
                    "eks_api": "eks",
                    "secretsmanager_api": "secretsmanager",
                    "ssm_api": "ssm",
                    "cognito_api": "cognito",
                    "iam_api": "iam",
                    "kms_api": "kms",
                    "sts_api": "sts",
                    "apigateway_api": "apigateway",
                    "cloudformation_api": "cloudformation",
                    "rds_api": "rds",
                    "elb_api": "elb",
                    "cloudfront_api": "cloudfront",
                    "route53_api": "route53",
                    "cloudtrail_api": "cloudtrail",
                    "config_api": "config",
                    "guardduty_api": "guardduty",
                    "securityhub_api": "securityhub",
                    "inspector_api": "inspector",
                    "macie_api": "macie",
                    "waf_api": "waf",
                    "shield_api": "shield",
                    "acm_api": "acm",
                    "networkfirewall_api": "networkfirewall",
                    "ecr_api": "ecr",
                    "efs_api": "efs",
                    "detective_api": "detective",
                    "accessanalyzer_api": "accessanalyzer",
                    "fargate_api": "fargate",
                    "batch_api": "batch",
                    "elasticache_api": "elasticache",
                    "memorydb_api": "memorydb",
                    "emr_api": "emr",
                    "firehose_api": "firehose",
                    "msk_api": "msk",
                    "appsync_api": "appsync",
                    "amazon_mq_api": "amazon_mq",
                    "neptune_api": "neptune",
                    "documentdb_api": "documentdb",
                    "fsx_api": "fsx",
                    "kendra_api": "kendra",
                    "personalize_api": "personalize",
                    "forecast_api": "forecast",
                    "mediaconvert_api": "mediaconvert",
                    "transfer_api": "transfer",
                    "datasync_api": "datasync",
                    "backup_api": "backup",
                    "lightsail_api": "lightsail",
                    "elasticbeanstalk_api": "elasticbeanstalk",
                    "workspaces_api": "workspaces",
                    "appstream_api": "appstream",
                    "mediastore_api": "mediastore",
                    "outposts_api": "outposts",
                    "storagegateway_api": "storagegateway",
                    "directconnect_api": "directconnect",
                    "transitgateway_api": "transitgateway",
                    "ec2_api": "ec2",
                    "autoscaling_api": "autoscaling",
                    "organizations_api": "organizations",
                    "ram_api": "ram",
                    "codebuild_api": "codebuild",
                    "codepipeline_api": "codepipeline",
                    "codedeploy_api": "codedeploy",
                    "codecommit_api": "codecommit",
                    "cloud9_api": "cloud9",
                    "amplify_api": "amplify",
                    "fis_api": "fis",
                    "resiliencehub_api": "resiliencehub",
                    "wellarchitected_api": "wellarchitected",
                    "support_api": "support",
                    "trustedadvisor_api": "trustedadvisor",
                    "controltower_api": "controltower",
                    "servicecatalog_api": "servicecatalog",
                    "lakeformation_api": "lakeformation",
                    "ses_api": "ses",
                    "pinpoint_api": "pinpoint",
                    "connect_api": "connect",
                    "chime_api": "chime",
                    "ivs_api": "ivs",
                    "gamelift_api": "gamelift",
                    "braket_api": "braket",
                    "qldb_api": "qldb",
                    "timestream_api": "timestream",
                    "appconfig_api": "appconfig",
                    "grafana_api": "grafana",
                    "prometheus_api": "prometheus",
                    "location_api": "location",
                    "emrserverless_api": "emrserverless",
                    "iot_api": "iot",
                    "greengrass_api": "greengrass",
                    "iotanalytics_api": "iotanalytics",
                    "freertos_api": "freertos",
                    "datazone_api": "datazone",
                    "cleanrooms_api": "cleanrooms",
                    "entityresolution_api": "entityresolution",
                    "supplychain_api": "supplychain",
                    "amp_api": "amp",
                    "managedgrafana_api": "managedgrafana",
                    "opensearchserverless_api": "opensearchserverless",
                    "mwaa_api": "mwaa",
                    "appflow_api": "appflow",
                    "databrew_api": "databrew",
                    "healthlake_api": "healthlake",
                    "medicalimaging_api": "medicalimaging",
                    "omics_api": "omics",
                    "finspace_api": "finspace",
                    "lookoutmetrics_api": "lookoutmetrics",
                    "lookoutvision_api": "lookoutvision",
                    "evidently_api": "evidently",
                    "rum_api": "rum",
                    "pipedrive_api": "pipedrive",
                    "shopify_api": "shopify",
                    "salesforce_api": "salesforce",
                    "servicenow_api": "servicenow",
                    "jira_api": "jira",
                    "confluence_api": "confluence",
                }
                provider = provider_map.get(node_type, node_type)
            else:
                url = resolve_orchestration_template(
                    str(config.get("url") or ""),
                    step_outputs=step_outputs,
                    run_input=run_input,
                )
                method = str(config.get("method") or "GET").strip().upper()
                auth_type = str(config.get("auth_type") or "none").strip().lower()
                headers_raw = config.get("headers_json") or "{}"
                headers = json.loads(headers_raw) if isinstance(headers_raw, str) else headers_raw
                if not isinstance(headers, dict):
                    headers = {}
                headers = {
                    key: resolve_orchestration_template(str(val), step_outputs=step_outputs, run_input=run_input)
                    if isinstance(val, str)
                    else val
                    for key, val in headers.items()
                }
                provider = None

            host_error = _validate_http_url(db, url)
            if host_error:
                raise HTTPException(status_code=403, detail=host_error)
            auth_binding_id = str(config.get("auth_binding_id") or "").strip() or None
            auth_header_name = config.get("auth_header_name")
            auth_headers = apply_http_auth_headers(
                db,
                auth_type=auth_type,
                auth_binding_id=auth_binding_id,
                auth_header_name=str(auth_header_name) if auth_header_name is not None else None,
            )
            headers = {**headers, **auth_headers}
            body_raw = config.get("body_template")
            body = (
                resolve_orchestration_template(str(body_raw), step_outputs=step_outputs, run_input=run_input)
                if body_raw
                else None
            )
            request_kwargs: dict[str, Any] = {"method": method, "url": url, "headers": headers, "timeout": 30.0}
            if body and method in {"POST", "PUT", "PATCH"}:
                request_kwargs["content"] = body
            response = httpx.request(**request_kwargs)
            body_text = response.text
            parsed_data: Any = {"raw": body_text[:2048]}
            try:
                candidate = response.json()
                if isinstance(candidate, (dict, list)):
                    parsed_data = candidate
            except Exception:
                pass
            output = {
                "live": True,
                "simulated": False,
                "url": url,
                "method": method,
                "status_code": response.status_code,
                "status": response.status_code,
                "body_preview": body_text[:2048],
                "data": parsed_data,
                "auth_type": auth_type if auth_type not in {"", "none"} else None,
            }
            if provider:
                output["provider"] = provider
        elif node_type == "email_send":
            channel_id = str(config.get("channel_id") or "").strip()
            to = resolve_orchestration_template(
                str(config.get("to_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            subject = resolve_orchestration_template(
                str(config.get("subject_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            body = resolve_orchestration_template(
                str(config.get("body_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            for field_name, value in (
                ("to_template", to),
                ("subject_template", subject),
                ("body_template", body),
            ):
                template_error = validate_recipient_template(value, field_name=field_name)
                if template_error:
                    raise HTTPException(status_code=422, detail=template_error)
            from_override = str(config.get("from_override") or "").strip() or None
            delivery = deliver_email(
                db,
                channel_id=channel_id,
                to=to,
                subject=subject,
                body=body,
                from_override=from_override,
            )
            output = {
                **delivery,
                "to": to,
                "subject": subject,
                "body_preview": body[:512],
                "from_override": from_override,
            }
        elif node_type == "sms_send":
            channel_id = str(config.get("channel_id") or "").strip()
            to = resolve_orchestration_template(
                str(config.get("to_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            body = resolve_orchestration_template(
                str(config.get("body_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            for field_name, value in (("to_template", to), ("body_template", body)):
                template_error = validate_recipient_template(value, field_name=field_name)
                if template_error:
                    raise HTTPException(status_code=422, detail=template_error)
            from_override = str(config.get("from_override") or "").strip() or None
            delivery = deliver_sms(
                db,
                channel_id=channel_id,
                to=to,
                body=body,
                from_override=from_override,
            )
            output = {
                **delivery,
                "to": to,
                "body_preview": body[:512],
                "from_override": from_override,
            }
        elif node_type == "human_approval":
            gate_id = str(uuid4())
            resolved_approver_id, resolved_approver_role = _resolve_human_approver(config, step_outputs)
            gate_row = OrchestrationRunApprovalGate(
                gate_id=gate_id,
                run_id=run_id,
                flow_id=flow_id,
                node_id=node_id,
                status="pending",
                approval_title=str(config.get("approval_title") or "Approval required"),
                required_role=str(config.get("required_role") or "").strip() or None,
                resolved_approver_id=resolved_approver_id,
                resolved_approver_role=resolved_approver_role,
                metadata_json=json.dumps(
                    {
                        "instructions": config.get("instructions"),
                        "approver_source": config.get("approver_source") or "static",
                        "source_node_id": config.get("source_node_id"),
                    },
                    separators=(",", ":"),
                ),
            )
            db.add(gate_row)
            db.flush()
            output = {
                "live": True,
                "simulated": False,
                "approval_gate_id": gate_id,
                "approval_title": config.get("approval_title"),
                "status": "pending",
                "resolved_approver_id": resolved_approver_id,
                "resolved_approver_role": resolved_approver_role,
            }
            return {
                "node_id": node_id,
                "node_type": node_type,
                "status": "awaiting_approval",
                "trace_id": trace_id,
                "output": output,
                "gate_id": gate_id,
            }
        elif node_type == "set_fields":
            # Align with static_data: shared template resolver + JSON parse of resolved strings.
            fields_raw = config.get("fields_json") or "{}"
            fields = json.loads(fields_raw) if isinstance(fields_raw, str) else fields_raw
            if not isinstance(fields, dict):
                raise HTTPException(status_code=422, detail="fields_json must be a JSON object")
            resolved: dict[str, Any] = {}
            for key, value in fields.items():
                field_key = str(key or "").strip()
                if not field_key:
                    continue
                if isinstance(value, str):
                    text = resolve_orchestration_template(
                        value, step_outputs=step_outputs, run_input=run_input
                    )
                    try:
                        resolved[field_key] = json.loads(text)
                    except json.JSONDecodeError:
                        resolved[field_key] = text
                else:
                    resolved[field_key] = value
            output = {"live": True, "simulated": False, "fields": resolved, **resolved}
        elif node_type == "json_transform":
            source_node_id = str(config.get("source_node_id") or "").strip()
            source = step_outputs.get(source_node_id) if source_node_id else {}
            if not isinstance(source, dict):
                source = {"value": source}
            mapping_raw = config.get("mapping_json") or "{}"
            mapping = json.loads(mapping_raw) if isinstance(mapping_raw, str) else mapping_raw
            if not isinstance(mapping, dict):
                raise HTTPException(status_code=422, detail="mapping_json must be a JSON object")
            transformed: dict[str, Any] = {}
            for key, template in mapping.items():
                field_key = str(key or "").strip()
                if not field_key:
                    continue
                transformed[field_key] = resolve_orchestration_template(
                    str(template),
                    step_outputs={**step_outputs, "_source": source, source_node_id: source},
                    run_input=run_input,
                )
            output = {
                "live": True,
                "simulated": False,
                "source_node_id": source_node_id or None,
                "transformed": transformed,
                **transformed,
            }
        elif node_type == "slack_webhook":
            webhook_url = resolve_orchestration_template(
                str(config.get("webhook_url") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            host_error = _validate_http_url(db, webhook_url)
            if host_error:
                raise HTTPException(status_code=403, detail=host_error)
            text = resolve_orchestration_template(
                str(config.get("text_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            payload_body: dict[str, Any] = {"text": text}
            blocks_raw = config.get("blocks_json")
            if blocks_raw:
                blocks_text = resolve_orchestration_template(
                    str(blocks_raw), step_outputs=step_outputs, run_input=run_input
                )
                try:
                    blocks = json.loads(blocks_text)
                    if isinstance(blocks, list):
                        payload_body["blocks"] = blocks
                except json.JSONDecodeError as exc:
                    raise HTTPException(status_code=422, detail="blocks_json must be valid JSON") from exc
            response = httpx.post(webhook_url, json=payload_body, timeout=30.0)
            output = {
                "live": True,
                "simulated": False,
                "webhook_url": webhook_url,
                "text": text,
                "status_code": response.status_code,
                "delivery_status": "sent" if response.status_code < 300 else "failed",
                "body_preview": (response.text or "")[:512],
            }
            if response.status_code >= 300:
                raise HTTPException(
                    status_code=422,
                    detail=f"Slack webhook returned HTTP {response.status_code}",
                )
        elif node_type == "discord_webhook":
            webhook_url = resolve_orchestration_template(
                str(config.get("webhook_url") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            host_error = _validate_http_url(db, webhook_url)
            if host_error:
                raise HTTPException(status_code=403, detail=host_error)
            content = resolve_orchestration_template(
                str(config.get("content_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            payload_body = {"content": content}
            embeds_raw = config.get("embeds_json")
            if embeds_raw:
                embeds_text = resolve_orchestration_template(
                    str(embeds_raw), step_outputs=step_outputs, run_input=run_input
                )
                try:
                    embeds = json.loads(embeds_text)
                    if isinstance(embeds, list):
                        payload_body["embeds"] = embeds
                except json.JSONDecodeError as exc:
                    raise HTTPException(status_code=422, detail="embeds_json must be valid JSON") from exc
            response = httpx.post(webhook_url, json=payload_body, timeout=30.0)
            output = {
                "live": True,
                "simulated": False,
                "webhook_url": webhook_url,
                "content": content,
                "status_code": response.status_code,
                "delivery_status": "sent" if response.status_code < 300 else "failed",
                "body_preview": (response.text or "")[:512],
            }
            if response.status_code >= 300:
                raise HTTPException(
                    status_code=422,
                    detail=f"Discord webhook returned HTTP {response.status_code}",
                )
        elif node_type == "teams_webhook":
            webhook_url = resolve_orchestration_template(
                str(config.get("webhook_url") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            host_error = _validate_http_url(db, webhook_url)
            if host_error:
                raise HTTPException(status_code=403, detail=host_error)
            text = resolve_orchestration_template(
                str(config.get("text_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            title = resolve_orchestration_template(
                str(config.get("title_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            payload_body: dict[str, Any] = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "text": text,
            }
            if title:
                payload_body["summary"] = title
                payload_body["title"] = title
            response = httpx.post(webhook_url, json=payload_body, timeout=30.0)
            output = {
                "live": True,
                "simulated": False,
                "webhook_url": webhook_url,
                "text": text,
                "title": title or None,
                "status_code": response.status_code,
                "delivery_status": "sent" if response.status_code < 300 else "failed",
                "body_preview": (response.text or "")[:512],
            }
            if response.status_code >= 300:
                raise HTTPException(
                    status_code=422,
                    detail=f"Teams webhook returned HTTP {response.status_code}",
                )
        elif node_type == "mattermost_webhook":
            webhook_url = resolve_orchestration_template(
                str(config.get("webhook_url") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            host_error = _validate_http_url(db, webhook_url)
            if host_error:
                raise HTTPException(status_code=403, detail=host_error)
            text = resolve_orchestration_template(
                str(config.get("text_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            username = resolve_orchestration_template(
                str(config.get("username_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            channel = resolve_orchestration_template(
                str(config.get("channel_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            payload_body: dict[str, Any] = {"text": text}
            if username:
                payload_body["username"] = username[:64]
            if channel:
                payload_body["channel"] = channel[:64]
            response = httpx.post(webhook_url, json=payload_body, timeout=30.0)
            output = {
                "live": True,
                "simulated": False,
                "provider": "mattermost",
                "webhook_url": webhook_url,
                "text": text,
                "status_code": response.status_code,
                "delivery_status": "sent" if response.status_code < 300 else "failed",
                "body_preview": (response.text or "")[:512],
            }
            if response.status_code >= 300:
                raise HTTPException(
                    status_code=422,
                    detail=f"Mattermost webhook returned HTTP {response.status_code}",
                )
        elif node_type == "google_chat_webhook":
            webhook_url = resolve_orchestration_template(
                str(config.get("webhook_url") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            host_error = _validate_http_url(db, webhook_url)
            if host_error:
                raise HTTPException(status_code=403, detail=host_error)
            text = resolve_orchestration_template(
                str(config.get("text_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            thread_key = resolve_orchestration_template(
                str(config.get("thread_key_template") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            ).strip()
            payload_body: dict[str, Any] = {"text": text}
            post_url = webhook_url
            if thread_key:
                separator = "&" if "?" in webhook_url else "?"
                post_url = f"{webhook_url}{separator}threadKey={thread_key[:128]}"
            response = httpx.post(post_url, json=payload_body, timeout=30.0)
            output = {
                "live": True,
                "simulated": False,
                "provider": "google_chat",
                "webhook_url": webhook_url,
                "text": text,
                "thread_key": thread_key or None,
                "status_code": response.status_code,
                "delivery_status": "sent" if response.status_code < 300 else "failed",
                "body_preview": (response.text or "")[:512],
            }
            if response.status_code >= 300:
                raise HTTPException(
                    status_code=422,
                    detail=f"Google Chat webhook returned HTTP {response.status_code}",
                )
        elif node_type in {"parallel_fork", "parallel_join"}:
            # Control-plane nodes: branch bodies already execute live; emit live metadata (closes RSK-018).
            output = {
                "live": True,
                "simulated": False,
                "group_id": str(config.get("group_id") or "").strip() or None,
                "fork_node_id": str(config.get("fork_node_id") or "").strip() or None,
                "branch_count": config.get("branch_count"),
                "control_node": node_type,
            }
        elif node_type in {"schedule_trigger", "webhook_trigger"}:
            # Trigger nodes are ingress markers; runtime trigger is handled by orchestration_triggers.
            output = {
                "live": True,
                "simulated": False,
                "trigger_type": "schedule" if node_type == "schedule_trigger" else "webhook",
                "trigger_config": {
                    key: config.get(key)
                    for key in (
                        "cron_expression",
                        "webhook_path_ref",
                        "path_ref",
                        "token_binding_id",
                    )
                    if config.get(key) not in (None, "")
                },
            }
        else:
            raise HTTPException(
                status_code=422,
                detail=f"Live executor does not support node type '{node_type}' — remove or replace this step",
            )

        return {
            "node_id": node_id,
            "node_type": node_type,
            "status": "completed",
            "trace_id": trace_id,
            "output": output,
        }
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, str) else json.dumps(exc.detail)
        return {
            "node_id": node_id,
            "node_type": node_type,
            "status": "failed",
            "trace_id": trace_id,
            "output": {"live": True, "error": detail},
        }
    except Exception as exc:
        return {
            "node_id": node_id,
            "node_type": node_type,
            "status": "failed",
            "trace_id": trace_id,
            "output": {"live": True, "error": str(exc)},
        }


def execute_flow(
    db: Session,
    ctx: ActorContext,
    *,
    flow_id: str,
    run_id: str,
    graph_json: str,
    environment: str,
    dry_run: bool,
    trace_id: str,
    run_input: str = "",
    resume_state: Optional[dict[str, Any]] = None,
) -> tuple[str, list[dict[str, Any]], Optional[str], bool, Optional[dict[str, Any]]]:
    if dry_run or not live_executor_enabled(db, environment=environment):
        status, steps, error = execute_flow_stub(
            flow_id=flow_id,
            graph_json=graph_json,
            dry_run=dry_run,
            trace_id=trace_id,
        )
        return status, steps, error, False, None

    resume = resume_state or {}
    step_outputs: dict[str, Any] = dict(resume.get("step_outputs") or {})
    completed_node_ids = {str(node_id) for node_id in (resume.get("completed_node_ids") or []) if str(node_id)}
    initial_step_results = list(resume.get("prior_steps") or [])
    resume_from_node_id = str(resume.get("resume_from_node_id") or "").strip() or None

    def node_executor(node: dict[str, Any], outputs: dict[str, Any]) -> dict[str, Any]:
        config = node.get("config") if isinstance(node.get("config"), dict) else {}
        try:
            max_retries = int(config.get("max_retries") or 0)
        except (TypeError, ValueError):
            max_retries = 0
        max_retries = max(0, min(3, max_retries))
        try:
            retry_delay = float(config.get("retry_delay_seconds") or 0)
        except (TypeError, ValueError):
            retry_delay = 0.0
        retry_delay = max(0.0, min(30.0, retry_delay))

        result: dict[str, Any] = {}
        attempts = 0
        while True:
            attempts += 1
            result = _execute_live_node(
                db,
                ctx,
                node,
                environment=environment,
                trace_id=trace_id,
                step_outputs=outputs,
                run_input=run_input,
                flow_id=flow_id,
                run_id=run_id,
            )
            if result.get("status") != "failed" or attempts > max_retries:
                break
            if retry_delay > 0:
                time.sleep(retry_delay)

        if attempts > 1:
            output = result.get("output") if isinstance(result.get("output"), dict) else {}
            result["output"] = {**output, "attempts": attempts, "max_retries": max_retries}

        node_id = str(result.get("node_id") or "")
        if node_id and result.get("status") != "awaiting_approval":
            outputs[node_id] = result.get("output")
        return result

    status, steps, error = _execute_flow_graph(
        graph_json=graph_json,
        dry_run=False,
        trace_id=trace_id,
        node_executor=node_executor,
        step_outputs=step_outputs,
        fail_on_node_error=True,
        initial_completed=completed_node_ids,
        initial_step_results=initial_step_results,
        resume_from_node_id=resume_from_node_id,
    )

    execution_state: Optional[dict[str, Any]] = None
    if status == "awaiting_approval":
        pending_step = next((step for step in steps if step.get("status") == "awaiting_approval"), None)
        pending_node_id = str(pending_step.get("node_id") or "") if pending_step else ""
        pending_gate_id = str(
            pending_step.get("gate_id") or pending_step.get("output", {}).get("approval_gate_id") or ""
        )
        all_completed = set(completed_node_ids)
        for step in steps:
            step_node_id = str(step.get("node_id") or "")
            if step_node_id and step.get("status") not in {"awaiting_approval"}:
                all_completed.add(step_node_id)
        execution_state = {
            "step_outputs": step_outputs,
            "completed_node_ids": sorted(all_completed),
            "pending_gate_id": pending_gate_id,
            "pending_node_id": pending_node_id,
            "prior_steps": steps,
        }
        return status, steps, error, True, execution_state

    if error:
        status = "failed"
    elif status == "completed":
        status = "completed"
    return status, steps, error, True, execution_state
