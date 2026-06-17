from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any, Callable, Optional
from urllib.parse import urlparse
from uuid import uuid4

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import OrchestrationRunApprovalGate, VirtualKey
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
from app.services.orchestration_flows import (
    _execute_flow_graph,
    _execute_single_stub_node,
    _json_path_value,
    _stub_node_output,
    _validate_http_url,
    evaluate_condition,
    execute_flow_stub,
)
from app.services.orchestration_http_auth import apply_http_auth_headers
from app.services.runtime_config import get_runtime_config, get_runtime_config_int

_STEP_OUTPUT_PATTERN = re.compile(
    r"\{\{steps\[['\"]([^'\"]+)['\"]\]\.output(?:\.([a-zA-Z0-9_.\[\]]+))?\}\}"
)


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
) -> str:
    text = str(template or "")

    def _replace(match: re.Match[str]) -> str:
        node_id = match.group(1)
        subpath = match.group(2)
        value = step_outputs.get(node_id)
        if subpath:
            resolved = _json_path_value(value, f"$.{subpath}")
            if resolved is None:
                return ""
            if isinstance(resolved, (dict, list)):
                return json.dumps(resolved, separators=(",", ":"))
            return str(resolved)
        if isinstance(value, (dict, list)):
            return json.dumps(value, separators=(",", ":"))
        return "" if value is None else str(value)

    text = _STEP_OUTPUT_PATTERN.sub(_replace, text)
    return text.replace("{{input}}", run_input)


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
            server = resolve_mcp_server(db, server_id)
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
            output = {"live": True, "simulated": False, "server_id": server_id, "tool_name": tool_name, "result": result}
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
        elif node_type == "condition":
            matched = evaluate_condition(config, step_outputs)
            output = {
                "live": True,
                "simulated": False,
                "expression": config.get("expression"),
                "matched": matched,
            }
        elif node_type == "http_request":
            url = resolve_orchestration_template(
                str(config.get("url") or ""),
                step_outputs=step_outputs,
                run_input=run_input,
            )
            host_error = _validate_http_url(db, url)
            if host_error:
                raise HTTPException(status_code=403, detail=host_error)
            method = str(config.get("method") or "GET").strip().upper()
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
            auth_type = str(config.get("auth_type") or "none").strip().lower()
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
        else:
            output = _stub_node_output(node_type, config, dry_run=False)
            output["live"] = False

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
