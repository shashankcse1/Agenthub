from __future__ import annotations

from typing import Any, Optional
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import PromptRegistryItem, RoutePolicy
from app.services.gateway_inference import ChatCompletionInferenceResult, execute_chat_completion, resolve_inference_credential
from app.services.gateway_response_cache import (
    evaluate_pre_inference_cache,
    finalize_post_inference_cache,
    fingerprint_cache_request,
)
from app.services.prompt_template_render import (
    extract_prompt_template_variables,
    render_prompt_template_variables,
    sanitize_prompt_template_variables,
)


def resolve_prompt_registry_for_chat(
    db: Session,
    *,
    prompt_id: Optional[str] = None,
    prompt_registry_id: Optional[str] = None,
    variables: Optional[dict[str, str]] = None,
) -> tuple[Optional[str], dict[str, Any]]:
    """Portkey-style prompt registry resolve for `/v1/chat/completions`."""
    registry_id = str(prompt_id or prompt_registry_id or "").strip()
    if not registry_id:
        return None, {}

    item = db.query(PromptRegistryItem).filter_by(prompt_registry_id=registry_id).first()
    if item is None:
        raise HTTPException(status_code=404, detail=f"Prompt registry item '{registry_id}' not found")

    sanitized_vars = sanitize_prompt_template_variables(variables)
    rendered = render_prompt_template_variables(
        str(item.prompt_text or ""),
        sanitized_vars,
        require_matched_braces=True,
    )

    return rendered, {
        "prompt_registry_id": registry_id,
        "prompt_registry_name": item.name,
        "variable_count": len(sanitized_vars),
    }


def resolve_llm_chat_prompt(
    db: Session,
    config: dict[str, Any],
    *,
    step_outputs: dict[str, Any],
    run_input: str,
) -> tuple[str, dict[str, Any]]:
    from app.services.orchestration_executor import resolve_orchestration_template

    meta: dict[str, Any] = {}
    prompt_template = str(config.get("prompt_template") or "").strip()
    registry_id = str(config.get("prompt_registry_id") or "").strip()
    registry_text = ""
    if registry_id:
        item = db.query(PromptRegistryItem).filter_by(prompt_registry_id=registry_id).first()
        if item is None:
            raise HTTPException(status_code=404, detail=f"Prompt registry item {registry_id} not found")
        registry_text = str(item.prompt_text or "")
        meta["prompt_registry_id"] = registry_id
        meta["prompt_registry_name"] = item.name

    if registry_text and prompt_template:
        combined = f"{registry_text}\n\n{prompt_template}"
    elif registry_text:
        combined = registry_text
    else:
        combined = prompt_template or "{{input}}"

    # Resolve gateway run input + prior-step output templates first so
    # {{input}} and {{steps['id'].output.field}} map correctly into the prompt.
    resolved = resolve_orchestration_template(combined, step_outputs=step_outputs, run_input=run_input)
    if registry_text:
        var_names = extract_prompt_template_variables(registry_text)
        variables: dict[str, str] = {}
        for name in var_names:
            # Already handled by resolve_orchestration_template — do not blank them out.
            if name in {"input"} or name.startswith("steps"):
                continue
            # Prefer values already present on prior step outputs under the same key.
            if name in step_outputs and not isinstance(step_outputs.get(name), (dict, list)):
                variables[name] = str(step_outputs[name])
                continue
            nested = None
            for output in step_outputs.values():
                if isinstance(output, dict) and name in output and not isinstance(output[name], (dict, list)):
                    nested = output[name]
                    break
            if nested is not None:
                variables[name] = str(nested)
                continue
            variables[name] = resolve_orchestration_template(
                f"{{{{{name}}}}}",
                step_outputs=step_outputs,
                run_input=run_input,
            )
        resolved = render_prompt_template_variables(
            resolved,
            variables,
            require_matched_braces=False,
        )
    return resolved, meta


def resolve_llm_chat_route(
    db: Session,
    route_id: str,
    *,
    model_id: str,
    tenant_id: Optional[str] = None,
) -> tuple[str, Optional[str], dict[str, Any]]:
    from app.routers.gateway import _parse_json_object, _resolve_route_provider_configs

    normalized_route_id = str(route_id or "").strip()
    route = db.query(RoutePolicy).filter_by(route_policy_id=normalized_route_id).first()
    if route is None:
        raise HTTPException(status_code=404, detail="Route policy not found")

    tenant = str(tenant_id or "").strip() or "default"
    fallback = _parse_json_object(route.fallback_policy, "fallback_policy")
    configs = _resolve_route_provider_configs(
        db,
        fallback,
        tenant_id=tenant,
        request_tag=None,
        default_strategy=route.load_balancing_strategy or "weighted",
        resource="orchestration llm_chat",
    )
    if not configs or not configs[0].get("priority_order"):
        raise HTTPException(status_code=422, detail="route policy does not contain provider priority configuration")

    selected = configs[0]["priority_order"][0]
    resolved_model = str(selected.get("model_name") or model_id).strip() or model_id
    provider_id = str(selected.get("provider_id") or "").strip() or None
    meta = {
        "route_id": normalized_route_id,
        "route_policy_id": normalized_route_id,
        "selected_provider_id": provider_id,
    }
    return resolved_model, provider_id, meta


def _resolve_agent_config_defaults(db: Session, config: dict[str, Any]) -> dict[str, Any]:
    """Merge Agent Configuration Studio defaults into an llm_chat step (Portkey-style)."""
    from app.models import AgentConfig

    agent_key = str(config.get("agent_key") or "").strip()
    meta: dict[str, Any] = {}
    if not agent_key:
        return meta
    row = db.query(AgentConfig).filter_by(agent_key=agent_key).first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Agent config '{agent_key}' not found")
    if not bool(row.enabled):
        raise HTTPException(status_code=422, detail=f"Agent config '{agent_key}' is disabled")
    meta["agent_key"] = agent_key
    meta["agent_display_name"] = row.display_name
    # Step-level overrides win; agent config fills gaps.
    if not str(config.get("model_id") or "").strip() and row.model:
        config["model_id"] = row.model
    if config.get("max_tokens") in (None, "") and row.max_tokens is not None:
        config["max_tokens"] = row.max_tokens
    if config.get("temperature") in (None, "") and row.temperature is not None:
        config["temperature"] = row.temperature
    if not str(config.get("binding_id") or "").strip() and row.credential_binding_id:
        config["binding_id"] = row.credential_binding_id
    # Prefer agent_key for credential resolution (AgentConfig lookup path).
    meta["credential_agent_key"] = agent_key
    return meta


def execute_orchestration_llm_chat(
    db: Session,
    *,
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    run_input: str,
    environment: str,
    trace_id: str,
    actor_id: str,
    tenant_id: Optional[str],
    credential_resolver: Any,
) -> dict[str, Any]:
    working = dict(config or {})
    agent_meta = _resolve_agent_config_defaults(db, working)
    prompt, prompt_meta = resolve_llm_chat_prompt(
        db,
        working,
        step_outputs=step_outputs,
        run_input=run_input,
    )
    model_id = str(working.get("model_id") or "gpt-4o-mini").strip()
    route_meta: dict[str, Any] = {}
    route_id = str(working.get("route_id") or "").strip()
    route_policy_id: Optional[str] = None
    if route_id:
        model_id, _provider_id, route_meta = resolve_llm_chat_route(
            db,
            route_id,
            model_id=model_id,
            tenant_id=tenant_id,
        )
        route_policy_id = route_meta.get("route_policy_id")

    cache_mode = str(working.get("cache_mode") or "inherit").strip().lower() or "inherit"
    cache_meta: dict[str, Any] = {"cache_mode": cache_mode, "cache_hit": False, "cache_decision": "inherit"}
    request_id = f"orch-llm-{uuid4().hex[:12]}"
    tenant = str(tenant_id or "").strip() or "default"
    cached_content: Optional[str] = None
    cache_pre = None

    if cache_mode != "bypass":
        fingerprint = fingerprint_cache_request([model_id, prompt, "chat.completions"])
        cache_pre = evaluate_pre_inference_cache(
            db,
            actor_id=actor_id,
            trace_id=trace_id,
            request_id=request_id,
            request_fingerprint=fingerprint,
            request_text=prompt,
            tenant_id=tenant,
            environment=environment,
            route_policy_id=route_policy_id,
            request_tag=None,
            owner_scope=None,
            endpoint_family="chat.completions",
        )
        cache_meta["cache_decision"] = cache_pre.decision
        if cache_pre.cached_response is not None:
            cached_body = cache_pre.cached_response
            if isinstance(cached_body, dict):
                choices = cached_body.get("choices") or []
                if choices and isinstance(choices[0], dict):
                    message = choices[0].get("message") or {}
                    cached_content = str(message.get("content") or "")
            cache_meta["cache_hit"] = True
            cache_meta["cache_provenance"] = cache_pre.provenance

    response_format = None
    fmt = str(working.get("response_format") or "").strip().lower()
    if fmt == "json_object":
        response_format = {"type": "json_object"}
    max_tokens_raw = working.get("max_tokens")
    max_tokens = int(max_tokens_raw) if max_tokens_raw not in (None, "") else None

    if cached_content is not None:
        from app.services.gateway_inference import InferenceUsage

        inference = ChatCompletionInferenceResult(
            content=cached_content,
            finish_reason="stop",
            usage=InferenceUsage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
        )
    else:
        # Explicit Providers binding_id override wins; else agent_key (Agent Config Studio).
        credential_ref = (
            str(working.get("binding_id") or "").strip()
            or str(agent_meta.get("credential_agent_key") or "").strip()
            or None
        )
        credential = resolve_inference_credential(
            db,
            agent_id=credential_ref,
            environment=environment,
            model_name=model_id,
            resolve_gateway_cursor_token=credential_resolver,
        )
        inference = execute_chat_completion(
            db,
            credential=credential,
            model_name=model_id,
            messages=[{"role": "user", "content": prompt}],
            prompt_preview=prompt,
            max_tokens=max_tokens,
            response_format=response_format,
        )
        if cache_pre is not None and cache_pre.should_store_after_inference and cache_mode != "bypass":
            response_body = {
                "choices": [{"message": {"role": "assistant", "content": inference.content}, "finish_reason": inference.finish_reason}],
                "model": model_id,
            }
            finalize_post_inference_cache(
                db,
                pre=cache_pre,
                actor_id=actor_id,
                trace_id=trace_id,
                request_id=request_id,
                tenant_id=tenant,
                environment=environment,
                route_policy_id=route_policy_id,
                response_body=response_body,
                endpoint_family="chat.completions",
                owner_scope=None,
            )

    content = inference.content
    # Expose both gateway-native (`message`/`content`) and OpenAI-style
    # (`choices[0].message.content`) paths so Flow Studio variable maps resolve.
    return {
        "live": True,
        "simulated": False,
        "model_id": model_id,
        "message": content,
        "content": content,
        "finish_reason": inference.finish_reason,
        "choices": [
            {
                "message": {"role": "assistant", "content": content},
                "finish_reason": inference.finish_reason,
            }
        ],
        "usage": {
            "prompt_tokens": inference.usage.prompt_tokens,
            "completion_tokens": inference.usage.completion_tokens,
            "total_tokens": inference.usage.total_tokens,
        },
        **prompt_meta,
        **route_meta,
        **cache_meta,
        **{k: v for k, v in agent_meta.items() if k != "credential_agent_key"},
    }
