from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import OrchestrationFlowDefinition, OrchestrationFlowRun, ProviderCredentialBinding
from app.security import ActorContext
from app.services.audit import create_audit_event
from app.services.credential_resolution import resolve_binding_for_runtime
from app.services.orchestration_executor import execute_flow


def _parse_trigger_config(raw: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _cron_field_matches(field: str, value: int) -> bool:
    token = str(field or "").strip()
    if token == "*":
        return True
    if token.isdigit():
        return int(token) == value
    if token.startswith("*/"):
        try:
            step = int(token[2:])
        except ValueError:
            return False
        return step > 0 and value % step == 0
    if "," in token:
        return any(_cron_field_matches(part, value) for part in token.split(","))
    return False


def cron_matches_now(cron_expression: str, when: Optional[datetime] = None) -> bool:
    when = when or datetime.utcnow()
    parts = str(cron_expression or "").split()
    if len(parts) != 5:
        return False
    minute, hour, day, month, weekday = parts
    cron_weekday = (when.weekday() + 1) % 7
    return (
        _cron_field_matches(minute, when.minute)
        and _cron_field_matches(hour, when.hour)
        and _cron_field_matches(day, when.day)
        and _cron_field_matches(month, when.month)
        and _cron_field_matches(weekday, cron_weekday)
    )


def verify_webhook_token(db: Session, trigger_config: dict[str, Any], authorization: Optional[str]) -> None:
    binding_id = str(trigger_config.get("token_binding_id") or "").strip()
    if not binding_id:
        return
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Webhook bearer token required")
    provided = authorization.split(" ", 1)[1].strip()
    binding = db.query(ProviderCredentialBinding).filter_by(binding_id=binding_id).first()
    if binding is None:
        raise HTTPException(status_code=403, detail="Webhook token binding not found")
    resolved = resolve_binding_for_runtime(db, binding)
    expected = str(getattr(resolved, "api_key", "") or getattr(resolved, "access_token", "") or "").strip()
    if not expected or provided != expected:
        raise HTTPException(status_code=403, detail="Invalid webhook token")


def find_webhook_flow(db: Session, webhook_token: str) -> OrchestrationFlowDefinition:
    token = str(webhook_token or "").strip()
    if not token:
        raise HTTPException(status_code=404, detail="Webhook flow not found")
    rows = (
        db.query(OrchestrationFlowDefinition)
        .filter(OrchestrationFlowDefinition.trigger_type == "webhook")
        .filter(OrchestrationFlowDefinition.status.in_(["active", "draft"]))
        .all()
    )
    for row in rows:
        config = _parse_trigger_config(row.trigger_config_json)
        path_ref = str(config.get("webhook_path_ref") or config.get("path_ref") or "").strip()
        if path_ref == token:
            return row
    raise HTTPException(status_code=404, detail="Webhook flow not found")


def trigger_webhook_flow(
    db: Session,
    ctx: ActorContext,
    *,
    webhook_token: str,
    authorization: Optional[str],
    run_input: str = "",
    dry_run: bool = False,
) -> OrchestrationFlowRun:
    flow = find_webhook_flow(db, webhook_token)
    trigger_config = _parse_trigger_config(flow.trigger_config_json)
    verify_webhook_token(db, trigger_config, authorization)

    trace_id = f"orch-webhook-{uuid4().hex[:16]}"
    run_id = str(uuid4())
    started_at = datetime.utcnow()
    run_status, step_results, error_summary, _live_used, execution_state = execute_flow(
        db,
        ctx,
        flow_id=flow.flow_id,
        run_id=run_id,
        graph_json=flow.graph_json,
        environment=flow.environment,
        dry_run=dry_run,
        trace_id=trace_id,
        run_input=run_input,
    )
    finished_at = None if run_status == "awaiting_approval" else datetime.utcnow()
    run_row = OrchestrationFlowRun(
        run_id=run_id,
        flow_id=flow.flow_id,
        status=run_status,
        started_at=started_at,
        finished_at=finished_at,
        trace_id=trace_id,
        step_results_json=json.dumps(step_results),
        error_summary=error_summary,
        execution_state_json=json.dumps(execution_state) if execution_state else None,
    )
    db.add(run_row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="orchestration.webhook.trigger",
        resource_type="orchestration_flow_run",
        resource_id=run_id,
        trace_id=trace_id,
        action_context={"flow_id": flow.flow_id, "webhook_token": webhook_token},
    )
    db.commit()
    db.refresh(run_row)
    return run_row


def poll_due_scheduled_flows(
    db: Session,
    ctx: ActorContext,
    *,
    dry_run: bool = False,
) -> list[dict[str, Any]]:
    now = datetime.utcnow()
    tick_key = now.strftime("%Y-%m-%dT%H:%M")
    results: list[dict[str, Any]] = []
    rows = (
        db.query(OrchestrationFlowDefinition)
        .filter(OrchestrationFlowDefinition.trigger_type == "schedule")
        .filter(OrchestrationFlowDefinition.status == "active")
        .all()
    )
    for flow in rows:
        config = _parse_trigger_config(flow.trigger_config_json)
        cron = str(config.get("cron_expression") or "").strip()
        if not cron or not cron_matches_now(cron, now):
            continue
        if str(config.get("last_scheduler_tick_at") or "") == tick_key:
            continue

        trace_id = f"orch-schedule-{uuid4().hex[:16]}"
        run_id = str(uuid4())
        started_at = datetime.utcnow()
        run_status, step_results, error_summary, _live_used, execution_state = execute_flow(
            db,
            ctx,
            flow_id=flow.flow_id,
            run_id=run_id,
            graph_json=flow.graph_json,
            environment=flow.environment,
            dry_run=dry_run,
            trace_id=trace_id,
            run_input="",
        )
        finished_at = None if run_status == "awaiting_approval" else datetime.utcnow()
        run_row = OrchestrationFlowRun(
            run_id=run_id,
            flow_id=flow.flow_id,
            status=run_status,
            started_at=started_at,
            finished_at=finished_at,
            trace_id=trace_id,
            step_results_json=json.dumps(step_results),
            error_summary=error_summary,
            execution_state_json=json.dumps(execution_state) if execution_state else None,
        )
        db.add(run_row)
        config["last_scheduler_tick_at"] = tick_key
        flow.trigger_config_json = json.dumps(config)
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="orchestration.scheduler.tick",
            resource_type="orchestration_flow_run",
            resource_id=run_id,
            trace_id=trace_id,
            action_context={"flow_id": flow.flow_id, "cron_expression": cron},
        )
        results.append(
            {
                "flow_id": flow.flow_id,
                "run_id": run_id,
                "status": run_status,
                "error_summary": error_summary,
            }
        )
    db.commit()
    return results
