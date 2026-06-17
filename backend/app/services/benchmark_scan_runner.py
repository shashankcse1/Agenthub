from __future__ import annotations

import json
import time
from dataclasses import dataclass
from statistics import mean
from typing import Any, Callable, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import Agent, AgentConfig, CostEvent
from app.services.gateway_inference import execute_chat_completion, resolve_inference_credential
from app.services.playground_judge import score_judge_response_with_reason


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    prompt: str
    min_quality: float = 0.55


@dataclass(frozen=True)
class ScanProbe:
    case_id: str
    prompt: str
    min_quality: float = 0.55
    reject_echo: bool = True


BENCHMARK_SUITE_CASES: dict[str, list[BenchmarkCase]] = {
    "reliability-core": [
        BenchmarkCase("fact-capital-russia", "what is capital of russia", min_quality=0.85),
        BenchmarkCase("structured-incident", "draft a p1 response format for incident", min_quality=0.55),
        BenchmarkCase("support-reply", "draft a concise support escalation reply for a billing dispute", min_quality=0.55),
    ],
    "latency-core": [
        BenchmarkCase("fact-capital-france", "what is capital of france", min_quality=0.85),
        BenchmarkCase("uptime-check", "respond in one sentence confirming uptime check ok", min_quality=0.55),
    ],
    "scale-tier3-100k": [
        BenchmarkCase("fact-capital-germany", "what is capital of germany", min_quality=0.85),
        BenchmarkCase("structured-incident", "draft a p1 response format for incident", min_quality=0.70),
        BenchmarkCase("support-reply", "draft a concise support escalation reply for a billing dispute", min_quality=0.70),
        BenchmarkCase("fact-capital-japan", "what is capital of japan", min_quality=0.85),
    ],
}

SECURITY_SCAN_PROBES: list[ScanProbe] = [
    ScanProbe("gateway-factual", "what is capital of russia", min_quality=0.85),
    ScanProbe("gateway-structured", "draft a p1 response format for incident", min_quality=0.55),
]

COMPLIANCE_REQUIRED_CONTROLS = ("CTRL-READINESS-SIGNED", "CTRL-AUDIT-IMMUTABLE")


def _resolve_gateway_cursor_token(db: Session) -> str:
    from app.routers.gateway import _resolve_gateway_cursor_api_token

    return _resolve_gateway_cursor_api_token(db)


def list_test_set_catalog() -> list[dict[str, Any]]:
    safety_cases = len(SECURITY_SCAN_PROBES) + 3
    return [
        {
            "test_set_id": "ts-regression",
            "name": "Regression Core",
            "case_count": len(BENCHMARK_SUITE_CASES["reliability-core"]),
        },
        {
            "test_set_id": "ts-safety",
            "name": "Safety and Policy",
            "case_count": safety_cases,
        },
    ]


def _estimate_tokens_for_prompt(prompt: str) -> tuple[int, int]:
    normalized = str(prompt or "").strip()
    input_tokens = max(24, len(normalized) // 4 + 48)
    output_tokens = 120
    return input_tokens, output_tokens


def _compute_gateway_call_cost_cents(
    db: Session,
    *,
    model_name: str,
    prompt_tokens: int,
    completion_tokens: int,
) -> int:
    from app.routers.gateway import (
        _estimate_hop_cost_cents,
        _load_cloud_component_multipliers,
        _load_model_token_rates,
    )

    model_rates, default_model_rates = _load_model_token_rates(db)
    provider_multipliers, endpoint_multipliers = _load_cloud_component_multipliers(db)
    return _estimate_hop_cost_cents(
        input_tokens=max(0, int(prompt_tokens)),
        output_tokens=max(0, int(completion_tokens)),
        model_name=model_name,
        provider_type="openai",
        endpoint_family="chat.completions",
        model_rates=model_rates,
        default_model_rates=default_model_rates,
        provider_multipliers=provider_multipliers,
        endpoint_multipliers=endpoint_multipliers,
    )


def _estimate_gateway_call_cost_cents(db: Session, *, model_name: str, prompt: str) -> int:
    input_tokens, output_tokens = _estimate_tokens_for_prompt(prompt)
    return _compute_gateway_call_cost_cents(
        db,
        model_name=model_name,
        prompt_tokens=input_tokens,
        completion_tokens=output_tokens,
    )


def estimate_benchmark_cost(
    db: Session,
    *,
    agent_id: str,
    benchmark_suite: str,
    environment: str,
) -> dict[str, Any]:
    suite = str(benchmark_suite or "reliability-core").strip() or "reliability-core"
    cases = BENCHMARK_SUITE_CASES.get(suite, BENCHMARK_SUITE_CASES["reliability-core"])
    normalized_agent = str(agent_id or "").strip()
    normalized_env = str(environment or "dev").strip().lower() or "dev"
    model_name = resolve_agent_model(db, normalized_agent, normalized_env)
    estimated_cost_cents = sum(
        _estimate_gateway_call_cost_cents(db, model_name=model_name, prompt=case.prompt) for case in cases
    )
    return {
        "agent_id": normalized_agent,
        "benchmark_suite": suite,
        "environment": normalized_env,
        "model_name": model_name,
        "gateway_call_count": len(cases),
        "estimated_cost_cents": max(0, int(estimated_cost_cents)),
        "currency": "USD",
    }


def estimate_scan_cost(
    db: Session,
    *,
    agent_id: str,
    scan_type: str,
    environment: str,
) -> dict[str, Any]:
    normalized_agent = str(agent_id or "").strip()
    normalized_env = str(environment or "dev").strip().lower() or "dev"
    normalized_scan_type = str(scan_type or "security").strip().lower() or "security"
    model_name = resolve_agent_model(db, normalized_agent, normalized_env)
    if normalized_scan_type == "compliance":
        gateway_call_count = 0
        estimated_cost_cents = 0
    else:
        gateway_call_count = len(SECURITY_SCAN_PROBES)
        estimated_cost_cents = sum(
            _estimate_gateway_call_cost_cents(db, model_name=model_name, prompt=probe.prompt)
            for probe in SECURITY_SCAN_PROBES
        )
    return {
        "agent_id": normalized_agent,
        "scan_type": normalized_scan_type,
        "environment": normalized_env,
        "model_name": model_name,
        "gateway_call_count": gateway_call_count,
        "estimated_cost_cents": max(0, int(estimated_cost_cents)),
        "currency": "USD",
    }


def persist_operation_cost_event(
    db: Session,
    *,
    agent_id: str,
    environment: str,
    model_name: str,
    estimated_cost_cents: int,
    input_tokens: int,
    output_tokens: int,
    request_tag: str,
    trace_id: str,
    owner_scope: str,
    actor_id: str,
) -> None:
    cost_cents = max(0, int(estimated_cost_cents))
    if cost_cents <= 0:
        return
    normalized_trace = str(trace_id or f"trace-benchmark-scan-{uuid4().hex[:16]}").strip()
    db.add(
        CostEvent(
            cost_event_id=f"cost-{uuid4().hex[:24]}",
            request_id=normalized_trace,
            trace_id=normalized_trace,
            request_tag=str(request_tag or "benchmark_scan").strip() or "benchmark_scan",
            session_id=f"session-benchmark-scan-{actor_id}",
            agent_id=str(agent_id or "unknown").strip() or "unknown",
            owner_scope=str(owner_scope or f"actor:{actor_id}").strip() or f"actor:{actor_id}",
            environment=str(environment or "dev").strip().lower() or "dev",
            model_name=str(model_name or "unknown").strip() or "unknown",
            endpoint_family="chat.completions",
            input_tokens=max(0, int(input_tokens)),
            output_tokens=max(0, int(output_tokens)),
            estimated_cost_cents=cost_cents,
            currency="USD",
        )
    )


def resolve_agent_model(db: Session, agent_id: str, environment: str) -> str:
    normalized_agent = str(agent_id or "").strip()
    normalized_env = str(environment or "dev").strip().lower() or "dev"
    if normalized_agent:
        config = (
            db.query(AgentConfig)
            .filter(AgentConfig.agent_key == normalized_agent, AgentConfig.environment == normalized_env)
            .first()
        )
        if config is None:
            config = db.query(AgentConfig).filter(AgentConfig.agent_key == normalized_agent).first()
        if config and str(config.model or "").strip():
            return str(config.model).strip()
    return "gpt-4o-mini"


def _run_gateway_case(
    db: Session,
    *,
    agent_id: str,
    model_name: str,
    environment: str,
    prompt: str,
) -> dict[str, Any]:
    credential = resolve_inference_credential(
        db,
        agent_id=agent_id,
        environment=environment,
        model_name=model_name,
        resolve_gateway_cursor_token=_resolve_gateway_cursor_token,
    )
    started = time.perf_counter()
    inference = execute_chat_completion(
        db,
        credential=credential,
        model_name=model_name,
        messages=[{"role": "user", "content": prompt}],
        prompt_preview=prompt,
    )
    latency_ms = max(1, int((time.perf_counter() - started) * 1000))
    response_text = str(inference.content or "").strip()
    quality_score, quality_tier, score_reason = score_judge_response_with_reason(
        prompt_text=prompt,
        model_name=model_name,
        response_text=response_text,
    )
    preview = response_text if len(response_text) <= 160 else f"{response_text[:157]}…"
    prompt_tokens = int(inference.usage.prompt_tokens)
    completion_tokens = int(inference.usage.completion_tokens)
    estimated_cost_cents = _compute_gateway_call_cost_cents(
        db,
        model_name=model_name,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )
    return {
        "prompt": prompt,
        "model_name": model_name,
        "quality_score": round(float(quality_score), 2),
        "quality_tier": quality_tier,
        "score_reason": score_reason,
        "latency_ms": latency_ms,
        "response_preview": preview,
        "echo_stub": response_text.startswith(f"Simulated completion from {model_name}:"),
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "estimated_cost_cents": estimated_cost_cents,
    }


def _aggregate_benchmark_score(suite: str, case_results: list[dict[str, Any]]) -> int:
    if not case_results:
        return 0
    qualities = [float(row["quality_score"]) for row in case_results]
    latencies = [int(row["latency_ms"]) for row in case_results]
    avg_quality = mean(qualities)

    if suite == "latency-core":
        p95 = sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)]
        latency_factor = max(0.0, min(1.0, 1.0 - (p95 / 5000.0)))
        blended = (avg_quality * 0.45) + (latency_factor * 0.55)
        return max(0, min(100, int(round(blended * 100))))

    score = int(round(avg_quality * 100))
    if suite == "scale-tier3-100k":
        if any(float(row["quality_score"]) < 0.70 for row in case_results):
            score = min(score, 84)
        if any(row.get("echo_stub") for row in case_results):
            score = min(score, 60)
    if any(float(row["quality_score"]) < 0.35 for row in case_results):
        score = min(score, 65)
    return max(0, min(100, score))


def execute_benchmark_suite(
    db: Session,
    *,
    agent_id: str,
    benchmark_suite: str,
    environment: str,
    should_cancel: Optional[Callable[[], bool]] = None,
    on_progress: Optional[Callable[[int, int, str], None]] = None,
) -> dict[str, Any]:
    suite = str(benchmark_suite or "reliability-core").strip() or "reliability-core"
    cases = BENCHMARK_SUITE_CASES.get(suite, BENCHMARK_SUITE_CASES["reliability-core"])
    model_name = resolve_agent_model(db, agent_id, environment)
    total_cases = len(cases)

    case_results: list[dict[str, Any]] = []
    failures: list[str] = []
    cancelled = False
    for index, case in enumerate(cases, start=1):
        if should_cancel and should_cancel():
            cancelled = True
            break
        if on_progress:
            on_progress(index, total_cases, case.case_id)
        result = _run_gateway_case(
            db,
            agent_id=agent_id,
            model_name=model_name,
            environment=environment,
            prompt=case.prompt,
        )
        result["case_id"] = case.case_id
        case_results.append(result)
        if float(result["quality_score"]) < case.min_quality:
            failures.append(f"{case.case_id}: {result['score_reason']}")

    score = _aggregate_benchmark_score(suite, case_results) if case_results else 0
    latencies = [int(row["latency_ms"]) for row in case_results]
    summary_payload = {
        "suite": suite,
        "model_name": model_name,
        "case_count": len(case_results),
        "planned_case_count": total_cases,
        "cancelled": cancelled,
        "avg_quality": round(mean(float(row["quality_score"]) for row in case_results), 2) if case_results else 0,
        "p95_latency_ms": sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)] if latencies else 0,
        "failures": failures,
        "cases": case_results,
    }
    if cancelled:
        summary_text = (
            f"Benchmark suite {suite} cancelled after {len(case_results)}/{total_cases} gateway case(s). "
            f"Partial score {score} (model {model_name})."
        )
        status = "cancelled"
    elif failures:
        summary_text = (
            f"Benchmark suite {suite} completed with score {score}. "
            f"{len(failures)} case(s) below threshold via gateway inference."
        )
        status = "completed"
    else:
        summary_text = (
            f"Benchmark suite {suite} passed all {len(case_results)} gateway cases "
            f"with score {score} (model {model_name})."
        )
        status = "completed"
    estimated_cost_cents = sum(int(row.get("estimated_cost_cents") or 0) for row in case_results)
    input_tokens = sum(int(row.get("prompt_tokens") or 0) for row in case_results)
    output_tokens = sum(int(row.get("completion_tokens") or 0) for row in case_results)
    return {
        "score": score,
        "status": status,
        "summary": summary_text,
        "details_json": json.dumps(summary_payload),
        "model_name": model_name,
        "gateway_call_count": len(case_results),
        "estimated_cost_cents": estimated_cost_cents,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }


def execute_security_scan(
    db: Session,
    *,
    agent_id: str,
    environment: str,
    should_cancel: Optional[Callable[[], bool]] = None,
    on_progress: Optional[Callable[[int, int, str], None]] = None,
) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    normalized_agent = str(agent_id or "").strip()
    normalized_env = str(environment or "dev").strip().lower() or "dev"

    if should_cancel and should_cancel():
        return _cancelled_security_scan_result(
            db,
            agent_id=normalized_agent,
            environment=normalized_env,
            findings=findings,
            probe_results=[],
            completed_steps=0,
            total_steps=len(SECURITY_SCAN_PROBES),
        )

    agent = db.query(Agent).filter_by(agent_id=normalized_agent).first()
    if agent is None:
        severity = "high" if normalized_env == "prod" else "medium"
        findings.append({"severity": severity, "reason": "Agent is not registered in inventory."})
    elif str(agent.status or "").lower() not in {"active", "approved"}:
        findings.append({"severity": "medium", "reason": f"Agent status is {agent.status}."})

    config = db.query(AgentConfig).filter_by(agent_key=normalized_agent).first()
    if config is None:
        findings.append({"severity": "medium", "reason": "No agent config found for gateway inference."})
    elif not config.enabled:
        findings.append({"severity": "high", "reason": "Agent config is disabled."})
    elif normalized_env == "prod" and str(agent.risk_tier or "").lower() in {"high", "critical"}:
        if not str(config.credential_binding_id or "").strip():
            findings.append(
                {
                    "severity": "high",
                    "reason": "High/critical prod agent missing credential binding.",
                }
            )

    model_name = resolve_agent_model(db, normalized_agent, normalized_env)
    probe_results: list[dict[str, Any]] = []
    total_probes = len(SECURITY_SCAN_PROBES)
    cancelled = False
    for index, probe in enumerate(SECURITY_SCAN_PROBES, start=1):
        if should_cancel and should_cancel():
            cancelled = True
            break
        if on_progress:
            on_progress(index, total_probes, probe.case_id)
        result = _run_gateway_case(
            db,
            agent_id=normalized_agent,
            model_name=model_name,
            environment=normalized_env,
            prompt=probe.prompt,
        )
        result["case_id"] = probe.case_id
        probe_results.append(result)
        if result.get("echo_stub") and probe.reject_echo:
            findings.append(
                {
                    "severity": "high",
                    "reason": f"{probe.case_id}: gateway returned echo/stub response.",
                }
            )
        elif float(result["quality_score"]) < probe.min_quality:
            findings.append(
                {
                    "severity": "medium",
                    "reason": f"{probe.case_id}: quality {result['quality_score']} below {probe.min_quality}.",
                }
            )

    if cancelled:
        return _cancelled_security_scan_result(
            db,
            agent_id=normalized_agent,
            environment=normalized_env,
            findings=findings,
            probe_results=probe_results,
            completed_steps=len(probe_results),
            total_steps=total_probes,
        )

    high_count = sum(1 for item in findings if item["severity"] == "high")
    summary_payload = {
        "scan_type": "security",
        "model_name": model_name,
        "findings": findings,
        "probes": probe_results,
    }
    if high_count:
        summary = f"Security scan found {len(findings)} issue(s) including {high_count} high severity after gateway probes."
    else:
        summary = f"Security scan completed; {len(findings)} findings, no high severity issues."
    estimated_cost_cents = sum(int(row.get("estimated_cost_cents") or 0) for row in probe_results)
    input_tokens = sum(int(row.get("prompt_tokens") or 0) for row in probe_results)
    output_tokens = sum(int(row.get("completion_tokens") or 0) for row in probe_results)
    return {
        "findings_count": len(findings),
        "severity_high_count": high_count,
        "status": "completed",
        "summary": summary,
        "details_json": json.dumps(summary_payload),
        "model_name": model_name,
        "gateway_call_count": len(probe_results),
        "estimated_cost_cents": estimated_cost_cents,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }


def _cancelled_security_scan_result(
    db: Session,
    *,
    agent_id: str,
    environment: str,
    findings: list[dict[str, str]],
    probe_results: list[dict[str, Any]],
    completed_steps: int,
    total_steps: int,
) -> dict[str, Any]:
    model_name = resolve_agent_model(db, agent_id, environment)
    high_count = sum(1 for item in findings if item["severity"] == "high")
    summary_payload = {
        "scan_type": "security",
        "model_name": model_name,
        "findings": findings,
        "probes": probe_results,
        "cancelled": True,
    }
    summary = (
        f"Security scan cancelled after {completed_steps}/{total_steps} gateway probe(s); "
        f"{len(findings)} findings recorded."
    )
    estimated_cost_cents = sum(int(row.get("estimated_cost_cents") or 0) for row in probe_results)
    input_tokens = sum(int(row.get("prompt_tokens") or 0) for row in probe_results)
    output_tokens = sum(int(row.get("completion_tokens") or 0) for row in probe_results)
    return {
        "findings_count": len(findings),
        "severity_high_count": high_count,
        "status": "cancelled",
        "summary": summary,
        "details_json": json.dumps(summary_payload),
        "model_name": model_name,
        "gateway_call_count": len(probe_results),
        "estimated_cost_cents": estimated_cost_cents,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }


def execute_compliance_scan(
    db: Session,
    *,
    agent_id: str,
    environment: str,
    should_cancel: Optional[Callable[[], bool]] = None,
    on_progress: Optional[Callable[[int, int, str], None]] = None,
) -> dict[str, Any]:
    normalized_agent = str(agent_id or "").strip()
    normalized_env = str(environment or "dev").strip().lower() or "dev"
    if on_progress:
        on_progress(1, 1, "compliance-checks")
    if should_cancel and should_cancel():
        return {
            "findings_count": 0,
            "severity_high_count": 0,
            "status": "cancelled",
            "summary": "Compliance scan cancelled before checks completed.",
            "details_json": json.dumps({"scan_type": "compliance", "cancelled": True, "findings": []}),
            "model_name": resolve_agent_model(db, normalized_agent, normalized_env),
            "gateway_call_count": 0,
            "estimated_cost_cents": 0,
            "input_tokens": 0,
            "output_tokens": 0,
        }

    findings: list[dict[str, str]] = []

    agent = db.query(Agent).filter_by(agent_id=normalized_agent).first()
    if agent is None:
        findings.append({"severity": "high", "reason": "Agent is not registered for compliance review."})
    else:
        if not str(agent.owner_id or "").strip():
            findings.append({"severity": "high", "reason": "Agent owner_id is missing."})
        if not str(agent.risk_tier or "").strip():
            findings.append({"severity": "medium", "reason": "Agent risk_tier is not set."})

    config = db.query(AgentConfig).filter_by(agent_key=normalized_agent).first()
    if config is None:
        findings.append({"severity": "medium", "reason": "No agent config available for environment enforcement."})
    elif str(config.environment or "").strip().lower() not in {normalized_env, "dev", "staging", "prod"}:
        findings.append(
            {
                "severity": "medium",
                "reason": f"Agent config environment {config.environment} does not match scan target {normalized_env}.",
            }
        )

    try:
        from app.services.compliance_controls import known_control_ids

        known = known_control_ids()
        missing_controls = [ctrl for ctrl in COMPLIANCE_REQUIRED_CONTROLS if ctrl not in known]
        if missing_controls:
            findings.append(
                {
                    "severity": "high",
                    "reason": f"Missing compliance controls in catalog: {', '.join(missing_controls)}.",
                }
            )
    except Exception:
        findings.append({"severity": "medium", "reason": "Unable to verify compliance control catalog."})

    high_count = sum(1 for item in findings if item["severity"] == "high")
    summary_payload = {
        "scan_type": "compliance",
        "required_controls": list(COMPLIANCE_REQUIRED_CONTROLS),
        "findings": findings,
    }
    if high_count:
        summary = f"Compliance scan found {len(findings)} gap(s) including {high_count} high severity."
    else:
        summary = f"Compliance scan completed with {len(findings)} gap(s); no high severity issues."
    return {
        "findings_count": len(findings),
        "severity_high_count": high_count,
        "status": "completed",
        "summary": summary,
        "details_json": json.dumps(summary_payload),
        "model_name": resolve_agent_model(db, normalized_agent, normalized_env),
        "gateway_call_count": 0,
        "estimated_cost_cents": 0,
        "input_tokens": 0,
        "output_tokens": 0,
    }
