from __future__ import annotations

import time

from sqlalchemy.orm import Session

from app.services.gateway_inference import (
    execute_chat_completion,
    lookup_factual_answer,
    resolve_inference_credential,
)


def _resolve_gateway_cursor_token(db: Session) -> str:
    from app.routers.gateway import _resolve_gateway_cursor_api_token

    return _resolve_gateway_cursor_api_token(db)


def score_judge_response(*, prompt_text: str, model_name: str, response_text: str) -> float:
    score, _, _ = score_judge_response_with_reason(
        prompt_text=prompt_text,
        model_name=model_name,
        response_text=response_text,
    )
    return score


def score_judge_response_with_reason(
    *,
    prompt_text: str,
    model_name: str,
    response_text: str,
) -> tuple[float, str, str]:
    text = str(response_text or "").strip()
    if not text:
        return 0.0, "poor", "Empty response"

    echo_prefix = f"Simulated completion from {model_name}:"
    if text.startswith(echo_prefix):
        return 0.15, "poor", "Echo/stub response (simulated completion without a real answer)"

    expected = lookup_factual_answer(prompt_text)
    if expected:
        expected_lower = expected.lower()
        text_lower = text.lower()
        if expected_lower in text_lower:
            return 0.97, "excellent", f"Matches expected factual answer: {expected}"
        key_terms = [term for term in expected_lower.replace(",", "").split() if len(term) > 3]
        if key_terms and all(term in text_lower for term in key_terms):
            return 0.88, "good", f"Contains key terms from expected answer ({expected})"
        return 0.35, "fair", "Factual prompt but response does not match the expected answer"

    if len(text) < 8:
        return 0.35, "fair", "Response is too short to be useful"

    score = min(0.92, 0.55 + min(len(text), 400) / 800.0)
    return score, "good", "Substantive response (heuristic length score for non-factual prompts)"


def estimate_judge_cost_cents(*, prompt_tokens: int, completion_tokens: int) -> int:
    total = max(0, int(prompt_tokens)) + max(0, int(completion_tokens))
    return max(1, total // 40)


def extract_playground_prompt_text(packaged_prompt: str) -> str:
    text = str(packaged_prompt or "").strip()
    marker = "## Prompt"
    if marker in text:
        return text.split(marker, 1)[1].strip()
    return text


def quality_score_to_suggested_rating(quality_score: float) -> int:
    score = float(quality_score)
    if score >= 0.9:
        return 5
    if score >= 0.75:
        return 4
    if score >= 0.55:
        return 3
    if score >= 0.35:
        return 2
    return 1


def build_suggested_feedback_comment(*, quality_tier: str, score_reason: str, model_name: str) -> str:
    tier = str(quality_tier or "fair").strip().lower()
    reason = str(score_reason or "No assessment reason provided.").strip()
    model = str(model_name or "unknown").strip()
    return f"AI assessment ({tier}): {reason} [model: {model}]"


def assess_playground_run_response(
    db: Session,
    *,
    prompt_text: str,
    model_name: str,
    response_text: str | None = None,
    environment: str = "dev",
) -> dict[str, object]:
    normalized_prompt = extract_playground_prompt_text(prompt_text)
    normalized_model = str(model_name or "").strip()
    if not normalized_prompt:
        raise ValueError("prompt_text is required")
    if not normalized_model:
        raise ValueError("selected_model is required")

    inference_ran = False
    resolved_response = str(response_text or "").strip()
    if not resolved_response:
        credential = resolve_inference_credential(
            db,
            agent_id=None,
            environment=environment,
            model_name=normalized_model,
            resolve_gateway_cursor_token=_resolve_gateway_cursor_token,
        )
        inference = execute_chat_completion(
            db,
            credential=credential,
            model_name=normalized_model,
            messages=[{"role": "user", "content": normalized_prompt}],
            prompt_preview=normalized_prompt,
        )
        resolved_response = str(inference.content or "").strip()
        inference_ran = True

    quality_score, quality_tier, score_reason = score_judge_response_with_reason(
        prompt_text=normalized_prompt,
        model_name=normalized_model,
        response_text=resolved_response,
    )
    preview = resolved_response if len(resolved_response) <= 160 else f"{resolved_response[:157]}…"
    suggested_rating = quality_score_to_suggested_rating(quality_score)
    suggested_comment = build_suggested_feedback_comment(
        quality_tier=quality_tier,
        score_reason=score_reason,
        model_name=normalized_model,
    )
    return {
        "model_name": normalized_model,
        "quality_score": round(quality_score, 2),
        "quality_tier": quality_tier,
        "score_reason": score_reason,
        "suggested_rating": suggested_rating,
        "suggested_comment": suggested_comment,
        "response_preview": preview,
        "response_text": resolved_response,
        "inference_ran": inference_ran,
    }


def judge_candidate_models(
    db: Session,
    *,
    prompt_text: str,
    candidate_models: list[str],
    environment: str = "dev",
) -> list[dict[str, object]]:
    normalized_prompt = str(prompt_text or "").strip()
    if not normalized_prompt:
        return []

    results: list[dict[str, object]] = []
    for model_name in candidate_models:
        normalized_model = str(model_name or "").strip()
        if not normalized_model:
            continue

        started = time.perf_counter()
        credential = resolve_inference_credential(
            db,
            agent_id=None,
            environment=environment,
            model_name=normalized_model,
            resolve_gateway_cursor_token=_resolve_gateway_cursor_token,
        )
        inference = execute_chat_completion(
            db,
            credential=credential,
            model_name=normalized_model,
            messages=[{"role": "user", "content": normalized_prompt}],
            prompt_preview=normalized_prompt,
        )
        latency_ms = max(1, int((time.perf_counter() - started) * 1000))
        response_text = str(inference.content or "").strip()
        preview = response_text if len(response_text) <= 160 else f"{response_text[:157]}…"
        quality_score, quality_tier, score_reason = score_judge_response_with_reason(
            prompt_text=normalized_prompt,
            model_name=normalized_model,
            response_text=response_text,
        )

        results.append(
            {
                "model_name": normalized_model,
                "estimated_latency_ms": latency_ms,
                "estimated_cost_cents": estimate_judge_cost_cents(
                    prompt_tokens=inference.usage.prompt_tokens,
                    completion_tokens=inference.usage.completion_tokens,
                ),
                "quality_score": round(quality_score, 2),
                "quality_tier": quality_tier,
                "score_reason": score_reason,
                "response_preview": preview,
                "response_text": response_text,
            }
        )

    results.sort(key=lambda row: (-float(row["quality_score"]), int(row["estimated_latency_ms"])))
    for index, row in enumerate(results, start=1):
        row["rank"] = index
    return results
