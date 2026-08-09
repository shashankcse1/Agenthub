"""Complexity-based auto-router (LiteLLM Auto Router / OpenRouter-style).

Heuristic classifier maps prompt signals to simple|standard|complex tiers and
selects a preferred catalog model, preferring live-ready providers.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models import SupportedModelCatalogEntry
from app.services.inference_readiness import build_inference_readiness


AUTO_ROUTE_MODEL_ALIASES = frozenset({"auto", "gateway/auto", "auto-route", "auto_route"})

_TIER_MODELS: dict[str, tuple[str, ...]] = {
    "simple": (
        "gpt-4o-mini",
        "claude-3-5-haiku-latest",
        "gemini-2.0-flash",
        "gemini-2.5-flash",
        "llama-3.1-8b-instant",
        "amazon.nova-lite-v1:0",
        "mistral-small-latest",
        "deepseek-chat",
        "grok-3-mini",
        "sonar",
    ),
    "standard": (
        "gpt-4o",
        "claude-sonnet-4-20250514",
        "claude-3-5-sonnet-latest",
        "gemini-2.5-flash",
        "gemini-1.5-pro",
        "mistral-large-latest",
        "amazon.nova-pro-v1:0",
        "command-r-plus",
        "grok-3",
        "sonar-pro",
    ),
    "complex": (
        "o4-mini",
        "o3-mini",
        "gpt-4.1",
        "claude-opus-4-20250514",
        "claude-3-opus-latest",
        "gemini-2.5-pro",
        "deepseek-reasoner",
        "anthropic.claude-3-5-sonnet-20241022-v2:0",
    ),
}

_COMPLEX_KEYWORDS = (
    "step by step",
    "chain of thought",
    "prove that",
    "formal proof",
    "architecture",
    "refactor",
    "security review",
    "threat model",
    "multi-agent",
    "plan then",
    "reason carefully",
    "optimize algorithm",
    "distributed system",
    "compliance",
    "soc2",
    "pci",
)

_CODE_FENCE_RE = re.compile(r"```")
_JSON_SCHEMA_RE = re.compile(r"\b(json schema|openapi|protobuf|graphql)\b", re.I)
_TOOL_RE = re.compile(r"\b(tool call|function call|mcp|agent loop|workflow)\b", re.I)
_MULTI_QUESTION_RE = re.compile(r"\?")


def classify_prompt_complexity(
    prompt_text: str,
    *,
    has_tools: bool = False,
    json_response_format: bool = False,
    message_count: int = 0,
    attachment_types: Optional[list[str]] = None,
) -> dict[str, Any]:
    text = str(prompt_text or "").strip()
    lower = text.lower()
    signals: list[str] = []
    score = 0

    char_len = len(text)
    word_count = len(text.split()) if text else 0
    if char_len >= 4000 or word_count >= 700:
        score += 40
        signals.append("long_prompt")
    elif char_len >= 1200 or word_count >= 220:
        score += 20
        signals.append("medium_prompt")
    elif char_len > 0:
        score += 5
        signals.append("short_prompt")

    fence_count = len(_CODE_FENCE_RE.findall(text))
    if fence_count >= 2:
        score += 25
        signals.append("multi_code_blocks")
    elif fence_count == 1:
        score += 12
        signals.append("code_block")

    keyword_hits = [kw for kw in _COMPLEX_KEYWORDS if kw in lower]
    if keyword_hits:
        score += min(30, 8 * len(keyword_hits))
        signals.append(f"complex_keywords:{len(keyword_hits)}")

    if _JSON_SCHEMA_RE.search(text):
        score += 15
        signals.append("schema_or_api_spec")
    if _TOOL_RE.search(text):
        score += 15
        signals.append("tool_or_agent_language")

    question_marks = len(_MULTI_QUESTION_RE.findall(text))
    if question_marks >= 3:
        score += 10
        signals.append("multi_question")

    if has_tools:
        score += 18
        signals.append("structured_tools")
    if json_response_format:
        score += 8
        signals.append("json_response_format")
    if int(message_count or 0) >= 8:
        score += 10
        signals.append("long_conversation")

    attachments = [str(item).strip().lower() for item in (attachment_types or []) if str(item).strip()]
    if attachments:
        score += min(24, 8 * len(attachments))
        signals.append(f"multimodal_attachments:{','.join(attachments[:5])}")
        if any(kind in {"image", "audio", "video", "pdf"} for kind in attachments):
            score += 10
            signals.append("rich_modality")

    if score >= 55:
        tier = "complex"
    elif score >= 25:
        tier = "standard"
    else:
        tier = "simple"

    return {
        "tier": tier,
        "score": score,
        "signals": signals,
        "char_length": char_len,
        "word_count": word_count,
        "attachment_types": attachments,
    }


def _catalog_models(db: Session) -> list[tuple[str, str]]:
    rows = (
        db.query(SupportedModelCatalogEntry.provider_type, SupportedModelCatalogEntry.model_name)
        .filter(SupportedModelCatalogEntry.status.in_(("active", "beta")))
        .order_by(SupportedModelCatalogEntry.model_name.asc())
        .all()
    )
    return [(str(provider or "").strip().lower(), str(model or "").strip()) for provider, model in rows if model]


def refine_complexity_with_judge(complexity: dict[str, Any], prompt_text: str) -> dict[str, Any]:
    """Boundary-aware second-pass judge (heuristic). Soft LLM-judge substitute for GOV-AI-MARKET-004."""
    base = dict(complexity or {})
    score = int(base.get("score") or 0)
    tier = str(base.get("tier") or "simple")
    signals = list(base.get("signals") or [])
    text = str(prompt_text or "")
    lower = text.lower()
    adjustments: list[str] = []

    # Pack 10 item 106: optional runtime judge thresholds.
    near_lo, near_hi = 20, 30
    complex_lo, complex_hi = 50, 60
    runtime_thresholds = base.get("_judge_thresholds") if isinstance(base.get("_judge_thresholds"), dict) else None
    if runtime_thresholds:
        ns = runtime_thresholds.get("near_standard") or [20, 30]
        nc = runtime_thresholds.get("near_complex") or [50, 60]
        if isinstance(ns, list) and len(ns) == 2:
            near_lo, near_hi = int(ns[0]), int(ns[1])
        if isinstance(nc, list) and len(nc) == 2:
            complex_lo, complex_hi = int(nc[0]), int(nc[1])

    # Near boundary windows: simple→standard, standard→complex
    near_standard = near_lo <= score <= near_hi
    near_complex = complex_lo <= score <= complex_hi

    if near_standard or near_complex:
        if any(token in lower for token in ("must", "exactly", "production", "do not", "constraints:")):
            score += 8
            adjustments.append("judge_strict_constraints")
        if text.count("\n-") >= 4 or text.count("\n*") >= 4:
            score += 6
            adjustments.append("judge_structured_checklist")
        if "ignore previous" in lower or "jailbreak" in lower:
            score += 12
            adjustments.append("judge_adversarial_prompt")
        if len(text) < 80 and not any(token in lower for token in ("json", "schema", "code", "threat")):
            score -= 6
            adjustments.append("judge_trivial_shortform")

    if score >= 55:
        new_tier = "complex"
    elif score >= 25:
        new_tier = "standard"
    else:
        new_tier = "simple"

    if adjustments:
        signals = [*signals, *adjustments]
    changed = new_tier != tier or score != int(base.get("score") or 0)
    return {
        **base,
        "tier": new_tier,
        "score": score,
        "signals": signals,
        "judge_refined": changed,
        "judge_mode": "heuristic",
        "prior_tier": tier,
    }


def _preferred_for_strategy(tier: str, strategy: str) -> tuple[str, ...]:
    preferred = _TIER_MODELS.get(tier, ())
    normalized = str(strategy or "balanced").strip().lower()
    if normalized == "quality":
        # Prefer frontier/higher models within the tier first.
        return tuple(reversed(preferred))
    # cost + balanced keep cheaper/faster models first (list already ordered that way).
    return preferred


def _reorder_by_telemetry(preferred: tuple[str, ...], score_by_model: dict[str, float]) -> tuple[str, ...]:
    if not score_by_model:
        return preferred

    def _key(model_name: str) -> tuple[float, int]:
        score = float(score_by_model.get(model_name.lower(), 0.0))
        # Keep original relative order as tie-breaker.
        try:
            original = preferred.index(model_name)
        except ValueError:
            original = 999
        return (-score, original)

    return tuple(sorted(preferred, key=_key))


def _pick_tier_model(
    *,
    tier: str,
    catalog: list[tuple[str, str]],
    live_providers: set[str],
    prefer_live_only: bool,
    strategy: str = "balanced",
    score_by_model: Optional[dict[str, float]] = None,
) -> Optional[dict[str, Any]]:
    preferred = _preferred_for_strategy(tier, strategy)
    if strategy in {"balanced", "quality"}:
        preferred = _reorder_by_telemetry(preferred, score_by_model or {})
    catalog_by_name = {model.lower(): (provider, model) for provider, model in catalog}
    used_telemetry = bool(score_by_model) and strategy in {"balanced", "quality"}
    for candidate in preferred:
        hit = catalog_by_name.get(candidate.lower())
        if not hit:
            continue
        provider_type, model_name = hit
        live = provider_type in live_providers
        if prefer_live_only and not live:
            continue
        return {
            "tier": tier,
            "provider_type": provider_type,
            "model_name": model_name,
            "live_ready": live,
            "source": (
                f"telemetry_ranked:{strategy}" if used_telemetry else f"preferred_catalog:{strategy}"
            ),
            "strategy": strategy,
            "telemetry_score": float((score_by_model or {}).get(model_name.lower(), 0.0)),
        }

    # Soften: any catalog model for a live provider when preferred list misses.
    for provider_type, model_name in catalog:
        live = provider_type in live_providers
        if prefer_live_only and not live:
            continue
        if provider_type in {"openai", "anthropic", "azure-openai", "aws", "google", "vertex", "groq"}:
            return {
                "tier": tier,
                "provider_type": provider_type,
                "model_name": model_name,
                "live_ready": live,
                "source": "catalog_fallback",
                "strategy": strategy,
            }
    return None


def _cap_tier(tier: str, max_budget_tier: Optional[str]) -> str:
    order = {"simple": 0, "standard": 1, "complex": 2}
    current = str(tier or "simple").strip().lower()
    ceiling = str(max_budget_tier or "").strip().lower()
    if ceiling not in order or current not in order:
        return current
    return current if order[current] <= order[ceiling] else ceiling


def build_auto_route_decision(
    db: Session,
    *,
    prompt_text: str,
    prefer_live_only: bool = True,
    max_candidates_per_tier: int = 3,
    strategy: str = "balanced",
    has_tools: bool = False,
    json_response_format: bool = False,
    message_count: int = 0,
    refine_with_judge: bool = True,
    use_telemetry_ranking: bool = True,
    max_budget_tier: Optional[str] = None,
    latency_slo_ms: Optional[int] = None,
    allowed_regions: Optional[list[str]] = None,
    attachment_types: Optional[list[str]] = None,
) -> dict[str, Any]:
    normalized_strategy = str(strategy or "balanced").strip().lower()
    if normalized_strategy not in {"balanced", "cost", "quality"}:
        normalized_strategy = "balanced"

    complexity = classify_prompt_complexity(
        prompt_text,
        has_tools=has_tools,
        json_response_format=json_response_format,
        message_count=message_count,
        attachment_types=attachment_types,
    )

    try:
        from app.services.gateway_leadership_pack11 import get_enforcement_flags

        flags = get_enforcement_flags(db).get("flags") or {}
    except Exception:  # noqa: BLE001
        flags = {}

    # Pack 10 items 104–105 (+ Pack 11 flags): adversarial hard-boost + PII bias signals.
    pii_bias = {"pii_detected": False, "preferred_providers": [], "avoid_providers": []}
    try:
        from app.services.gateway_leadership_pack8 import (
            apply_adversarial_tier_hard_boost,
            pii_aware_routing_bias,
        )

        if flags.get("enforce_adversarial_boost", True):
            complexity = apply_adversarial_tier_hard_boost(prompt_text, complexity)
        if flags.get("enforce_pii_bias", True):
            pii_bias = pii_aware_routing_bias(prompt_text)
    except Exception:  # noqa: BLE001
        pii_bias = {"pii_detected": False, "preferred_providers": [], "avoid_providers": []}

    if refine_with_judge:
        try:
            from app.services.gateway_leadership_pack8 import get_judge_thresholds

            thresholds = get_judge_thresholds(db).get("thresholds") or {}
            complexity = {**complexity, "_judge_thresholds": thresholds}
        except Exception:  # noqa: BLE001
            pass
        complexity = refine_complexity_with_judge(complexity, prompt_text)
        complexity.pop("_judge_thresholds", None)

    # Budget ceiling (item 38): never select above max_budget_tier.
    # Pack 10: PII bias can also cap budget tier.
    if pii_bias.get("pii_detected") and pii_bias.get("max_budget_tier") and not max_budget_tier:
        max_budget_tier = str(pii_bias.get("max_budget_tier"))
    capped_tier = _cap_tier(str(complexity.get("tier") or "simple"), max_budget_tier)
    if capped_tier != complexity.get("tier"):
        complexity = {
            **complexity,
            "tier": capped_tier,
            "signals": list(complexity.get("signals") or []) + [f"budget_cap:{capped_tier}"],
            "budget_capped": True,
        }

    # Latency SLO bias (item 39): prefer cost/simple when SLO is tight.
    if latency_slo_ms is not None and int(latency_slo_ms) > 0 and int(latency_slo_ms) <= 800:
        if normalized_strategy == "quality":
            normalized_strategy = "balanced"
        if complexity.get("tier") == "complex":
            complexity = {
                **complexity,
                "tier": "standard",
                "signals": list(complexity.get("signals") or []) + ["latency_slo_bias"],
            }

    readiness = build_inference_readiness(db)
    live_providers = {
        str(row.get("provider_type") or "").strip().lower()
        for row in readiness.get("providers") or []
        if row.get("live_ready")
    }
    catalog = _catalog_models(db)

    # Pack 11 item 137: model allow/deny policy.
    try:
        from app.services.gateway_leadership_pack11 import get_model_route_policy

        model_policy = get_model_route_policy(db) if flags.get("enforce_model_denylist", True) else {"allowlist": [], "denylist": []}
    except Exception:  # noqa: BLE001
        model_policy = {"allowlist": [], "denylist": []}
    allowlist = {str(m).strip().lower() for m in (model_policy.get("allowlist") or []) if str(m).strip()}
    denylist = {str(m).strip().lower() for m in (model_policy.get("denylist") or []) if str(m).strip()}
    catalog_before_policy = len(catalog)
    if allowlist or denylist:
        catalog = [
            (provider, model)
            for provider, model in catalog
            if (not allowlist or model.lower() in allowlist) and model.lower() not in denylist
        ]
    catalog_policy_meta = {
        "catalog_before": catalog_before_policy,
        "catalog_after": len(catalog),
        "allowlist_size": len(allowlist),
        "denylist_size": len(denylist),
        "empty_after_policy": bool((allowlist or denylist) and not catalog),
    }

    score_by_model: dict[str, float] = {}
    ranking_meta: dict[str, Any] = {"enabled": False, "sample_events": 0}
    if use_telemetry_ranking and normalized_strategy in {"balanced", "quality"}:
        from app.services.gateway_leadership import build_model_liquidity_ranking

        ranking = build_model_liquidity_ranking(db, hours=168, limit=50)
        score_by_model = dict(ranking.get("score_by_model") or {})
        ranking_meta = {
            "enabled": True,
            "sample_events": ranking.get("sample_events"),
            "leader_signal": ranking.get("leader_signal"),
            "top_model": (ranking.get("models") or [{}])[0].get("model_name") if ranking.get("models") else None,
        }

    tier_candidates: dict[str, list[dict[str, Any]]] = {}
    for tier in ("simple", "standard", "complex"):
        picks: list[dict[str, Any]] = []
        preferred = _preferred_for_strategy(tier, normalized_strategy)
        if normalized_strategy in {"balanced", "quality"}:
            preferred = _reorder_by_telemetry(preferred, score_by_model)
        catalog_by_name = {model.lower(): (provider, model) for provider, model in catalog}
        for candidate in preferred:
            hit = catalog_by_name.get(candidate.lower())
            if not hit:
                continue
            provider_type, model_name = hit
            live = provider_type in live_providers
            if prefer_live_only and not live:
                continue
            picks.append(
                {
                    "provider_type": provider_type,
                    "model_name": model_name,
                    "live_ready": live,
                    "telemetry_score": float(score_by_model.get(model_name.lower(), 0.0)),
                }
            )
            if len(picks) >= max(1, min(int(max_candidates_per_tier or 3), 8)):
                break
        tier_candidates[tier] = picks

    # PII-aware provider preference (Pack 10 item 105).
    preferred_providers = {
        str(p).strip().lower() for p in (pii_bias.get("preferred_providers") or []) if str(p).strip()
    }
    avoid_providers = {
        str(p).strip().lower() for p in (pii_bias.get("avoid_providers") or []) if str(p).strip()
    }
    filtered_catalog = catalog
    if preferred_providers or avoid_providers:
        preferred_first = [row for row in catalog if row[0] in preferred_providers]
        others = [
            row
            for row in catalog
            if row[0] not in avoid_providers and row[0] not in preferred_providers
        ]
        filtered_catalog = preferred_first + others if preferred_first or others else catalog

    selected = _pick_tier_model(
        tier=str(complexity["tier"]),
        catalog=filtered_catalog,
        live_providers=live_providers,
        prefer_live_only=prefer_live_only,
        strategy=normalized_strategy,
        score_by_model=score_by_model,
    )
    if selected is None and prefer_live_only:
        selected = _pick_tier_model(
            tier=str(complexity["tier"]),
            catalog=filtered_catalog,
            live_providers=live_providers,
            prefer_live_only=False,
            strategy=normalized_strategy,
            score_by_model=score_by_model,
        )

    regions = [str(r).strip().lower() for r in (allowed_regions or []) if str(r).strip()]
    empty_policy = bool(catalog_policy_meta.get("empty_after_policy"))
    no_model_reason = (
        "model allow/deny policy removed all catalog candidates."
        if empty_policy
        else "no catalog model available for this tier."
    )
    return {
        "complexity": complexity,
        "selected": selected,
        "selected_model": selected["model_name"] if selected else None,
        "selected_provider_type": selected["provider_type"] if selected else None,
        "tier_candidates": tier_candidates,
        "prefer_live_only": prefer_live_only,
        "strategy": normalized_strategy,
        "refine_with_judge": bool(refine_with_judge),
        "telemetry_ranking": ranking_meta,
        "catalog_policy": catalog_policy_meta,
        "constraints": {
            "max_budget_tier": max_budget_tier,
            "latency_slo_ms": latency_slo_ms,
            "allowed_regions": regions,
            "attachment_types": list(attachment_types or []),
            "pii_detected": bool(pii_bias.get("pii_detected")),
            "adversarial_boost": bool(complexity.get("adversarial_boost")),
        },
        "rationale": (
            f"Classified as {complexity['tier']} (score={complexity['score']}, strategy={normalized_strategy}"
            f"{', judge=on' if refine_with_judge else ''}"
            f"{', telemetry=on' if ranking_meta.get('enabled') else ''}"
            f"{', budget_cap=' + str(max_budget_tier) if max_budget_tier else ''}"
            f"{', latency_slo=' + str(latency_slo_ms) if latency_slo_ms else ''}"
            f"{', regions=' + ','.join(regions) if regions else ''}"
            f"{', pii_bias' if pii_bias.get('pii_detected') else ''}"
            f"{', adversarial_boost' if complexity.get('adversarial_boost') else ''}); "
            + (
                f"selected {selected['model_name']} via {selected['source']}."
                if selected
                else no_model_reason
            )
        ),
        "readiness": {
            "ready_providers": readiness.get("ready_providers"),
            "live_provider_types": sorted(live_providers),
            "simulation_enabled": readiness.get("simulation_enabled"),
        },
    }


def should_auto_route(model_name: str, auto_route_flag: bool = False) -> bool:
    if auto_route_flag:
        return True
    normalized = str(model_name or "").strip().lower()
    return normalized in AUTO_ROUTE_MODEL_ALIASES
