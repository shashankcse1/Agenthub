from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import CacheDecisionEvent, CachePolicy, GatewayResponseCacheEntry
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_CACHE_INFERENCE_SHORT_CIRCUIT_ENABLED
from app.services.audit import create_audit_event
from app.services.runtime_config import get_runtime_config
from app.services.secret_crypto import decrypt_sensitive_value, encrypt_sensitive_value


def normalize_cache_request_text(value: str | None) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def fingerprint_cache_request(parts: list[str]) -> str:
    normalized = "|".join(str(part or "").strip() for part in parts)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]


def semantic_similarity_score(left_text: str | None, right_text: str | None) -> float:
    left_tokens = set(re.findall(r"[a-z0-9]+", normalize_cache_request_text(left_text)))
    right_tokens = set(re.findall(r"[a-z0-9]+", normalize_cache_request_text(right_text)))
    if not left_tokens or not right_tokens:
        return 0.0
    overlap = len(left_tokens & right_tokens)
    union = len(left_tokens | right_tokens)
    return round(overlap / union, 4) if union else 0.0


def classify_cache_data_class(request_tag: str | None, request_text: str) -> str:
    normalized_tag = str(request_tag or "").strip().lower()
    if normalized_tag.startswith("pii"):
        return "pii"
    if normalized_tag.startswith("phi"):
        return "phi"
    if normalized_tag.startswith("secret"):
        return "secret"
    lowered = str(request_text or "").lower()
    if any(token in lowered for token in ["password", "secret", "api key", "ssn", "token"]):
        return "sensitive"
    return "standard"


def _parse_string_list(raw: str) -> list[str]:
    try:
        parsed = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item).strip() for item in parsed if str(item).strip()]


def _parse_bool(raw: str, default: bool = False) -> bool:
    value = (raw or "").strip().lower()
    if value in {"true", "1", "yes", "on"}:
        return True
    if value in {"false", "0", "no", "off"}:
        return False
    return default


def is_inference_short_circuit_enabled(db: Session) -> bool:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_CACHE_INFERENCE_SHORT_CIRCUIT_ENABLED, "false")
    return _parse_bool(raw, False)


def resolve_cache_policy_for_request(
    db: Session,
    tenant_id: str,
    route_policy_id: str | None,
    owner_scope: str | None,
) -> CachePolicy | None:
    normalized_tenant = str(tenant_id or "").strip()
    normalized_route = str(route_policy_id or "").strip()
    normalized_owner_scope = str(owner_scope or "").strip()
    scopes: list[str] = ["global"]
    if normalized_tenant:
        scopes.append(f"tenant:{normalized_tenant}")
    if normalized_route:
        scopes.append(f"route:{normalized_route}")
    if normalized_owner_scope:
        scopes.append(f"owner:{normalized_owner_scope}")

    rows = (
        db.query(CachePolicy)
        .filter(CachePolicy.status == "active")
        .filter(CachePolicy.scope.in_(scopes))
        .all()
    )
    by_scope = {str(row.scope): row for row in rows}
    if normalized_route and by_scope.get(f"route:{normalized_route}"):
        return by_scope[f"route:{normalized_route}"]
    if normalized_owner_scope and by_scope.get(f"owner:{normalized_owner_scope}"):
        return by_scope[f"owner:{normalized_owner_scope}"]
    if normalized_tenant and by_scope.get(f"tenant:{normalized_tenant}"):
        return by_scope[f"tenant:{normalized_tenant}"]
    return by_scope.get("global")


@dataclass
class CachePreInferenceResult:
    short_circuit_active: bool
    cached_response: dict[str, Any] | None
    matched_policy: CachePolicy | None
    data_class: str
    decision: str
    explanation: str
    provenance: str
    cache_mode: str | None
    match_score: float
    source_request_id: str | None
    request_fingerprint: str
    request_text_normalized: str
    should_store_after_inference: bool


def _build_scope_filters(
    db: Session,
    *,
    policy: CachePolicy,
    tenant_id: str,
    owner_scope: str | None,
) -> list[Any]:
    privacy_scope = str(policy.privacy_scope or "tenant").strip().lower() or "tenant"
    filters: list[Any] = []
    if privacy_scope == "owner":
        normalized_owner = str(owner_scope or "").strip()
        if normalized_owner:
            filters.append(GatewayResponseCacheEntry.owner_scope == normalized_owner)
    elif privacy_scope == "tenant":
        normalized_tenant = str(tenant_id or "").strip()
        if normalized_tenant:
            filters.append(GatewayResponseCacheEntry.tenant_id == normalized_tenant)
    return filters


def _record_decision_event(
    db: Session,
    *,
    actor_id: str,
    trace_id: str,
    request_id: str,
    request_fingerprint: str,
    request_text: str,
    tenant_id: str,
    environment: str,
    route_policy_id: str | None,
    data_class: str,
    matched_policy: CachePolicy | None,
    cache_mode: str | None,
    match_score: float,
    decision: str,
    explanation: str,
    provenance: str,
    source_request_id: str | None,
) -> None:
    cache_policy_id = matched_policy.cache_policy_id if matched_policy else None
    cache_policy_scope = matched_policy.scope if matched_policy else None

    if decision == "hit" and matched_policy is not None:
        create_audit_event(
            db,
            actor_id=actor_id,
            action_type="gateway.cache.hit",
            resource_type="cache_policy",
            resource_id=matched_policy.cache_policy_id,
            trace_id=trace_id,
            decision_outcome="allow",
        )
    elif decision == "miss" and matched_policy is not None:
        create_audit_event(
            db,
            actor_id=actor_id,
            action_type="gateway.cache.miss",
            resource_type="cache_policy",
            resource_id=matched_policy.cache_policy_id,
            trace_id=trace_id,
            decision_outcome="allow",
        )
    elif decision == "bypass" and matched_policy is not None:
        create_audit_event(
            db,
            actor_id=actor_id,
            action_type="gateway.cache.bypass",
            resource_type="cache_policy",
            resource_id=matched_policy.cache_policy_id,
            trace_id=trace_id,
            decision_outcome="allow",
        )

    db.add(
        CacheDecisionEvent(
            cache_decision_event_id=str(uuid4()),
            trace_id=trace_id,
            request_id=request_id,
            request_fingerprint=request_fingerprint,
            request_text=request_text,
            actor_id=actor_id,
            tenant_id=str(tenant_id or "").strip(),
            environment=str(environment or "dev").strip().lower() or "dev",
            route_policy_id=str(route_policy_id or "").strip() or None,
            data_class=data_class,
            cache_policy_id=cache_policy_id,
            cache_policy_scope=cache_policy_scope,
            cache_mode=cache_mode,
            match_score=match_score,
            decision=decision,
            explanation=explanation,
            match_provenance=provenance,
            source_request_id=source_request_id,
        )
    )


def evaluate_pre_inference_cache(
    db: Session,
    *,
    actor_id: str,
    trace_id: str,
    request_id: str,
    request_fingerprint: str,
    request_text: str,
    tenant_id: str,
    environment: str,
    route_policy_id: str | None,
    request_tag: str | None,
    owner_scope: str | None,
    endpoint_family: str,
) -> CachePreInferenceResult:
    request_text_normalized = normalize_cache_request_text(request_text)
    data_class = classify_cache_data_class(request_tag, request_text)
    short_circuit_active = is_inference_short_circuit_enabled(db)

    if not short_circuit_active:
        return CachePreInferenceResult(
            short_circuit_active=False,
            cached_response=None,
            matched_policy=None,
            data_class=data_class,
            decision="disabled",
            explanation="inference cache short-circuit disabled",
            provenance="cache-policy:short-circuit-disabled",
            cache_mode=None,
            match_score=0.0,
            source_request_id=None,
            request_fingerprint=request_fingerprint,
            request_text_normalized=request_text_normalized,
            should_store_after_inference=False,
        )

    matched_policy = resolve_cache_policy_for_request(
        db,
        tenant_id=tenant_id,
        route_policy_id=route_policy_id,
        owner_scope=owner_scope,
    )

    if matched_policy is None:
        return CachePreInferenceResult(
            short_circuit_active=True,
            cached_response=None,
            matched_policy=None,
            data_class=data_class,
            decision="bypass",
            explanation="cache bypassed: no active policy for request scope",
            provenance="cache-policy:none",
            cache_mode=None,
            match_score=0.0,
            source_request_id=None,
            request_fingerprint=request_fingerprint,
            request_text_normalized=request_text_normalized,
            should_store_after_inference=False,
        )

    privacy_scope = str(matched_policy.privacy_scope or "tenant").strip().lower() or "tenant"
    non_cache_data_classes = {
        str(item).strip().lower() for item in _parse_string_list(str(matched_policy.non_cache_data_classes or "[]"))
    }
    cache_mode = str(matched_policy.cache_mode or "exact").strip() or "exact"
    provenance = (
        f"cache-policy:{matched_policy.cache_policy_id};scope:{matched_policy.scope};"
        f"mode:{cache_mode};privacy_scope:{privacy_scope};data_class:{data_class};short_circuit:true"
    )

    if data_class in non_cache_data_classes:
        explanation = f"cache bypassed: data_class {data_class} is disallowed by policy"
        provenance += f";policy_action:no_cache"
        _record_decision_event(
            db,
            actor_id=actor_id,
            trace_id=trace_id,
            request_id=request_id,
            request_fingerprint=request_fingerprint,
            request_text=request_text_normalized,
            tenant_id=tenant_id,
            environment=environment,
            route_policy_id=route_policy_id,
            data_class=data_class,
            matched_policy=matched_policy,
            cache_mode=cache_mode,
            match_score=0.0,
            decision="bypass",
            explanation=explanation,
            provenance=provenance,
            source_request_id=None,
        )
        return CachePreInferenceResult(
            short_circuit_active=True,
            cached_response=None,
            matched_policy=matched_policy,
            data_class=data_class,
            decision="bypass",
            explanation=explanation,
            provenance=provenance,
            cache_mode=cache_mode,
            match_score=0.0,
            source_request_id=None,
            request_fingerprint=request_fingerprint,
            request_text_normalized=request_text_normalized,
            should_store_after_inference=False,
        )

    if privacy_scope == "owner" and not str(owner_scope or "").strip():
        explanation = "cache bypassed: owner-scoped policy requires owner scope context"
        provenance += ";policy_action:owner_scope_required"
        _record_decision_event(
            db,
            actor_id=actor_id,
            trace_id=trace_id,
            request_id=request_id,
            request_fingerprint=request_fingerprint,
            request_text=request_text_normalized,
            tenant_id=tenant_id,
            environment=environment,
            route_policy_id=route_policy_id,
            data_class=data_class,
            matched_policy=matched_policy,
            cache_mode=cache_mode,
            match_score=0.0,
            decision="bypass",
            explanation=explanation,
            provenance=provenance,
            source_request_id=None,
        )
        return CachePreInferenceResult(
            short_circuit_active=True,
            cached_response=None,
            matched_policy=matched_policy,
            data_class=data_class,
            decision="bypass",
            explanation=explanation,
            provenance=provenance,
            cache_mode=cache_mode,
            match_score=0.0,
            source_request_id=None,
            request_fingerprint=request_fingerprint,
            request_text_normalized=request_text_normalized,
            should_store_after_inference=False,
        )

    now = datetime.utcnow()
    normalized_environment = str(environment or "dev").strip().lower() or "dev"
    base_query = (
        db.query(GatewayResponseCacheEntry)
        .filter(GatewayResponseCacheEntry.status == "active")
        .filter(GatewayResponseCacheEntry.cache_policy_id == matched_policy.cache_policy_id)
        .filter(GatewayResponseCacheEntry.endpoint_family == endpoint_family)
        .filter(GatewayResponseCacheEntry.environment == normalized_environment)
        .filter(GatewayResponseCacheEntry.ttl_expires_at > now)
    )
    for scope_filter in _build_scope_filters(db, policy=matched_policy, tenant_id=tenant_id, owner_scope=owner_scope):
        base_query = base_query.filter(scope_filter)

    hit_entry: GatewayResponseCacheEntry | None = None
    match_score = 0.0
    source_request_id: str | None = None

    if cache_mode == "exact":
        hit_entry = base_query.filter(GatewayResponseCacheEntry.request_fingerprint == request_fingerprint).first()
        if hit_entry is not None:
            match_score = 1.0
            source_request_id = hit_entry.source_request_id
    else:
        candidates = base_query.filter(GatewayResponseCacheEntry.request_text != "").order_by(
            GatewayResponseCacheEntry.created_at.desc()
        ).all()
        best_score = 0.0
        best_entry: GatewayResponseCacheEntry | None = None
        threshold = float(matched_policy.similarity_threshold)
        for candidate in candidates:
            candidate_score = semantic_similarity_score(request_text_normalized, candidate.request_text)
            if candidate_score > best_score:
                best_score = candidate_score
                best_entry = candidate
        match_score = best_score
        if best_entry is not None and best_score >= threshold:
            hit_entry = best_entry
            source_request_id = best_entry.source_request_id

    if hit_entry is not None:
        try:
            decrypted = decrypt_sensitive_value(hit_entry.response_body_encrypted)
            cached_body = json.loads(decrypted)
        except (json.JSONDecodeError, ValueError):
            cached_body = None

        if isinstance(cached_body, dict):
            explanation = (
                f"inference short-circuit hit: {'exact' if cache_mode == 'exact' else 'semantic'} "
                f"cache returned stored response (score={match_score})"
            )
            provenance += f";match_score:{match_score};source_request_id:{source_request_id};entry_id:{hit_entry.cache_entry_id}"
            _record_decision_event(
                db,
                actor_id=actor_id,
                trace_id=trace_id,
                request_id=request_id,
                request_fingerprint=request_fingerprint,
                request_text=request_text_normalized,
                tenant_id=tenant_id,
                environment=environment,
                route_policy_id=route_policy_id,
                data_class=data_class,
                matched_policy=matched_policy,
                cache_mode=cache_mode,
                match_score=match_score,
                decision="hit",
                explanation=explanation,
                provenance=provenance,
                source_request_id=source_request_id,
            )
            refreshed = dict(cached_body)
            refreshed["request_id"] = request_id
            refreshed["trace_id"] = trace_id
            refreshed["cache_short_circuit"] = True
            return CachePreInferenceResult(
                short_circuit_active=True,
                cached_response=refreshed,
                matched_policy=matched_policy,
                data_class=data_class,
                decision="hit",
                explanation=explanation,
                provenance=provenance,
                cache_mode=cache_mode,
                match_score=match_score,
                source_request_id=source_request_id,
                request_fingerprint=request_fingerprint,
                request_text_normalized=request_text_normalized,
                should_store_after_inference=False,
            )

    explanation = (
        f"inference short-circuit miss: no stored response for "
        f"{'exact fingerprint' if cache_mode == 'exact' else f'semantic threshold {matched_policy.similarity_threshold}'}"
    )
    if cache_mode == "semantic" and match_score > 0:
        provenance += f";match_score:{match_score}"
    return CachePreInferenceResult(
        short_circuit_active=True,
        cached_response=None,
        matched_policy=matched_policy,
        data_class=data_class,
        decision="miss",
        explanation=explanation,
        provenance=provenance,
        cache_mode=cache_mode,
        match_score=match_score,
        source_request_id=None,
        request_fingerprint=request_fingerprint,
        request_text_normalized=request_text_normalized,
        should_store_after_inference=True,
    )


def store_cache_entry(
    db: Session,
    *,
    cache_policy: CachePolicy,
    request_fingerprint: str,
    request_text: str,
    response_body: dict[str, Any],
    tenant_id: str,
    environment: str,
    route_policy_id: str | None,
    owner_scope: str,
    data_class: str,
    cache_mode: str,
    endpoint_family: str,
    source_request_id: str,
    match_score: float = 1.0,
) -> GatewayResponseCacheEntry:
    ttl_seconds = max(60, int(cache_policy.ttl_seconds or 60))
    encrypted_body = encrypt_sensitive_value(json.dumps(response_body, separators=(",", ":")))
    entry = GatewayResponseCacheEntry(
        cache_entry_id=str(uuid4()),
        cache_policy_id=cache_policy.cache_policy_id,
        request_fingerprint=request_fingerprint,
        request_text=normalize_cache_request_text(request_text),
        response_body_encrypted=encrypted_body,
        tenant_id=str(tenant_id or "").strip(),
        environment=str(environment or "dev").strip().lower() or "dev",
        route_policy_id=str(route_policy_id or "").strip() or None,
        owner_scope=str(owner_scope or "").strip(),
        data_class=data_class,
        cache_mode=cache_mode,
        match_score=match_score,
        endpoint_family=endpoint_family,
        source_request_id=source_request_id,
        ttl_expires_at=datetime.utcnow() + timedelta(seconds=ttl_seconds),
        status="active",
    )
    db.add(entry)
    return entry


def finalize_post_inference_cache(
    db: Session,
    *,
    pre: CachePreInferenceResult,
    actor_id: str,
    trace_id: str,
    request_id: str,
    tenant_id: str,
    environment: str,
    route_policy_id: str | None,
    response_body: dict[str, Any],
    endpoint_family: str,
    owner_scope: str,
) -> None:
    if not pre.short_circuit_active:
        return
    if pre.decision in {"bypass", "hit", "disabled"}:
        return
    if not pre.should_store_after_inference or pre.matched_policy is None:
        return

    store_cache_entry(
        db,
        cache_policy=pre.matched_policy,
        request_fingerprint=pre.request_fingerprint,
        request_text=pre.request_text_normalized,
        response_body=response_body,
        tenant_id=tenant_id,
        environment=environment,
        route_policy_id=route_policy_id,
        owner_scope=owner_scope,
        data_class=pre.data_class,
        cache_mode=str(pre.cache_mode or "exact"),
        endpoint_family=endpoint_family,
        source_request_id=request_id,
        match_score=pre.match_score if pre.cache_mode == "semantic" else 1.0,
    )

    _record_decision_event(
        db,
        actor_id=actor_id,
        trace_id=trace_id,
        request_id=request_id,
        request_fingerprint=pre.request_fingerprint,
        request_text=pre.request_text_normalized,
        tenant_id=tenant_id,
        environment=environment,
        route_policy_id=route_policy_id,
        data_class=pre.data_class,
        matched_policy=pre.matched_policy,
        cache_mode=pre.cache_mode,
        match_score=pre.match_score,
        decision="miss",
        explanation=pre.explanation,
        provenance=pre.provenance + ";stored:true",
        source_request_id=None,
    )


def purge_cache_entries(
    db: Session,
    *,
    scope: str | None = None,
    cache_keys: list[str] | None = None,
    active_only: bool = True,
) -> int:
    query = db.query(GatewayResponseCacheEntry)
    if active_only:
        query = query.filter(GatewayResponseCacheEntry.status == "active")

    normalized_scope = str(scope or "").strip()
    if normalized_scope:
        if normalized_scope.startswith("tenant:"):
            tenant_id = normalized_scope.split(":", 1)[1]
            query = query.filter(GatewayResponseCacheEntry.tenant_id == tenant_id)
        elif normalized_scope.startswith("owner:"):
            owner = normalized_scope.split(":", 1)[1]
            query = query.filter(GatewayResponseCacheEntry.owner_scope == owner)
        elif normalized_scope.startswith("route:"):
            route_id = normalized_scope.split(":", 1)[1]
            query = query.filter(GatewayResponseCacheEntry.route_policy_id == route_id)
        else:
            policy_ids = [
                row.cache_policy_id
                for row in db.query(CachePolicy.cache_policy_id)
                .filter(CachePolicy.scope == normalized_scope)
                .all()
            ]
            if policy_ids:
                query = query.filter(GatewayResponseCacheEntry.cache_policy_id.in_(policy_ids))

    normalized_keys = [str(item).strip() for item in (cache_keys or []) if str(item).strip()]
    if normalized_keys:
        query = query.filter(GatewayResponseCacheEntry.request_fingerprint.in_(normalized_keys))

    rows = query.all()
    purged = 0
    for row in rows:
        row.status = "invalidated"
        purged += 1
    return purged


def cache_entry_stats(db: Session) -> dict[str, Any]:
    now = datetime.utcnow()
    active_entries = (
        db.query(GatewayResponseCacheEntry)
        .filter(GatewayResponseCacheEntry.status == "active")
        .filter(GatewayResponseCacheEntry.ttl_expires_at > now)
        .count()
    )
    return {
        "short_circuit_enabled": is_inference_short_circuit_enabled(db),
        "active_cache_entries": int(active_entries),
    }
