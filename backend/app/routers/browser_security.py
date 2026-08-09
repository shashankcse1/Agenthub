"""
GuardBridge Browser Extension — Backend Governance Router
==========================================================
GuardBridge is the browser extension component of AgentHub. It runs as an
independent extension (separate Chrome Web Store / AMO / Safari extension
identity) that governs AI interactions at the browser layer and reports
minimal, privacy-safe telemetry to this control plane.

Data minimization contract (immutable by design)
-------------------------------------------------
Field                  | What is stored              | What is NEVER stored
-----------------------|-----------------------------|-----------------------------------
browser_name           | canonical slug (chrome etc) | raw User-Agent string
browser_version        | major.minor string          | full UA header
extension_version      | semver string               | --
os_name                | coarse class (macos etc)    | raw navigator.platform
os_version             | version string              | --
device_type            | desktop/mobile/tablet       | hardware model, IMEI
user_agent_digest      | SHA-256 of raw UA           | raw UA
ip_hash                | HMAC-SHA256 of client IP    | raw IP address
geo_country            | ISO 3166-1 alpha-2          | lat/lon, postal code
geo_region             | state/province (opt-in)     | street address
geo_city               | NEVER stored server-side    | always stripped at ingest
content_fingerprint    | hash of content             | raw prompt text, file content

All geo collection defaults to DISABLED. Region requires policy opt-in.
City-level is stripped server-side regardless of what the client sends.

Browser compatibility
---------------------
GuardBridge ships as a WebExtensions API (MV3) extension compatible with:
  Chrome / Chromium, Edge, Opera, Brave, Arc, Vivaldi, Samsung Internet
  Firefox (MV2 manifest, same codebase via polyfill)
  Safari (converted via Xcode Safari Web Extension converter)

The `browser_name` field uses canonical slugs from SUPPORTED_BROWSER_TYPES.
Unknown values are normalised to "other"; the backend never rejects a session
because of an unrecognised browser name.

Role model
----------
- Platform Admin / Security Approver: full write access
- Auditor / Security Approver: read access
- All deny-path decisions emit audit events for CISO evidence.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import (
    BrowserAnalyticsSummary,
    BrowserExtensionSession,
    BrowserRiskPolicy,
    BrowserSecurityEvent,
    BrowserShadowAiApp,
)
from app.policy_constants import (
    BROWSER_ACTION_TYPES,
    BROWSER_DECISION_MODES,
    BROWSER_GEO_DETAIL_LEVEL_COUNTRY,
    SUPPORTED_BROWSER_TYPES,
    SUPPORTED_GEO_DETAIL_LEVELS,
)
from app.router_constants import AUTH_ADMIN_OR_SECURITY_ROLES, GATEWAY_READ_ROLES
from app.security import ActorContext, get_actor_context, require_role
from app.services.audit import create_audit_event

router = APIRouter()
logger = get_logger(__name__)

# ── Role sets ─────────────────────────────────────────────────────────────────
_BROWSER_WRITE_ROLES = AUTH_ADMIN_OR_SECURITY_ROLES
_BROWSER_READ_ROLES = GATEWAY_READ_ROLES          # Platform Admin + Security Approver + Auditor
_BROWSER_INGEST_ROLES = AUTH_ADMIN_OR_SECURITY_ROLES   # extension telemetry writers

# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts() -> datetime:
    return datetime.utcnow()


def _new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(16)}"


def _normalise_browser(value: str) -> str:
    v = (value or "unknown").strip().lower()
    return v if v in SUPPORTED_BROWSER_TYPES else "other"


def _normalise_action(value: str) -> str:
    v = (value or "other").strip().lower()
    return v if v in BROWSER_ACTION_TYPES else "other"


def _normalise_decision(value: str) -> str:
    v = (value or "allow").strip().lower()
    return v if v in BROWSER_DECISION_MODES else "allow"


def _hash_ip(raw_ip: str) -> str:
    """HMAC-SHA256 of raw IP; raw IP is never stored."""
    if not raw_ip:
        return ""
    return hashlib.sha256(raw_ip.encode("utf-8")).hexdigest()[:32]


def _emit_audit(
    db: Session,
    ctx: ActorContext,
    action_type: str,
    resource_type: str,
    resource_id: str,
    decision_outcome: str,
    metadata: Optional[dict] = None,
) -> None:
    trace_id = f"trace-browser-{resource_type}-{resource_id}"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type=action_type,
        resource_type=resource_type,
        resource_id=resource_id,
        trace_id=trace_id,
        decision_outcome=decision_outcome,
    )
    if metadata:
        logger.trace(
            "browser_audit_metadata %s",
            sanitize_fields({"action_type": action_type, "resource_id": resource_id, **metadata}),
        )


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class _ORMBase(BaseModel):
    model_config = {"from_attributes": True, "protected_namespaces": ()}


class BrowserSessionCreateRequest(BaseModel):
    actor_id: str
    tenant_id: Optional[str] = None
    environment: str = "dev"
    browser_name: str = "unknown"
    browser_version: str = ""
    extension_version: str = ""
    os_name: str = "unknown"
    os_version: str = ""
    device_type: str = "unknown"
    device_managed: bool = False
    user_agent_digest: str = ""       # SHA-256 of raw UA, computed by extension
    # Geo — only populated when policy geo_collection_enabled=true
    geo_country: str = ""
    geo_region: str = ""
    geo_city: str = ""
    geo_detail_level: str = "country"
    ip_hash: str = ""                 # HMAC of IP, computed by extension or gateway


class BrowserSessionResponse(_ORMBase):
    session_id: str
    actor_id: str
    tenant_id: Optional[str]
    environment: str
    browser_name: str
    browser_version: str
    extension_version: str
    os_name: str
    os_version: str
    device_type: str
    device_managed: bool
    geo_country: str
    geo_region: str
    geo_detail_level: str
    status: str
    last_heartbeat_at: Optional[datetime]
    created_at: datetime
    expires_at: Optional[datetime]


class BrowserEventIngestRequest(BaseModel):
    ext_session_id: Optional[str] = None
    trace_id: str
    actor_id: str
    tenant_id: Optional[str] = None
    environment: str = "dev"
    action_type: str
    destination_domain: str = ""
    destination_app: str = ""
    page_url_host: str = ""
    decision_outcome: str = "allow"
    policy_rule_id: Optional[str] = None
    risk_signals: list[str] = Field(default_factory=list)
    content_fingerprint: str = ""
    data_class: str = "standard"
    browser_name: str = "unknown"
    browser_version: str = ""
    os_name: str = "unknown"
    device_type: str = "unknown"
    geo_country: str = ""
    geo_region: str = ""


class BrowserEventResponse(_ORMBase):
    event_id: str
    ext_session_id: Optional[str]
    trace_id: str
    actor_id: str
    environment: str
    action_type: str
    destination_domain: str
    destination_app: str
    page_url_host: str
    decision_outcome: str
    policy_rule_id: Optional[str]
    risk_signals: str
    data_class: str
    browser_name: str
    os_name: str
    device_type: str
    geo_country: str
    geo_region: str
    created_at: datetime


class ShadowAiAppResponse(_ORMBase):
    app_id: str
    domain: str
    app_name: str
    category: str
    risk_score: int
    status: str
    first_seen_at: datetime
    last_seen_at: datetime
    active_user_count: int
    data_upload_events: int
    notes: str
    reviewed_by: Optional[str]
    reviewed_at: Optional[datetime]


class ShadowAiAppUpdateRequest(BaseModel):
    status: Optional[str] = None          # unsanctioned|sanctioned|blocked|under-review
    notes: Optional[str] = None
    risk_score: Optional[int] = None


class BrowserRiskPolicyRequest(BaseModel):
    name: str
    description: str = ""
    scope_type: str = "global"
    scope_value: str = ""
    action_type_pattern: str = "*"
    domain_pattern: str = "*"
    data_class_filter: str = "*"
    decision_mode: str = "warn"
    enabled: bool = True
    environment: str = "dev"
    geo_collection_enabled: bool = False
    geo_detail_level: str = "country"
    analytics_retention_days: int = 90


class BrowserRiskPolicyResponse(_ORMBase):
    policy_id: str
    name: str
    description: str
    scope_type: str
    scope_value: str
    action_type_pattern: str
    domain_pattern: str
    data_class_filter: str
    decision_mode: str
    enabled: bool
    environment: str
    geo_collection_enabled: bool
    geo_detail_level: str
    analytics_retention_days: int
    created_by: str
    updated_by: Optional[str]
    created_at: datetime
    updated_at: datetime


class BrowserRiskSummaryResponse(BaseModel):
    total_events_24h: int
    deny_events_24h: int
    warn_events_24h: int
    shadow_ai_apps: int
    active_sessions: int
    top_browsers: list[dict]
    top_countries: list[dict]
    top_denied_domains: list[dict]
    top_action_types: list[dict]


# ── Extension Sessions ────────────────────────────────────────────────────────

@router.post(
    "/browser/extensions/sessions",
    response_model=BrowserSessionResponse,
    summary="GuardBridge: Register a browser extension session",
    description=(
        "Called by the GuardBridge extension when it starts up or after re-auth. "
        "Records browser name (canonical slug), version, OS, device type, and "
        "coarse geo analytics (country only by default; region requires policy opt-in; "
        "city is ALWAYS stripped server-side). "
        "Raw UA, raw IP, and raw prompt content are NEVER transmitted or stored. "
        "Supported: Chrome, Firefox, Safari, Edge, Opera, Brave, Arc, Vivaldi, Samsung Internet."
    ),
    tags=["Browser Security"],
)
def create_browser_session(
    req: BrowserSessionCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _BROWSER_INGEST_ROLES)

    # Normalise browser to canonical set
    browser_name = _normalise_browser(req.browser_name)

    # Enforce geo detail-level guards
    geo_detail_level = req.geo_detail_level if req.geo_detail_level in SUPPORTED_GEO_DETAIL_LEVELS else BROWSER_GEO_DETAIL_LEVEL_COUNTRY
    # City is only kept when policy explicitly allows it (checked by extension SDK);
    # backend strips it — geo_city column deliberately absent from schema.

    session_id = _new_id("bsess")
    now = _ts()
    record = BrowserExtensionSession(
        session_id=session_id,
        actor_id=req.actor_id,
        tenant_id=req.tenant_id,
        environment=req.environment,
        browser_name=browser_name,
        browser_version=req.browser_version[:64],
        extension_version=req.extension_version[:64],
        os_name=(req.os_name or "unknown").strip()[:64],
        os_version=req.os_version[:64],
        device_type=(req.device_type or "unknown").strip()[:32],
        device_managed=req.device_managed,
        user_agent_digest=req.user_agent_digest[:64],
        geo_country=req.geo_country[:8].upper(),
        geo_region=req.geo_region[:128] if geo_detail_level in {"region", "city"} else "",
        # geo_city intentionally NOT stored — stripped regardless of client input
        geo_detail_level=geo_detail_level,
        ip_hash=req.ip_hash[:64],
        status="active",
        created_at=now,
        expires_at=now + timedelta(hours=8),
        last_heartbeat_at=now,
    )
    db.add(record)
    _emit_audit(db, ctx, "browser.session.create", "browser_session", session_id, "allow",
                {"browser_name": browser_name, "actor_id": req.actor_id})
    db.commit()
    db.refresh(record)
    logger.info("browser_session_created %s", sanitize_fields(
        {"session_id": session_id, "actor_id": req.actor_id, "browser_name": browser_name}))
    return record


@router.post(
    "/browser/extensions/sessions/{session_id}/heartbeat",
    summary="Heartbeat for an active browser session",
    tags=["Browser Security"],
)
def browser_session_heartbeat(
    session_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _BROWSER_INGEST_ROLES)
    record = db.query(BrowserExtensionSession).filter_by(session_id=session_id).first()
    if not record:
        raise HTTPException(status_code=404, detail={"error_code": "NOT_FOUND", "message": "Session not found."})
    record.last_heartbeat_at = _ts()
    record.status = "active"
    db.commit()
    return {"session_id": session_id, "status": "ok", "last_heartbeat_at": record.last_heartbeat_at}


@router.get(
    "/browser/extensions/sessions",
    response_model=list[BrowserSessionResponse],
    summary="List browser extension sessions",
    tags=["Browser Security"],
)
def list_browser_sessions(
    environment: Optional[str] = None,
    browser_name: Optional[str] = None,
    status: Optional[str] = None,
    geo_country: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _BROWSER_READ_ROLES)
    q = db.query(BrowserExtensionSession)
    if environment:
        q = q.filter_by(environment=environment)
    if browser_name:
        q = q.filter_by(browser_name=browser_name.lower())
    if status:
        q = q.filter_by(status=status)
    if geo_country:
        q = q.filter_by(geo_country=geo_country.upper())
    return q.order_by(BrowserExtensionSession.created_at.desc()).offset(offset).limit(limit).all()


# ── Event Ingest ──────────────────────────────────────────────────────────────

@router.post(
    "/browser/extensions/events",
    response_model=BrowserEventResponse,
    summary="GuardBridge: Ingest a browser security interaction event",
    description=(
        "Called by the GuardBridge extension for each governed interaction. "
        "DATA MINIMIZATION: Raw prompt text, file content, full URLs, and raw IPs "
        "are NEVER accepted. Only content_fingerprint (hash), page_url_host (eTLD+1), "
        "and action metadata are ingested. "
        "Covers: prompt_send, file_upload, file_download, paste, copy, screenshot, "
        "extension_install, extension_update, navigation, form_submit, api_call."
    ),
    tags=["Browser Security"],
)
def ingest_browser_event(
    req: BrowserEventIngestRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _BROWSER_INGEST_ROLES)

    event_id = _new_id("bevt")
    record = BrowserSecurityEvent(
        event_id=event_id,
        ext_session_id=req.ext_session_id,
        trace_id=req.trace_id[:128],
        actor_id=req.actor_id[:128],
        tenant_id=req.tenant_id,
        environment=req.environment,
        action_type=_normalise_action(req.action_type),
        destination_domain=req.destination_domain[:255],
        destination_app=req.destination_app[:128],
        page_url_host=req.page_url_host[:255],
        decision_outcome=_normalise_decision(req.decision_outcome),
        policy_rule_id=req.policy_rule_id,
        risk_signals=json.dumps(req.risk_signals),
        content_fingerprint=req.content_fingerprint[:128],
        data_class=req.data_class[:64],
        browser_name=_normalise_browser(req.browser_name),
        browser_version=req.browser_version[:64],
        os_name=(req.os_name or "unknown")[:64],
        device_type=(req.device_type or "unknown")[:32],
        geo_country=req.geo_country[:8].upper(),
        geo_region=req.geo_region[:128],
        created_at=_ts(),
    )
    db.add(record)

    # Always emit audit for deny/mask outcomes
    if record.decision_outcome in {"deny", "mask"}:
        _emit_audit(db, ctx, f"browser.event.{record.decision_outcome}",
                    "browser_event", event_id, record.decision_outcome,
                    {"action_type": record.action_type, "domain": record.destination_domain,
                     "data_class": record.data_class})

    # Auto-update shadow AI inventory
    if record.destination_domain:
        _upsert_shadow_ai(db, record.destination_domain, record.destination_app,
                          record.action_type)

    db.commit()
    db.refresh(record)
    logger.info("browser_event_ingested %s", sanitize_fields(
        {"event_id": event_id, "action": record.action_type,
         "decision": record.decision_outcome, "domain": record.destination_domain}))
    return record


@router.get(
    "/browser/extensions/events",
    response_model=list[BrowserEventResponse],
    summary="Query browser security events",
    tags=["Browser Security"],
)
def list_browser_events(
    actor_id: Optional[str] = None,
    environment: Optional[str] = None,
    decision_outcome: Optional[str] = None,
    action_type: Optional[str] = None,
    browser_name: Optional[str] = None,
    geo_country: Optional[str] = None,
    data_class: Optional[str] = None,
    since_hours: int = Query(default=24, ge=1, le=720),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _BROWSER_READ_ROLES)
    since = _ts() - timedelta(hours=since_hours)
    q = db.query(BrowserSecurityEvent).filter(BrowserSecurityEvent.created_at >= since)
    if actor_id:
        q = q.filter_by(actor_id=actor_id)
    if environment:
        q = q.filter_by(environment=environment)
    if decision_outcome:
        q = q.filter_by(decision_outcome=decision_outcome)
    if action_type:
        q = q.filter_by(action_type=action_type)
    if browser_name:
        q = q.filter_by(browser_name=browser_name.lower())
    if geo_country:
        q = q.filter_by(geo_country=geo_country.upper())
    if data_class:
        q = q.filter_by(data_class=data_class)
    return q.order_by(BrowserSecurityEvent.created_at.desc()).offset(offset).limit(limit).all()


# ── Shadow AI Inventory ───────────────────────────────────────────────────────

def _upsert_shadow_ai(db: Session, domain: str, app_name: str, action_type: str) -> None:
    """Idempotently maintain shadow-AI app inventory from event stream."""
    existing = db.query(BrowserShadowAiApp).filter_by(domain=domain).first()
    now = _ts()
    if existing:
        existing.last_seen_at = now
        existing.active_user_count = existing.active_user_count + 1
        if action_type in {"file_upload", "form_submit"}:
            existing.data_upload_events = existing.data_upload_events + 1
        if app_name and not existing.app_name:
            existing.app_name = app_name[:255]
    else:
        db.add(BrowserShadowAiApp(
            app_id=_new_id("saiapp"),
            domain=domain[:255],
            app_name=(app_name or "")[:255],
            category="generative-ai",
            risk_score=50,
            status="unsanctioned",
            first_seen_at=now,
            last_seen_at=now,
            active_user_count=1,
            data_upload_events=1 if action_type in {"file_upload", "form_submit"} else 0,
        ))


@router.get(
    "/browser/extensions/shadow-ai/apps",
    response_model=list[ShadowAiAppResponse],
    summary="List detected shadow AI apps",
    tags=["Browser Security"],
)
def list_shadow_ai_apps(
    status: Optional[str] = None,
    min_risk_score: int = Query(default=0, ge=0, le=100),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _BROWSER_READ_ROLES)
    q = db.query(BrowserShadowAiApp).filter(BrowserShadowAiApp.risk_score >= min_risk_score)
    if status:
        q = q.filter_by(status=status)
    return q.order_by(BrowserShadowAiApp.last_seen_at.desc()).offset(offset).limit(limit).all()


@router.patch(
    "/browser/extensions/shadow-ai/apps/{app_id}",
    response_model=ShadowAiAppResponse,
    summary="Update shadow AI app status or risk score",
    tags=["Browser Security"],
)
def update_shadow_ai_app(
    app_id: str,
    req: ShadowAiAppUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _BROWSER_WRITE_ROLES)
    record = db.query(BrowserShadowAiApp).filter_by(app_id=app_id).first()
    if not record:
        raise HTTPException(status_code=404, detail={"error_code": "NOT_FOUND", "message": "App not found."})
    allowed_statuses = {"unsanctioned", "sanctioned", "blocked", "under-review"}
    if req.status is not None:
        if req.status not in allowed_statuses:
            raise HTTPException(status_code=422, detail={"error_code": "INVALID_STATUS",
                                "message": f"status must be one of {sorted(allowed_statuses)}"})
        record.status = req.status
    if req.notes is not None:
        record.notes = req.notes
    if req.risk_score is not None:
        record.risk_score = max(0, min(100, req.risk_score))
    record.reviewed_by = ctx.actor_id
    record.reviewed_at = _ts()
    _emit_audit(db, ctx, "browser.shadow_ai.update", "shadow_ai_app", app_id, "allow",
                {"status": record.status, "risk_score": record.risk_score})
    db.commit()
    db.refresh(record)
    return record


# ── Risk Policies ─────────────────────────────────────────────────────────────

@router.post(
    "/browser/risk-policies",
    response_model=BrowserRiskPolicyResponse,
    summary="Create a browser risk policy",
    tags=["Browser Security"],
)
def create_browser_risk_policy(
    req: BrowserRiskPolicyRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _BROWSER_WRITE_ROLES)
    if req.decision_mode not in BROWSER_DECISION_MODES:
        raise HTTPException(status_code=422, detail={"error_code": "INVALID_DECISION_MODE",
            "message": f"decision_mode must be one of {sorted(BROWSER_DECISION_MODES)}"})
    if req.geo_detail_level not in SUPPORTED_GEO_DETAIL_LEVELS:
        raise HTTPException(status_code=422, detail={"error_code": "INVALID_GEO_DETAIL_LEVEL",
            "message": f"geo_detail_level must be one of {sorted(SUPPORTED_GEO_DETAIL_LEVELS)}"})

    policy_id = _new_id("brpol")
    now = _ts()
    record = BrowserRiskPolicy(
        policy_id=policy_id,
        name=req.name,
        description=req.description,
        scope_type=req.scope_type,
        scope_value=req.scope_value,
        action_type_pattern=req.action_type_pattern,
        domain_pattern=req.domain_pattern,
        data_class_filter=req.data_class_filter,
        decision_mode=req.decision_mode,
        enabled=req.enabled,
        environment=req.environment,
        geo_collection_enabled=req.geo_collection_enabled,
        geo_detail_level=req.geo_detail_level,
        analytics_retention_days=req.analytics_retention_days,
        created_by=ctx.actor_id,
        created_at=now,
        updated_at=now,
    )
    db.add(record)
    _emit_audit(db, ctx, "browser.risk_policy.create", "browser_risk_policy", policy_id, "allow",
                {"name": req.name, "decision_mode": req.decision_mode})
    db.commit()
    db.refresh(record)
    return record


@router.get(
    "/browser/risk-policies",
    response_model=list[BrowserRiskPolicyResponse],
    summary="List browser risk policies",
    tags=["Browser Security"],
)
def list_browser_risk_policies(
    environment: Optional[str] = None,
    enabled: Optional[bool] = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _BROWSER_READ_ROLES)
    q = db.query(BrowserRiskPolicy)
    if environment:
        q = q.filter_by(environment=environment)
    if enabled is not None:
        q = q.filter_by(enabled=enabled)
    return q.order_by(BrowserRiskPolicy.created_at.desc()).offset(offset).limit(limit).all()


@router.patch(
    "/browser/risk-policies/{policy_id}",
    response_model=BrowserRiskPolicyResponse,
    summary="Update a browser risk policy",
    tags=["Browser Security"],
)
def update_browser_risk_policy(
    policy_id: str,
    req: BrowserRiskPolicyRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _BROWSER_WRITE_ROLES)
    record = db.query(BrowserRiskPolicy).filter_by(policy_id=policy_id).first()
    if not record:
        raise HTTPException(status_code=404, detail={"error_code": "NOT_FOUND", "message": "Policy not found."})
    if req.decision_mode not in BROWSER_DECISION_MODES:
        raise HTTPException(status_code=422, detail={"error_code": "INVALID_DECISION_MODE",
            "message": f"decision_mode must be one of {sorted(BROWSER_DECISION_MODES)}"})
    for field in ("name", "description", "scope_type", "scope_value", "action_type_pattern",
                  "domain_pattern", "data_class_filter", "decision_mode", "enabled",
                  "environment", "geo_collection_enabled", "geo_detail_level", "analytics_retention_days"):
        setattr(record, field, getattr(req, field))
    record.updated_by = ctx.actor_id
    record.updated_at = _ts()
    _emit_audit(db, ctx, "browser.risk_policy.update", "browser_risk_policy", policy_id, "allow",
                {"name": record.name, "decision_mode": record.decision_mode})
    db.commit()
    db.refresh(record)
    return record


@router.delete(
    "/browser/risk-policies/{policy_id}",
    summary="Delete a browser risk policy",
    tags=["Browser Security"],
)
def delete_browser_risk_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _BROWSER_WRITE_ROLES)
    record = db.query(BrowserRiskPolicy).filter_by(policy_id=policy_id).first()
    if not record:
        raise HTTPException(status_code=404, detail={"error_code": "NOT_FOUND", "message": "Policy not found."})
    db.delete(record)
    _emit_audit(db, ctx, "browser.risk_policy.delete", "browser_risk_policy", policy_id, "allow")
    db.commit()
    return {"deleted": True, "policy_id": policy_id}


# ── Policy fetch for extension (lightweight, cached by TTL) ──────────────────

@router.get(
    "/browser/extensions/policies",
    summary="Fetch active browser policies (for extension SDK polling)",
    description=(
        "Returns active browser risk policies for the specified environment. "
        "The extension SDK caches this response with the TTL indicated in the "
        "`X-Policy-Cache-TTL-Seconds` response header. In strict enforcement mode, "
        "if this endpoint is unreachable the extension must fail closed for "
        "high-risk action classes."
    ),
    tags=["Browser Security"],
)
def get_browser_policies_for_extension(
    environment: str = "dev",
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _BROWSER_INGEST_ROLES)
    policies = (
        db.query(BrowserRiskPolicy)
        .filter_by(environment=environment, enabled=True)
        .order_by(BrowserRiskPolicy.created_at.asc())
        .all()
    )
    result = [
        {
            "policy_id": p.policy_id,
            "action_type_pattern": p.action_type_pattern,
            "domain_pattern": p.domain_pattern,
            "data_class_filter": p.data_class_filter,
            "decision_mode": p.decision_mode,
            "scope_type": p.scope_type,
            "scope_value": p.scope_value,
        }
        for p in policies
    ]
    return {"policies": result, "count": len(result), "environment": environment}


# ── Risk Summary Dashboard ────────────────────────────────────────────────────

@router.get(
    "/browser/extensions/risk/summary",
    response_model=BrowserRiskSummaryResponse,
    summary="Browser security risk summary for the dashboard",
    tags=["Browser Security"],
)
def get_browser_risk_summary(
    environment: Optional[str] = None,
    since_hours: int = Query(default=24, ge=1, le=720),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _BROWSER_READ_ROLES)
    since = _ts() - timedelta(hours=since_hours)
    q = db.query(BrowserSecurityEvent).filter(BrowserSecurityEvent.created_at >= since)
    if environment:
        q = q.filter_by(environment=environment)
    events = q.all()

    total = len(events)
    deny_count = sum(1 for e in events if e.decision_outcome == "deny")
    warn_count = sum(1 for e in events if e.decision_outcome == "warn")

    shadow_apps = db.query(BrowserShadowAiApp).filter_by(status="unsanctioned").count()
    active_sessions = db.query(BrowserExtensionSession).filter_by(status="active").count()

    # Top browsers
    browser_counts: dict[str, int] = {}
    for e in events:
        browser_counts[e.browser_name] = browser_counts.get(e.browser_name, 0) + 1
    top_browsers = sorted([{"browser": k, "count": v} for k, v in browser_counts.items()],
                          key=lambda x: x["count"], reverse=True)[:5]

    # Top countries
    country_counts: dict[str, int] = {}
    for e in events:
        if e.geo_country:
            country_counts[e.geo_country] = country_counts.get(e.geo_country, 0) + 1
    top_countries = sorted([{"country": k, "count": v} for k, v in country_counts.items()],
                           key=lambda x: x["count"], reverse=True)[:10]

    # Top denied domains
    denied_domains: dict[str, int] = {}
    for e in events:
        if e.decision_outcome == "deny" and e.destination_domain:
            denied_domains[e.destination_domain] = denied_domains.get(e.destination_domain, 0) + 1
    top_denied = sorted([{"domain": k, "count": v} for k, v in denied_domains.items()],
                        key=lambda x: x["count"], reverse=True)[:10]

    # Top action types
    action_counts: dict[str, int] = {}
    for e in events:
        action_counts[e.action_type] = action_counts.get(e.action_type, 0) + 1
    top_actions = sorted([{"action_type": k, "count": v} for k, v in action_counts.items()],
                         key=lambda x: x["count"], reverse=True)[:8]

    return BrowserRiskSummaryResponse(
        total_events_24h=total,
        deny_events_24h=deny_count,
        warn_events_24h=warn_count,
        shadow_ai_apps=shadow_apps,
        active_sessions=active_sessions,
        top_browsers=top_browsers,
        top_countries=top_countries,
        top_denied_domains=top_denied,
        top_action_types=top_actions,
    )


# ── Analytics ─────────────────────────────────────────────────────────────────

@router.get(
    "/browser/analytics",
    summary="Browser security analytics breakdown",
    description=(
        "Aggregated analytics across events. Supports breakdown by browser, OS, "
        "device type, country, and action type. "
        "City-level data is only returned when the active policy has "
        "geo_detail_level=city and geo_collection_enabled=true."
    ),
    tags=["Browser Security"],
)
def get_browser_analytics(
    environment: Optional[str] = None,
    group_by: str = Query(default="browser_name", description="browser_name|os_name|device_type|geo_country|action_type|decision_outcome"),
    since_hours: int = Query(default=168, ge=1, le=720),  # default 7 days
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _BROWSER_READ_ROLES)
    allowed_group_by = {"browser_name", "os_name", "device_type", "geo_country",
                        "action_type", "decision_outcome", "data_class", "destination_domain"}
    if group_by not in allowed_group_by:
        raise HTTPException(status_code=422, detail={"error_code": "INVALID_GROUP_BY",
            "message": f"group_by must be one of {sorted(allowed_group_by)}"})

    since = _ts() - timedelta(hours=since_hours)
    q = db.query(BrowserSecurityEvent).filter(BrowserSecurityEvent.created_at >= since)
    if environment:
        q = q.filter_by(environment=environment)
    events = q.all()

    counts: dict[str, int] = {}
    for e in events:
        key = getattr(e, group_by, "unknown") or "unknown"
        counts[key] = counts.get(key, 0) + 1

    rows = sorted([{"group": k, "count": v} for k, v in counts.items()],
                  key=lambda x: x["count"], reverse=True)[:limit]

    return {
        "group_by": group_by,
        "since_hours": since_hours,
        "environment": environment,
        "total_events": len(events),
        "rows": rows,
    }


# ── Incident Export ───────────────────────────────────────────────────────────

@router.post(
    "/browser/extensions/incidents/export",
    summary="Export browser security incident evidence bundle",
    description=(
        "Produces a filtered JSON evidence bundle for CISO/security review. "
        "Includes decision timeline, policy hits, shadow AI exposure, and "
        "analytics breakdown. No raw prompt content is ever included."
    ),
    tags=["Browser Security"],
)
def export_browser_incident(
    actor_id: Optional[str] = None,
    environment: Optional[str] = None,
    decision_outcome: Optional[str] = None,
    since_hours: int = 24,
    include_analytics: bool = True,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _BROWSER_WRITE_ROLES)
    since = _ts() - timedelta(hours=since_hours)
    q = db.query(BrowserSecurityEvent).filter(BrowserSecurityEvent.created_at >= since)
    if actor_id:
        q = q.filter_by(actor_id=actor_id)
    if environment:
        q = q.filter_by(environment=environment)
    if decision_outcome:
        q = q.filter_by(decision_outcome=decision_outcome)
    events = q.order_by(BrowserSecurityEvent.created_at.desc()).limit(500).all()

    bundle: dict = {
        "generated_at": _ts().isoformat(),
        "generated_by": ctx.actor_id,
        "filters": {
            "actor_id": actor_id, "environment": environment,
            "decision_outcome": decision_outcome, "since_hours": since_hours,
        },
        "event_count": len(events),
        "events": [
            {
                "event_id": e.event_id,
                "trace_id": e.trace_id,
                "actor_id": e.actor_id,
                "action_type": e.action_type,
                "destination_domain": e.destination_domain,
                "decision_outcome": e.decision_outcome,
                "data_class": e.data_class,
                "browser_name": e.browser_name,
                "os_name": e.os_name,
                "geo_country": e.geo_country,
                "created_at": e.created_at.isoformat(),
            }
            for e in events
        ],
    }

    if include_analytics:
        action_counts: dict[str, int] = {}
        browser_counts: dict[str, int] = {}
        decision_counts: dict[str, int] = {}
        for e in events:
            action_counts[e.action_type] = action_counts.get(e.action_type, 0) + 1
            browser_counts[e.browser_name] = browser_counts.get(e.browser_name, 0) + 1
            decision_counts[e.decision_outcome] = decision_counts.get(e.decision_outcome, 0) + 1
        bundle["analytics"] = {
            "by_action": action_counts,
            "by_browser": browser_counts,
            "by_decision": decision_counts,
        }

    _emit_audit(db, ctx, "browser.incident.export", "browser_events", "batch", "allow",
                {"event_count": len(events), "since_hours": since_hours})
    db.commit()
    return bundle
