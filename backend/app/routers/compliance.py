from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.api_errors import conflict_error, not_found_error, validation_error as api_validation_error
from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import AuditEvent, ComplianceControlMapping, ComplianceEvidenceArtifact, LegalHold, RetentionPolicy
from app.router_constants import COMPLIANCE_READ_ROLES, COMPLIANCE_WRITE_ROLES
from app.schemas import (
    ComplianceControlMappingResponse,
    ComplianceControlMappingUpsertRequest,
    ComplianceControlCoverageSummaryResponse,
    ComplianceControlResponse,
    ComplianceEvidenceArtifactResponse,
    ComplianceEvidenceBundleResponse,
    ComplianceEvidenceExportRequest,
    ComplianceEvidenceExportResponse,
    ComplianceEvidenceFreshnessSummaryResponse,
    ComplianceEvidenceGenerateRequest,
    ComplianceEvidenceResponse,
    LegalHoldCreateRequest,
    LegalHoldReleaseRequest,
    LegalHoldResponse,
    RetentionPolicyCreateRequest,
    RetentionPolicyResponse,
    RetentionPolicyUpdateRequest,
)
from app.security import ActorContext, get_actor_context, require_role
from app.services.audit import create_audit_event
from app.services.compliance_controls import get_control_catalog, get_default_control_mappings, known_control_ids
from app.services.control_coverage import build_route_coverage, unknown_referenced_control_ids

router = APIRouter()
logger = get_logger(__name__)


def _ensure_default_control_mappings(db: Session) -> None:
    existing_ids = {row[0] for row in db.query(ComplianceControlMapping.control_id).all()}
    for control_id, payload in get_default_control_mappings(db).items():
        if control_id in existing_ids:
            continue
        db.add(ComplianceControlMapping(control_id=control_id, **payload))
    db.flush()


def _control_exists(db: Session, control_id: str, catalog: dict[str, str]) -> bool:
    if control_id in catalog:
        return True
    return db.query(ComplianceControlMapping).filter_by(control_id=control_id).first() is not None


@router.get("/compliance/controls", response_model=list[ComplianceControlResponse])
def list_controls(db: Session = Depends(get_db), ctx: ActorContext = Depends(get_actor_context)):
    require_role(ctx, COMPLIANCE_READ_ROLES)
    _ensure_default_control_mappings(db)
    catalog = get_control_catalog(db)
    audit_count = db.query(AuditEvent).count()
    artifact_count = db.query(ComplianceEvidenceArtifact).count()
    evidence_count = audit_count + artifact_count
    status = "pass" if evidence_count > 0 else "needs_evidence"

    controls = db.query(ComplianceControlMapping).order_by(ComplianceControlMapping.control_id.asc()).all()
    return [
        {
            "control_id": control.control_id,
            "title": catalog.get(control.control_id, control.requirement_text),
            "status": status,
            "evidence_count": evidence_count,
        }
        for control in controls
    ]


@router.get("/compliance/evidence/{control_id}", response_model=ComplianceEvidenceResponse)
def get_control_evidence(
    control_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, COMPLIANCE_READ_ROLES)
    catalog = get_control_catalog(db)
    if not _control_exists(db, control_id, catalog):
        raise not_found_error("compliance_control", control_id, decision_trace_id="compliance-control-not-found")

    recent_events = db.query(AuditEvent).order_by(AuditEvent.timestamp.desc()).limit(5).all()
    evidence_items = [
        f"{e.timestamp.isoformat()} {e.action_type} {e.resource_type}:{e.resource_id}"
        for e in recent_events
    ]

    return {
        "control_id": control_id,
        "generated_at": datetime.utcnow(),
        "evidence_items": evidence_items,
    }


@router.get("/compliance/controls/mappings", response_model=list[ComplianceControlMappingResponse])
def list_control_mappings(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, COMPLIANCE_READ_ROLES)
    _ensure_default_control_mappings(db)
    return db.query(ComplianceControlMapping).order_by(ComplianceControlMapping.control_id.asc()).all()


@router.get("/compliance/controls/coverage", response_model=ComplianceControlCoverageSummaryResponse)
def get_control_coverage_report(
    request: Request,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, COMPLIANCE_READ_ROLES)
    _ensure_default_control_mappings(db)
    report = build_route_coverage(request.app.routes)
    logger.info(
        "compliance_control_coverage_generated %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "total_routes": report["total_routes"],
                "uncovered_routes": report["uncovered_routes"],
            }
        ),
    )
    return {
        "generated_at": datetime.utcnow(),
        "total_routes": report["total_routes"],
        "covered_routes": report["covered_routes"],
        "uncovered_routes": report["uncovered_routes"],
        "unknown_control_ids": unknown_referenced_control_ids(known_control_ids(db)),
        "uncovered_paths": report["uncovered_paths"],
        "items": report["items"],
    }


@router.get("/compliance/controls/evidence-freshness", response_model=ComplianceEvidenceFreshnessSummaryResponse)
def get_control_evidence_freshness(
    freshness_slo_hours: int = Query(default=24, ge=1, le=168),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, COMPLIANCE_READ_ROLES)
    _ensure_default_control_mappings(db)

    controls = db.query(ComplianceControlMapping).order_by(ComplianceControlMapping.control_id.asc()).all()
    now = datetime.utcnow()
    freshness_cutoff = now - timedelta(hours=freshness_slo_hours)

    items = []
    passing = 0
    stale = 0
    missing = 0

    for control in controls:
        artifacts = (
            db.query(ComplianceEvidenceArtifact)
            .filter_by(control_id=control.control_id)
            .order_by(ComplianceEvidenceArtifact.generated_at.desc())
            .limit(1)
            .all()
        )
        if not artifacts:
            items.append(
                {
                    "control_id": control.control_id,
                    "status": "missing",
                    "freshness_slo_hours": freshness_slo_hours,
                    "evidence_count": 0,
                    "last_evidence_at": None,
                    "age_hours": None,
                }
            )
            missing += 1
            continue

        last = artifacts[0].generated_at
        age_hours = round((now - last).total_seconds() / 3600, 2)
        status = "pass" if last >= freshness_cutoff else "stale"
        if status == "pass":
            passing += 1
        else:
            stale += 1

        evidence_count = db.query(ComplianceEvidenceArtifact).filter_by(control_id=control.control_id).count()
        items.append(
            {
                "control_id": control.control_id,
                "status": status,
                "freshness_slo_hours": freshness_slo_hours,
                "evidence_count": evidence_count,
                "last_evidence_at": last,
                "age_hours": age_hours,
            }
        )

    return {
        "generated_at": now,
        "freshness_slo_hours": freshness_slo_hours,
        "total_controls": len(items),
        "controls_passing": passing,
        "controls_stale": stale,
        "controls_missing": missing,
        "items": items,
    }


@router.put("/compliance/controls/mappings/{control_id}", response_model=ComplianceControlMappingResponse)
def upsert_control_mapping(
    control_id: str,
    payload: ComplianceControlMappingUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, COMPLIANCE_WRITE_ROLES)
    control = db.query(ComplianceControlMapping).filter_by(control_id=control_id).first()
    if not control:
        control = ComplianceControlMapping(control_id=control_id, **payload.model_dump())
        db.add(control)
    else:
        for key, value in payload.model_dump().items():
            setattr(control, key, value)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="compliance.controls.mapping.upsert",
        resource_type="control_mapping",
        resource_id=control_id,
        trace_id=f"trace-control-mapping-{control_id}",
    )
    db.commit()
    db.refresh(control)
    return control


@router.post("/compliance/evidence/{control_id}/generate", response_model=ComplianceEvidenceArtifactResponse)
def generate_control_evidence(
    control_id: str,
    payload: ComplianceEvidenceGenerateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "compliance_evidence_generate_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "control_id": control_id}),
    )
    require_role(ctx, COMPLIANCE_READ_ROLES)
    catalog = get_control_catalog(db)
    if not _control_exists(db, control_id, catalog):
        logger.error("compliance_evidence_generate_control_not_found %s", sanitize_fields({"control_id": control_id}))
        raise not_found_error("compliance_control", control_id, decision_trace_id="compliance-control-not-found")

    trace_id = f"trace-evidence-{control_id}-{uuid4()}"
    artifact = ComplianceEvidenceArtifact(
        evidence_id=str(uuid4()),
        control_id=control_id,
        generated_by=ctx.actor_id,
        source_type=payload.source_type,
        source_id=payload.source_id,
        trace_id=trace_id,
        policy_version="v1",
        artifact_uri=f"evidence://controls/{control_id}/{uuid4()}",
        integrity_hash=f"sha256:{uuid4().hex}",
    )
    db.add(artifact)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="compliance.evidence.generate",
        resource_type="control",
        resource_id=control_id,
        trace_id=trace_id,
    )
    db.commit()
    db.refresh(artifact)
    logger.info(
        "compliance_evidence_generate_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "control_id": control_id, "evidence_id": artifact.evidence_id}),
    )
    return artifact


def _build_compliance_evidence_bundle(
    db: Session,
    *,
    control_id: str,
    since_hours: int,
    decision_outcome: Optional[str],
    action_type_prefix: Optional[str],
    tenant_id: Optional[str],
    environment: Optional[str],
    source_type: Optional[str],
    source_id_prefix: Optional[str],
    limit_events: int,
    limit_artifacts: int,
) -> dict:
    normalized_decision_outcome = (decision_outcome or "").strip().lower()
    if normalized_decision_outcome and normalized_decision_outcome not in {"allow", "deny", "warn"}:
        raise api_validation_error(
            "decision_outcome must be one of: allow, deny, warn",
            decision_trace_id="compliance-decision-outcome-invalid",
        )

    cutoff = datetime.utcnow() - timedelta(hours=since_hours)

    events_query = db.query(AuditEvent).filter(AuditEvent.timestamp >= cutoff)
    if normalized_decision_outcome:
        events_query = events_query.filter(AuditEvent.decision_outcome == normalized_decision_outcome)
    if action_type_prefix and action_type_prefix.strip():
        events_query = events_query.filter(AuditEvent.action_type.like(f"{action_type_prefix.strip()}%"))
    if tenant_id and tenant_id.strip():
        events_query = events_query.filter(AuditEvent.tenant_id == tenant_id.strip())
    if environment and environment.strip():
        events_query = events_query.filter(AuditEvent.environment == environment.strip())

    recent_events = events_query.order_by(AuditEvent.timestamp.desc()).limit(limit_events).all()

    artifacts_query = db.query(ComplianceEvidenceArtifact).filter_by(control_id=control_id)
    if source_type and source_type.strip():
        artifacts_query = artifacts_query.filter(ComplianceEvidenceArtifact.source_type == source_type.strip())
    if source_id_prefix and source_id_prefix.strip():
        artifacts_query = artifacts_query.filter(ComplianceEvidenceArtifact.source_id.like(f"{source_id_prefix.strip()}%"))

    artifacts = artifacts_query.order_by(ComplianceEvidenceArtifact.generated_at.desc()).limit(limit_artifacts).all()
    evidence_items = [
        f"{e.timestamp.isoformat()} {e.action_type} {e.resource_type}:{e.resource_id}"
        for e in recent_events
    ]
    artifact_count = len(artifacts)
    latest_artifact_at = artifacts[0].generated_at if artifacts else None
    malformed_integrity = any(not str(artifact.integrity_hash or "").startswith("sha256:") for artifact in artifacts)
    if malformed_integrity:
        raise conflict_error(
            "Evidence bundle integrity check failed",
            decision_trace_id="compliance-evidence-integrity-failed",
            remediation_hint="Regenerate the evidence bundle and retry export.",
        )

    return {
        "control_id": control_id,
        "generated_at": datetime.utcnow(),
        "evidence_items": evidence_items,
        "artifacts": artifacts,
        "artifact_count": artifact_count,
        "latest_artifact_at": latest_artifact_at,
        "integrity_status": "pass",
    }


@router.get(
    "/compliance/evidence/{control_id}/bundle",
    response_model=ComplianceEvidenceBundleResponse,
    summary="Retrieve compliance evidence bundle",
    description=(
        "Retrieves compliance evidence bundle drill-down for a control. "
        "Bundle retrieval supports scoped filters (time window, decision outcome, action prefix, tenant/environment, and artifact source filters), "
        "is integrity-guarded, and fails closed when artifact integrity hashes are malformed."
    ),
    responses={
        400: {"description": "Invalid bundle filter input."},
        404: {"description": "Control not found."},
        409: {"description": "Evidence bundle integrity check failed."},
    },
)
def get_control_evidence_bundle(
    control_id: str,
    since_hours: int = Query(default=24, ge=1, le=720),
    decision_outcome: Optional[str] = Query(default=None),
    action_type_prefix: Optional[str] = Query(default=None),
    tenant_id: Optional[str] = Query(default=None),
    environment: Optional[str] = Query(default=None),
    source_type: Optional[str] = Query(default=None),
    source_id_prefix: Optional[str] = Query(default=None),
    limit_events: int = Query(default=20, ge=1, le=200),
    limit_artifacts: int = Query(default=20, ge=1, le=200),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, COMPLIANCE_READ_ROLES)
    catalog = get_control_catalog(db)
    if not _control_exists(db, control_id, catalog):
        raise not_found_error("compliance_control", control_id, decision_trace_id="compliance-control-not-found")

    try:
        bundle = _build_compliance_evidence_bundle(
            db,
            control_id=control_id,
            since_hours=since_hours,
            decision_outcome=decision_outcome,
            action_type_prefix=action_type_prefix,
            tenant_id=tenant_id,
            environment=environment,
            source_type=source_type,
            source_id_prefix=source_id_prefix,
            limit_events=limit_events,
            limit_artifacts=limit_artifacts,
        )
    except HTTPException as exc:
        if exc.status_code == 409:
            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type="compliance.evidence.bundle.retrieve",
                resource_type="control",
                resource_id=control_id,
                trace_id=f"trace-evidence-bundle-{control_id}-{uuid4()}",
                decision_outcome="deny",
                tenant_id=tenant_id,
                environment=environment,
            )
            db.commit()
        raise

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="compliance.evidence.bundle.retrieve",
        resource_type="control",
        resource_id=control_id,
        trace_id=f"trace-evidence-bundle-{control_id}-{uuid4()}",
        decision_outcome="allow",
        tenant_id=tenant_id,
        environment=environment,
    )
    db.commit()
    return bundle


@router.post("/compliance/evidence/export", response_model=ComplianceEvidenceExportResponse)
def export_compliance_evidence(
    payload: ComplianceEvidenceExportRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, COMPLIANCE_READ_ROLES)
    control_id = str(payload.control_id).strip()
    catalog = get_control_catalog(db)
    if not _control_exists(db, control_id, catalog):
        trace_id = f"trace-compliance-export-deny-{uuid4()}"
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="compliance.evidence.export",
            resource_type="control",
            resource_id=control_id,
            trace_id=trace_id,
            decision_outcome="deny",
            tenant_id=payload.tenant_id,
            environment=payload.environment,
        )
        db.commit()
        raise not_found_error("compliance_control", control_id, decision_trace_id="compliance-control-not-found")

    export_id = str(uuid4())
    trace_id = f"trace-compliance-export-{export_id}"
    try:
        bundle = _build_compliance_evidence_bundle(
            db,
            control_id=control_id,
            since_hours=payload.since_hours,
            decision_outcome=payload.decision_outcome,
            action_type_prefix=payload.action_type_prefix,
            tenant_id=payload.tenant_id,
            environment=payload.environment,
            source_type=payload.source_type,
            source_id_prefix=payload.source_id_prefix,
            limit_events=payload.limit_events,
            limit_artifacts=payload.limit_artifacts,
        )
        if payload.investigation_context:
            bundle["investigation_context"] = payload.investigation_context
    except HTTPException as exc:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="compliance.evidence.export",
            resource_type="control",
            resource_id=control_id,
            trace_id=trace_id,
            decision_outcome="deny",
            tenant_id=payload.tenant_id,
            environment=payload.environment,
        )
        db.commit()
        raise

    audit_event = create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="compliance.evidence.export",
        resource_type="control",
        resource_id=control_id,
        trace_id=trace_id,
        decision_outcome="allow",
        tenant_id=payload.tenant_id,
        environment=payload.environment,
    )
    db.commit()

    return {
        "export_id": export_id,
        "exported_at": datetime.utcnow(),
        "control_id": control_id,
        "bundle": bundle,
        "audit_event": {
            "audit_event_id": audit_event.audit_event_id,
            "action_type": audit_event.action_type,
            "resource_type": audit_event.resource_type,
            "resource_id": audit_event.resource_id,
            "trace_id": audit_event.trace_id,
            "decision_outcome": audit_event.decision_outcome,
            "timestamp": audit_event.timestamp,
        },
        "investigation_context": payload.investigation_context,
    }


@router.get("/compliance/retention/policies", response_model=list[RetentionPolicyResponse])
def list_retention_policies(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, COMPLIANCE_READ_ROLES)
    return db.query(RetentionPolicy).order_by(RetentionPolicy.updated_at.desc()).all()


@router.post("/compliance/retention/policies", response_model=RetentionPolicyResponse)
def upsert_retention_policy(
    payload: RetentionPolicyCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, COMPLIANCE_WRITE_ROLES)

    policy = (
        db.query(RetentionPolicy)
        .filter_by(data_class=payload.data_class, jurisdiction=payload.jurisdiction)
        .first()
    )
    if not policy:
        policy = RetentionPolicy(
            policy_id=str(uuid4()),
            data_class=payload.data_class,
            jurisdiction=payload.jurisdiction,
            retention_days=payload.retention_days,
            deletion_mode=payload.deletion_mode,
            legal_hold_supported=payload.legal_hold_supported,
            updated_by=ctx.actor_id,
            updated_at=datetime.utcnow(),
        )
        db.add(policy)
    else:
        policy.retention_days = payload.retention_days
        policy.deletion_mode = payload.deletion_mode
        policy.legal_hold_supported = payload.legal_hold_supported
        policy.updated_by = ctx.actor_id
        policy.updated_at = datetime.utcnow()

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="compliance.retention_policy.upsert",
        resource_type="retention_policy",
        resource_id=f"{payload.data_class}:{payload.jurisdiction}",
        trace_id=f"trace-retention-{uuid4()}",
    )
    db.commit()
    db.refresh(policy)
    return policy


@router.patch("/compliance/retention/policies/{policy_id}", response_model=RetentionPolicyResponse)
def update_retention_policy(
    policy_id: str,
    payload: RetentionPolicyUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, COMPLIANCE_WRITE_ROLES)
    policy = db.query(RetentionPolicy).filter_by(policy_id=policy_id).first()
    if not policy:
        raise not_found_error("retention_policy", policy_id, decision_trace_id="compliance-retention-not-found")

    if payload.retention_days is not None:
        policy.retention_days = payload.retention_days
    if payload.deletion_mode is not None:
        policy.deletion_mode = payload.deletion_mode
    if payload.legal_hold_supported is not None:
        policy.legal_hold_supported = payload.legal_hold_supported
    if payload.status is not None:
        policy.status = payload.status
    policy.updated_by = ctx.actor_id
    policy.updated_at = datetime.utcnow()

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="compliance.retention_policy.update",
        resource_type="retention_policy",
        resource_id=policy_id,
        trace_id=f"trace-retention-update-{uuid4()}",
    )
    db.commit()
    db.refresh(policy)
    return policy


@router.get("/compliance/legal-holds", response_model=list[LegalHoldResponse])
def list_legal_holds(
    status: str = "active",
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, COMPLIANCE_READ_ROLES)
    query = db.query(LegalHold)
    if status != "all":
        query = query.filter_by(status=status)
    return query.order_by(LegalHold.placed_at.desc()).all()


@router.post("/compliance/legal-holds", response_model=LegalHoldResponse)
def place_legal_hold(
    payload: LegalHoldCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "compliance_legal_hold_place_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "scope_ref": payload.scope_ref}),
    )
    require_role(ctx, COMPLIANCE_WRITE_ROLES)

    hold = LegalHold(
        hold_id=str(uuid4()),
        data_class=payload.data_class,
        jurisdiction=payload.jurisdiction,
        reason=payload.reason,
        scope_ref=payload.scope_ref,
        status="active",
        placed_by=ctx.actor_id,
    )
    db.add(hold)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="compliance.legal_hold.place",
        resource_type="legal_hold",
        resource_id=hold.hold_id,
        trace_id=f"trace-legal-hold-place-{hold.hold_id}",
    )
    db.commit()
    db.refresh(hold)
    logger.info(
        "compliance_legal_hold_place_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "hold_id": hold.hold_id}),
    )
    return hold


@router.post("/compliance/legal-holds/{hold_id}/release", response_model=LegalHoldResponse)
def release_legal_hold(
    hold_id: str,
    payload: LegalHoldReleaseRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "compliance_legal_hold_release_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "hold_id": hold_id}),
    )
    require_role(ctx, COMPLIANCE_WRITE_ROLES)
    hold = db.query(LegalHold).filter_by(hold_id=hold_id).first()
    if not hold:
        logger.error("compliance_legal_hold_not_found %s", sanitize_fields({"hold_id": hold_id}))
        raise not_found_error("legal_hold", hold_id, decision_trace_id="compliance-legal-hold-not-found")
    if hold.status != "active":
        raise api_validation_error("Legal hold is not active", decision_trace_id="compliance-legal-hold-inactive")

    hold.status = "released"
    hold.released_by = ctx.actor_id
    hold.released_at = datetime.utcnow()

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="compliance.legal_hold.release",
        resource_type="legal_hold",
        resource_id=hold.hold_id,
        trace_id=f"trace-legal-hold-release-{hold.hold_id}",
    )
    db.commit()
    db.refresh(hold)
    logger.info(
        "compliance_legal_hold_release_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "hold_id": hold.hold_id}),
    )
    return hold
