from typing import List

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from agent_platform.api.dependencies import evidence_adapter
from agent_platform.api.security.auth import Principal, require_evidence_role

router = APIRouter(prefix="/api/v1/evidence", tags=["evidence"])


class AuditEventResponse(BaseModel):
    created_at: str
    prev_event_hash: str
    event_hash: str
    event_type: str
    decision_description: str
    trace_id: str
    actor_fingerprint: str
    tenant_id: str
    action: str
    target_scope: str
    target_fingerprint: str
    outcome: str
    reason: str
    policy_trace_id: str
    policy_version: str
    pii_redaction: str


class EvidenceBundleResponse(BaseModel):
    exported_by: str
    exporter_role: str
    event_count: int
    signature_algorithm: str
    chain_head: str
    signature: str
    events: List[AuditEventResponse]


class EvidenceVerificationRequest(BaseModel):
    exported_by: str
    exporter_role: str
    event_count: int
    signature_algorithm: str
    chain_head: str
    signature: str
    events: List[AuditEventResponse]


class EvidenceVerificationResponse(BaseModel):
    valid: bool


@router.get("/events", response_model=List[AuditEventResponse])
def list_evidence_events(
    limit: int = Query(default=100, ge=1, le=500),
    _: Principal = Depends(require_evidence_role),
) -> List[AuditEventResponse]:
    return [AuditEventResponse(**event.__dict__) for event in evidence_adapter.list_audit_events(limit=limit)]


@router.post("/export", response_model=EvidenceBundleResponse)
def export_evidence_bundle(
    limit: int = Query(default=100, ge=1, le=500),
    principal: Principal = Depends(require_evidence_role),
) -> EvidenceBundleResponse:
    bundle = evidence_adapter.export_evidence_bundle(
        exported_by=principal.username,
        exporter_role=principal.role,
        limit=limit,
    )
    return EvidenceBundleResponse(
        exported_by=bundle.exported_by,
        exporter_role=bundle.exporter_role,
        event_count=bundle.event_count,
        signature_algorithm=bundle.signature_algorithm,
        chain_head=bundle.chain_head,
        signature=bundle.signature,
        events=[AuditEventResponse(**event.__dict__) for event in bundle.events],
    )


@router.post("/verify", response_model=EvidenceVerificationResponse)
def verify_evidence_bundle(
    request: EvidenceVerificationRequest,
    _: Principal = Depends(require_evidence_role),
) -> EvidenceVerificationResponse:
    from agent_platform.domain.model.audit_event import AuditEvent
    from agent_platform.domain.model.evidence_bundle import EvidenceBundle

    bundle = EvidenceBundle(
        exported_by=request.exported_by,
        exporter_role=request.exporter_role,
        event_count=request.event_count,
        signature_algorithm=request.signature_algorithm,
        chain_head=request.chain_head,
        signature=request.signature,
        events=[AuditEvent(**event.model_dump()) for event in request.events],
    )
    return EvidenceVerificationResponse(valid=evidence_adapter.verify_evidence_bundle(bundle))