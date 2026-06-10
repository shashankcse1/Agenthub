from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from agent_platform.api.dependencies import preview_decision_use_case
from agent_platform.api.security.auth import Principal, require_policy_role

router = APIRouter(prefix="/api/v1/policy", tags=["policy"])


class DecisionPreviewRequest(BaseModel):
    trace_id: str = Field(min_length=1)
    actor_id: str = Field(min_length=1)
    actor_role: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    action: str = Field(min_length=1)
    target: str = Field(min_length=1)


class DecisionPreviewResponse(BaseModel):
    outcome: str
    reason: str
    policy_trace_id: str
    policy_version: str

@router.post("/preview", response_model=DecisionPreviewResponse)
def preview_policy_decision(
    request: DecisionPreviewRequest,
    _: Principal = Depends(require_policy_role),
) -> DecisionPreviewResponse:
    decision = preview_decision_use_case.execute(
        trace_id=request.trace_id,
        actor_id=request.actor_id,
        actor_role=request.actor_role,
        tenant_id=request.tenant_id,
        environment=request.environment,
        action=request.action,
        target=request.target,
    )
    return DecisionPreviewResponse(
        outcome=decision.outcome.value,
        reason=decision.reason,
        policy_trace_id=decision.policy_trace_id,
        policy_version=decision.policy_version,
    )
