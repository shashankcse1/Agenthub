"""orchestration IGA tables and staged approval state

Revision ID: 0038_orchestration_iga
Revises: 0037_orchestration_approval_gates
Create Date: 2026-06-13
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0038_orchestration_iga"
down_revision: Union[str, None] = "0037_orchestration_approval_gates"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("orchestration_flow_definitions"):
        columns = {col["name"] for col in inspector.get_columns("orchestration_flow_definitions")}
        if "approval_stage_state_json" not in columns:
            op.add_column(
                "orchestration_flow_definitions",
                sa.Column("approval_stage_state_json", sa.Text(), nullable=False, server_default="{}"),
            )

    if not inspector.has_table("orchestration_jit_access_requests"):
        op.create_table(
            "orchestration_jit_access_requests",
            sa.Column("request_id", sa.String(length=64), primary_key=True),
            sa.Column("flow_id", sa.String(length=64), nullable=False),
            sa.Column("requester_id", sa.String(length=128), nullable=False),
            sa.Column("requester_role", sa.String(length=128), nullable=False),
            sa.Column("requested_action", sa.String(length=32), nullable=False),
            sa.Column("justification", sa.Text(), nullable=False),
            sa.Column("environment", sa.String(length=64), nullable=False, server_default="dev"),
            sa.Column("requested_duration_minutes", sa.Integer(), nullable=False, server_default="60"),
            sa.Column("status", sa.String(length=64), nullable=False, server_default="requested"),
            sa.Column("approved_by", sa.String(length=128), nullable=True),
            sa.Column("approved_role", sa.String(length=128), nullable=True),
            sa.Column("approved_at", sa.DateTime(), nullable=True),
            sa.Column("expires_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index(
            "ix_orchestration_jit_status_env",
            "orchestration_jit_access_requests",
            ["status", "environment"],
        )
        op.create_index(
            "ix_orchestration_jit_flow_requester",
            "orchestration_jit_access_requests",
            ["flow_id", "requester_id"],
        )

    if not inspector.has_table("orchestration_flow_access_certifications"):
        op.create_table(
            "orchestration_flow_access_certifications",
            sa.Column("certification_id", sa.String(length=64), primary_key=True),
            sa.Column("flow_id", sa.String(length=64), nullable=False),
            sa.Column("certified_by", sa.String(length=128), nullable=False),
            sa.Column("approver_id", sa.String(length=128), nullable=True),
            sa.Column("certified_at", sa.DateTime(), nullable=False),
            sa.Column("next_due_at", sa.DateTime(), nullable=False),
            sa.Column("attestation_notes", sa.Text(), nullable=False, server_default=""),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        )
        op.create_index(
            "ix_orchestration_cert_flow_status",
            "orchestration_flow_access_certifications",
            ["flow_id", "status"],
        )
        op.create_index(
            "ix_orchestration_cert_next_due",
            "orchestration_flow_access_certifications",
            ["next_due_at", "status"],
        )

    if not inspector.has_table("orchestration_flow_approval_events"):
        op.create_table(
            "orchestration_flow_approval_events",
            sa.Column("approval_event_id", sa.String(length=64), primary_key=True),
            sa.Column("flow_id", sa.String(length=64), nullable=False),
            sa.Column("event_type", sa.String(length=64), nullable=False),
            sa.Column("stage_id", sa.String(length=128), nullable=True),
            sa.Column("action", sa.String(length=64), nullable=False),
            sa.Column("state_from", sa.String(length=64), nullable=False),
            sa.Column("state_to", sa.String(length=64), nullable=False),
            sa.Column("actor_id", sa.String(length=128), nullable=False),
            sa.Column("actor_role", sa.String(length=128), nullable=False),
            sa.Column("approver_id", sa.String(length=128), nullable=True),
            sa.Column("decision", sa.String(length=64), nullable=False),
            sa.Column("reason_code", sa.String(length=255), nullable=True),
            sa.Column("ticket_ref", sa.String(length=128), nullable=True),
            sa.Column("occurred_at", sa.DateTime(), nullable=False),
        )
        op.create_index(
            "ix_orchestration_approval_events_flow",
            "orchestration_flow_approval_events",
            ["flow_id", "occurred_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("orchestration_flow_approval_events"):
        op.drop_index("ix_orchestration_approval_events_flow", table_name="orchestration_flow_approval_events")
        op.drop_table("orchestration_flow_approval_events")

    if inspector.has_table("orchestration_flow_access_certifications"):
        op.drop_index("ix_orchestration_cert_next_due", table_name="orchestration_flow_access_certifications")
        op.drop_index("ix_orchestration_cert_flow_status", table_name="orchestration_flow_access_certifications")
        op.drop_table("orchestration_flow_access_certifications")

    if inspector.has_table("orchestration_jit_access_requests"):
        op.drop_index("ix_orchestration_jit_flow_requester", table_name="orchestration_jit_access_requests")
        op.drop_index("ix_orchestration_jit_status_env", table_name="orchestration_jit_access_requests")
        op.drop_table("orchestration_jit_access_requests")

    if inspector.has_table("orchestration_flow_definitions"):
        columns = {col["name"] for col in inspector.get_columns("orchestration_flow_definitions")}
        if "approval_stage_state_json" in columns:
            op.drop_column("orchestration_flow_definitions", "approval_stage_state_json")
