"""add control mapping, session controls, route draft evidence, readiness signature fields

Revision ID: 0007_ctrl_sess_rd
Revises: 0006_scale_cert
Create Date: 2026-06-04
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0007_ctrl_sess_rd"
down_revision: Union[str, None] = "0006_scale_cert"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _column_names(inspector: sa.Inspector, table_name: str) -> set[str]:
    return {col["name"] for col in inspector.get_columns(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("sessions"):
        cols = _column_names(inspector, "sessions")
        if "last_activity_at" not in cols:
            op.add_column("sessions", sa.Column("last_activity_at", sa.DateTime(), nullable=True))
            op.execute("UPDATE sessions SET last_activity_at = created_at WHERE last_activity_at IS NULL")
            op.alter_column("sessions", "last_activity_at", nullable=False)
        if "idle_timeout_minutes" not in cols:
            op.add_column(
                "sessions",
                sa.Column("idle_timeout_minutes", sa.Integer(), nullable=False, server_default="30"),
            )
        if "mfa_verified_at" not in cols:
            op.add_column("sessions", sa.Column("mfa_verified_at", sa.DateTime(), nullable=True))

    if inspector.has_table("route_drafts"):
        cols = _column_names(inspector, "route_drafts")
        if "state_version" not in cols:
            op.add_column(
                "route_drafts",
                sa.Column("state_version", sa.Integer(), nullable=False, server_default="1"),
            )

    if inspector.has_table("route_draft_approval_events"):
        cols = _column_names(inspector, "route_draft_approval_events")
        if "state_from" not in cols:
            op.add_column(
                "route_draft_approval_events",
                sa.Column("state_from", sa.String(length=64), nullable=False, server_default="unknown"),
            )
        if "state_to" not in cols:
            op.add_column(
                "route_draft_approval_events",
                sa.Column("state_to", sa.String(length=64), nullable=False, server_default="unknown"),
            )
        if "evidence_refs" not in cols:
            op.add_column("route_draft_approval_events", sa.Column("evidence_refs", sa.Text(), nullable=True))
        if "change_window_id" not in cols:
            op.add_column("route_draft_approval_events", sa.Column("change_window_id", sa.String(length=128), nullable=True))
        if "risk_ticket_ref" not in cols:
            op.add_column("route_draft_approval_events", sa.Column("risk_ticket_ref", sa.String(length=128), nullable=True))
        if "occurred_at" not in cols:
            op.add_column("route_draft_approval_events", sa.Column("occurred_at", sa.DateTime(), nullable=True))
            op.execute("UPDATE route_draft_approval_events SET occurred_at = created_at WHERE occurred_at IS NULL")
            op.alter_column("route_draft_approval_events", "occurred_at", nullable=False)

    if inspector.has_table("scale_certification_runs"):
        cols = _column_names(inspector, "scale_certification_runs")
        if "integrity_hash" not in cols:
            op.add_column(
                "scale_certification_runs",
                sa.Column("integrity_hash", sa.String(length=255), nullable=False, server_default=""),
            )
        if "signature" not in cols:
            op.add_column(
                "scale_certification_runs",
                sa.Column("signature", sa.String(length=255), nullable=False, server_default=""),
            )
        if "override_applied" not in cols:
            op.add_column(
                "scale_certification_runs",
                sa.Column("override_applied", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            )
        if "override_reason" not in cols:
            op.add_column("scale_certification_runs", sa.Column("override_reason", sa.Text(), nullable=True))
        if "override_by" not in cols:
            op.add_column("scale_certification_runs", sa.Column("override_by", sa.String(length=128), nullable=True))
        if "override_at" not in cols:
            op.add_column("scale_certification_runs", sa.Column("override_at", sa.DateTime(), nullable=True))

    if not inspector.has_table("compliance_control_mappings"):
        op.create_table(
            "compliance_control_mappings",
            sa.Column("control_id", sa.String(length=128), nullable=False),
            sa.Column("control_family", sa.String(length=128), nullable=False),
            sa.Column("requirement_text", sa.Text(), nullable=False),
            sa.Column("applicable_components", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("required_evidence_types", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("automation_status", sa.String(length=64), nullable=False, server_default="manual"),
            sa.Column("owner_team", sa.String(length=255), nullable=False),
            sa.Column("review_frequency", sa.String(length=64), nullable=False, server_default="quarterly"),
            sa.PrimaryKeyConstraint("control_id"),
        )

    indexes = {idx["name"] for idx in inspector.get_indexes("compliance_control_mappings")}
    if "ix_compliance_control_mappings_family" not in indexes:
        op.create_index(
            "ix_compliance_control_mappings_family",
            "compliance_control_mappings",
            ["control_family", "owner_team"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("compliance_control_mappings"):
        indexes = {idx["name"] for idx in inspector.get_indexes("compliance_control_mappings")}
        if "ix_compliance_control_mappings_family" in indexes:
            op.drop_index("ix_compliance_control_mappings_family", table_name="compliance_control_mappings")
        op.drop_table("compliance_control_mappings")
