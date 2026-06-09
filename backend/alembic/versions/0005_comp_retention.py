"""add compliance retention, legal hold, and evidence artifact tables

Revision ID: 0005_comp_retention
Revises: 0004_rd_ppv
Create Date: 2026-06-04
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0005_comp_retention"
down_revision: Union[str, None] = "0004_rd_ppv"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("retention_policies"):
        op.create_table(
            "retention_policies",
            sa.Column("policy_id", sa.String(length=64), nullable=False),
            sa.Column("data_class", sa.String(length=128), nullable=False),
            sa.Column("jurisdiction", sa.String(length=64), nullable=False),
            sa.Column("retention_days", sa.Integer(), nullable=False),
            sa.Column("deletion_mode", sa.String(length=64), nullable=False, server_default="soft_delete"),
            sa.Column("legal_hold_supported", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("status", sa.String(length=64), nullable=False, server_default="active"),
            sa.Column("updated_by", sa.String(length=128), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("policy_id"),
        )
    if "ix_retention_policies_data_class_jurisdiction" not in {
        idx["name"] for idx in inspector.get_indexes("retention_policies")
    }:
        op.create_index(
            "ix_retention_policies_data_class_jurisdiction",
            "retention_policies",
            ["data_class", "jurisdiction"],
            unique=False,
        )

    if not inspector.has_table("legal_holds"):
        op.create_table(
            "legal_holds",
            sa.Column("hold_id", sa.String(length=64), nullable=False),
            sa.Column("data_class", sa.String(length=128), nullable=False),
            sa.Column("jurisdiction", sa.String(length=64), nullable=False),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("scope_ref", sa.String(length=255), nullable=False),
            sa.Column("status", sa.String(length=64), nullable=False, server_default="active"),
            sa.Column("placed_by", sa.String(length=128), nullable=False),
            sa.Column("placed_at", sa.DateTime(), nullable=False),
            sa.Column("released_by", sa.String(length=128), nullable=True),
            sa.Column("released_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("hold_id"),
        )
    if "ix_legal_holds_status_created" not in {idx["name"] for idx in inspector.get_indexes("legal_holds")}:
        op.create_index(
            "ix_legal_holds_status_created",
            "legal_holds",
            ["status", "placed_at"],
            unique=False,
        )

    if not inspector.has_table("compliance_evidence_artifacts"):
        op.create_table(
            "compliance_evidence_artifacts",
            sa.Column("evidence_id", sa.String(length=64), nullable=False),
            sa.Column("control_id", sa.String(length=128), nullable=False),
            sa.Column("generated_at", sa.DateTime(), nullable=False),
            sa.Column("generated_by", sa.String(length=128), nullable=False),
            sa.Column("source_type", sa.String(length=128), nullable=False),
            sa.Column("source_id", sa.String(length=128), nullable=False),
            sa.Column("trace_id", sa.String(length=128), nullable=False),
            sa.Column("policy_version", sa.String(length=64), nullable=False, server_default="v1"),
            sa.Column("artifact_uri", sa.String(length=1024), nullable=False),
            sa.Column("integrity_hash", sa.String(length=255), nullable=False),
            sa.PrimaryKeyConstraint("evidence_id"),
        )
    if "ix_compliance_evidence_control_created" not in {
        idx["name"] for idx in inspector.get_indexes("compliance_evidence_artifacts")
    }:
        op.create_index(
            "ix_compliance_evidence_control_created",
            "compliance_evidence_artifacts",
            ["control_id", "generated_at"],
            unique=False,
        )


def downgrade() -> None:
    op.drop_index("ix_compliance_evidence_control_created", table_name="compliance_evidence_artifacts")
    op.drop_table("compliance_evidence_artifacts")

    op.drop_index("ix_legal_holds_status_created", table_name="legal_holds")
    op.drop_table("legal_holds")

    op.drop_index("ix_retention_policies_data_class_jurisdiction", table_name="retention_policies")
    op.drop_table("retention_policies")
