"""add scale readiness certification runs table

Revision ID: 0006_scale_cert
Revises: 0005_comp_retention
Create Date: 2026-06-04
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0006_scale_cert"
down_revision: Union[str, None] = "0005_comp_retention"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("scale_certification_runs"):
        op.create_table(
            "scale_certification_runs",
            sa.Column("certification_id", sa.String(length=64), nullable=False),
            sa.Column("target_capacity", sa.Integer(), nullable=False),
            sa.Column("required_multi_region", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("cost_freshness_slo_seconds", sa.Integer(), nullable=False, server_default="60"),
            sa.Column("readiness_score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("scale_benchmark_pass", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("security_scan_pass", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("contract_validation_pass", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("cost_freshness_pass", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("multi_region_pass", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("certified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("certified_user_capacity", sa.Integer(), nullable=False, server_default="10000"),
            sa.Column("summary", sa.Text(), nullable=False, server_default=""),
            sa.Column("executed_by", sa.String(length=128), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("certification_id"),
        )

    indexes = {idx["name"] for idx in inspector.get_indexes("scale_certification_runs")}
    if "ix_scale_certification_runs_created" not in indexes:
        op.create_index(
            "ix_scale_certification_runs_created",
            "scale_certification_runs",
            ["created_at"],
            unique=False,
        )
    if "ix_scale_certification_runs_certified" not in indexes:
        op.create_index(
            "ix_scale_certification_runs_certified",
            "scale_certification_runs",
            ["certified", "created_at"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("scale_certification_runs"):
        indexes = {idx["name"] for idx in inspector.get_indexes("scale_certification_runs")}
        if "ix_scale_certification_runs_certified" in indexes:
            op.drop_index("ix_scale_certification_runs_certified", table_name="scale_certification_runs")
        if "ix_scale_certification_runs_created" in indexes:
            op.drop_index("ix_scale_certification_runs_created", table_name="scale_certification_runs")
        op.drop_table("scale_certification_runs")
