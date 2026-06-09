"""add scale load test runs

Revision ID: 0009_load_cert
Revises: 0008_ckpt_resume
Create Date: 2026-06-04
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0009_load_cert"
down_revision: Union[str, None] = "0008_ckpt_resume"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("scale_load_test_runs"):
        op.create_table(
            "scale_load_test_runs",
            sa.Column("load_test_run_id", sa.String(length=64), nullable=False),
            sa.Column("tier", sa.String(length=16), nullable=False),
            sa.Column("target_capacity", sa.Integer(), nullable=False),
            sa.Column("expected_concurrency", sa.Integer(), nullable=False),
            sa.Column("expected_rps", sa.Integer(), nullable=False),
            sa.Column("observed_peak_concurrency", sa.Integer(), nullable=False),
            sa.Column("observed_peak_rps", sa.Integer(), nullable=False),
            sa.Column("degradation_test_pass", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("recovery_test_pass", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("compliance_continuity_pass", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("passed", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("summary", sa.Text(), nullable=False, server_default=""),
            sa.Column("executed_by", sa.String(length=128), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("load_test_run_id"),
        )

    indexes = {idx["name"] for idx in inspector.get_indexes("scale_load_test_runs")}
    if "ix_scale_load_test_runs_tier_created" not in indexes:
        op.create_index(
            "ix_scale_load_test_runs_tier_created",
            "scale_load_test_runs",
            ["tier", "created_at"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("scale_load_test_runs"):
        indexes = {idx["name"] for idx in inspector.get_indexes("scale_load_test_runs")}
        if "ix_scale_load_test_runs_tier_created" in indexes:
            op.drop_index("ix_scale_load_test_runs_tier_created", table_name="scale_load_test_runs")
        op.drop_table("scale_load_test_runs")
