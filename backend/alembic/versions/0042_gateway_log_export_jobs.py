"""gateway log export jobs for Portkey-style async log exports

Revision ID: 0042_gateway_log_export_jobs
Revises: 0041_cost_event_properties
Create Date: 2026-08-01
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0042_gateway_log_export_jobs"
down_revision: Union[str, None] = "0041_cost_event_properties"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("gateway_log_export_jobs"):
        return
    op.create_table(
        "gateway_log_export_jobs",
        sa.Column("export_id", sa.String(length=64), primary_key=True),
        sa.Column("actor_id", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("workspace_id", sa.String(length=128), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("filters_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("requested_data_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("row_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("content_jsonl", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
    )
    op.create_index(
        "ix_gateway_log_export_jobs_actor_created",
        "gateway_log_export_jobs",
        ["actor_id", "created_at"],
    )
    op.create_index(
        "ix_gateway_log_export_jobs_status_created",
        "gateway_log_export_jobs",
        ["status", "created_at"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("gateway_log_export_jobs"):
        return
    op.drop_index("ix_gateway_log_export_jobs_status_created", table_name="gateway_log_export_jobs")
    op.drop_index("ix_gateway_log_export_jobs_actor_created", table_name="gateway_log_export_jobs")
    op.drop_table("gateway_log_export_jobs")
