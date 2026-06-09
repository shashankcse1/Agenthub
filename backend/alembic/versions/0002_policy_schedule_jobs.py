"""add policy schedule jobs table

Revision ID: 0002_policy_schedule_jobs
Revises: 0001_initial_schema
Create Date: 2026-06-02
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = "0002_policy_schedule_jobs"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if not inspector.has_table("policy_schedule_jobs"):
        op.create_table(
            "policy_schedule_jobs",
            sa.Column("job_id", sa.String(length=64), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("environment", sa.String(length=32), nullable=False, server_default="prod"),
            sa.Column("optimize_for", sa.String(length=32), nullable=False, server_default="balanced"),
            sa.Column("max_routes", sa.Integer(), nullable=False, server_default="10"),
            sa.Column("window_start_hour_utc", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("window_end_hour_utc", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("max_changes_without_approval", sa.Integer(), nullable=False, server_default="3"),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.Column("last_run_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("job_id"),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if inspector.has_table("policy_schedule_jobs"):
        op.drop_table("policy_schedule_jobs")
