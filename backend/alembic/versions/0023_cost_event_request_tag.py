"""add request tag to cost events

Revision ID: 0023_cost_event_request_tag
Revises: 0022_budget_policy_advanced_controls
Create Date: 2026-06-08
"""

from alembic import op
import sqlalchemy as sa


revision = "0023_cost_event_request_tag"
down_revision = "0022_budget_policy_advanced_controls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("cost_events", sa.Column("request_tag", sa.String(length=64), nullable=True))
    op.create_index("ix_cost_events_request_tag", "cost_events", ["request_tag"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_cost_events_request_tag", table_name="cost_events")
    op.drop_column("cost_events", "request_tag")
