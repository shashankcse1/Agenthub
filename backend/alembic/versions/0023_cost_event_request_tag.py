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


def _column_exists(inspector: sa.Inspector, table_name: str, column_name: str) -> bool:
    return any(col.get("name") == column_name for col in inspector.get_columns(table_name))


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(idx.get("name") == index_name for idx in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _column_exists(inspector, "cost_events", "request_tag"):
        op.add_column("cost_events", sa.Column("request_tag", sa.String(length=64), nullable=True))
    if not _index_exists(inspector, "cost_events", "ix_cost_events_request_tag"):
        op.create_index("ix_cost_events_request_tag", "cost_events", ["request_tag"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_cost_events_request_tag", table_name="cost_events")
    op.drop_column("cost_events", "request_tag")
