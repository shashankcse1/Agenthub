"""add action_context_json to audit_events for prompt and action metadata

Revision ID: 0034_audit_event_action_context
Revises: 0033_audit_event_actor_login
Create Date: 2026-06-12
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0034_audit_event_action_context"
down_revision: Union[str, None] = "0033_audit_event_actor_login"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("audit_events"):
        return

    columns = {column["name"] for column in inspector.get_columns("audit_events")}
    if "action_context_json" not in columns:
        op.add_column("audit_events", sa.Column("action_context_json", sa.Text(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("audit_events"):
        return

    columns = {column["name"] for column in inspector.get_columns("audit_events")}
    if "action_context_json" in columns:
        op.drop_column("audit_events", "action_context_json")
