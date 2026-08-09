"""add actor_role and action_description to audit_events

Revision ID: 0039_audit_event_actor_role_description
Revises: 0038_orchestration_iga
Create Date: 2026-06-14
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0039_audit_event_actor_role_description"
down_revision: Union[str, None] = "0038_orchestration_iga"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("audit_events"):
        return

    columns = {column["name"] for column in inspector.get_columns("audit_events")}
    if "actor_role" not in columns:
        op.add_column("audit_events", sa.Column("actor_role", sa.String(length=128), nullable=True))
    if "action_description" not in columns:
        op.add_column("audit_events", sa.Column("action_description", sa.String(length=512), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("audit_events"):
        return

    columns = {column["name"] for column in inspector.get_columns("audit_events")}
    if "action_description" in columns:
        op.drop_column("audit_events", "action_description")
    if "actor_role" in columns:
        op.drop_column("audit_events", "actor_role")
