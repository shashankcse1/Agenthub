"""add actor_login to audit_events for user identity traceability

Revision ID: 0033_audit_event_actor_login
Revises: 0032_gateway_response_cache_entries
Create Date: 2026-06-12
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0033_audit_event_actor_login"
down_revision: Union[str, None] = "0032_gateway_response_cache_entries"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("audit_events"):
        return

    columns = {column["name"] for column in inspector.get_columns("audit_events")}
    if "actor_login" not in columns:
        op.add_column("audit_events", sa.Column("actor_login", sa.String(length=255), nullable=True))

    indexes = {index["name"] for index in inspector.get_indexes("audit_events")}
    if "ix_audit_events_actor_login_time" not in indexes:
        op.create_index(
            "ix_audit_events_actor_login_time",
            "audit_events",
            ["actor_login", "timestamp"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("audit_events"):
        return

    indexes = {index["name"] for index in inspector.get_indexes("audit_events")}
    if "ix_audit_events_actor_login_time" in indexes:
        op.drop_index("ix_audit_events_actor_login_time", table_name="audit_events")

    columns = {column["name"] for column in inspector.get_columns("audit_events")}
    if "actor_login" in columns:
        op.drop_column("audit_events", "actor_login")
