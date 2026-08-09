"""orchestration flow revisions for enterprise rollback

Revision ID: 0040_orchestration_flow_revisions
Revises: 0039_audit_event_actor_role_description
Create Date: 2026-07-30
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0040_orchestration_flow_revisions"
down_revision: Union[str, None] = "0039_audit_event_actor_role_description"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("orchestration_flow_revisions"):
        return
    op.create_table(
        "orchestration_flow_revisions",
        sa.Column("revision_id", sa.String(length=64), primary_key=True),
        sa.Column("flow_id", sa.String(length=64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("flow_name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="draft"),
        sa.Column("environment", sa.String(length=32), nullable=False, server_default="dev"),
        sa.Column("trigger_type", sa.String(length=32), nullable=False, server_default="manual"),
        sa.Column("trigger_config_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("graph_json", sa.Text(), nullable=False, server_default='{"nodes":[],"edges":[]}'),
        sa.Column("access_policy_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("change_reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_orchestration_flow_revisions_flow_version",
        "orchestration_flow_revisions",
        ["flow_id", "version"],
        unique=True,
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("orchestration_flow_revisions"):
        return
    op.drop_index("ix_orchestration_flow_revisions_flow_version", table_name="orchestration_flow_revisions")
    op.drop_table("orchestration_flow_revisions")
