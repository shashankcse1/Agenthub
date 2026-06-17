"""add discovery connections for live source sync

Revision ID: 0030_discovery_connections
Revises: 0029_provider_credential_bindings
Create Date: 2026-06-12
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0030_discovery_connections"
down_revision: Union[str, None] = "0029_provider_credential_bindings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("discovery_connections"):
        op.create_table(
            "discovery_connections",
            sa.Column("connection_id", sa.String(length=64), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=False),
            sa.Column("source_id", sa.String(length=128), nullable=False),
            sa.Column("connection_name", sa.String(length=255), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("sync_interval_minutes", sa.Integer(), nullable=False, server_default="60"),
            sa.Column("next_sync_at", sa.DateTime(), nullable=False),
            sa.Column("last_sync_at", sa.DateTime(), nullable=True),
            sa.Column("last_sync_status", sa.String(length=32), nullable=False, server_default="never"),
            sa.Column("last_sync_error", sa.Text(), nullable=False, server_default=""),
            sa.Column("last_discovered_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("credential_binding_id", sa.String(length=64), nullable=True),
            sa.Column("secret_provider_id", sa.String(length=64), nullable=True),
            sa.Column("secret_ref", sa.String(length=255), nullable=True),
            sa.Column("base_url", sa.String(length=1024), nullable=False, server_default=""),
            sa.Column("connection_config_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.Column("updated_by", sa.String(length=128), nullable=True),
            sa.PrimaryKeyConstraint("connection_id"),
        )
        op.create_index(
            "ix_discovery_connections_source_enabled",
            "discovery_connections",
            ["source_id", "enabled"],
        )
        op.create_index(
            "ix_discovery_connections_next_sync",
            "discovery_connections",
            ["enabled", "next_sync_at"],
        )
        op.create_index(
            "ix_discovery_connections_tenant",
            "discovery_connections",
            ["tenant_id", "status"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("discovery_connections"):
        op.drop_index("ix_discovery_connections_tenant", table_name="discovery_connections")
        op.drop_index("ix_discovery_connections_next_sync", table_name="discovery_connections")
        op.drop_index("ix_discovery_connections_source_enabled", table_name="discovery_connections")
        op.drop_table("discovery_connections")
