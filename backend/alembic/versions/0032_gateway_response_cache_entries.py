"""add gateway response cache entries for inference short-circuit

Revision ID: 0032_gateway_response_cache_entries
Revises: 0031_discovery_merge
Create Date: 2026-06-12
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0032_gateway_response_cache_entries"
down_revision: Union[str, None] = "0031_discovery_merge"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("gateway_response_cache_entries"):
        op.create_table(
            "gateway_response_cache_entries",
            sa.Column("cache_entry_id", sa.String(length=64), nullable=False),
            sa.Column("cache_policy_id", sa.String(length=64), nullable=False),
            sa.Column("request_fingerprint", sa.String(length=128), nullable=False),
            sa.Column("request_text", sa.Text(), nullable=False, server_default=""),
            sa.Column("response_body_encrypted", sa.Text(), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=False, server_default=""),
            sa.Column("environment", sa.String(length=64), nullable=False, server_default="dev"),
            sa.Column("route_policy_id", sa.String(length=64), nullable=True),
            sa.Column("owner_scope", sa.String(length=128), nullable=False, server_default=""),
            sa.Column("data_class", sa.String(length=64), nullable=False, server_default="standard"),
            sa.Column("cache_mode", sa.String(length=64), nullable=False, server_default="exact"),
            sa.Column("match_score", sa.Float(), nullable=False, server_default="1.0"),
            sa.Column("endpoint_family", sa.String(length=64), nullable=False, server_default="chat.completions"),
            sa.Column("source_request_id", sa.String(length=64), nullable=True),
            sa.Column("ttl_expires_at", sa.DateTime(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("status", sa.String(length=64), nullable=False, server_default="active"),
            sa.PrimaryKeyConstraint("cache_entry_id"),
        )

    indexes = {idx["name"] for idx in inspector.get_indexes("gateway_response_cache_entries")}
    if "ix_gw_cache_entry_fingerprint" not in indexes:
        op.create_index(
            "ix_gw_cache_entry_fingerprint",
            "gateway_response_cache_entries",
            ["request_fingerprint", "cache_policy_id"],
        )
    if "ix_gw_cache_entry_policy_expires" not in indexes:
        op.create_index(
            "ix_gw_cache_entry_policy_expires",
            "gateway_response_cache_entries",
            ["cache_policy_id", "ttl_expires_at"],
        )
    if "ix_gw_cache_entry_tenant_env" not in indexes:
        op.create_index(
            "ix_gw_cache_entry_tenant_env",
            "gateway_response_cache_entries",
            ["tenant_id", "environment"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("gateway_response_cache_entries"):
        indexes = {idx["name"] for idx in inspector.get_indexes("gateway_response_cache_entries")}
        for index_name in (
            "ix_gw_cache_entry_tenant_env",
            "ix_gw_cache_entry_policy_expires",
            "ix_gw_cache_entry_fingerprint",
        ):
            if index_name in indexes:
                op.drop_index(index_name, table_name="gateway_response_cache_entries")
        op.drop_table("gateway_response_cache_entries")
