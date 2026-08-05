"""JIT grant virtual key minting columns

Revision ID: 0044_gateway_jit_virtual_key
Revises: 0043_openai_file_content_store
Create Date: 2026-08-05
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0044_gateway_jit_virtual_key"
down_revision: Union[str, None] = "0043_openai_file_content_store"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(idx.get("name") == index_name for idx in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("virtual_keys"):
        columns = {col["name"] for col in inspector.get_columns("virtual_keys")}
        if "jit_request_id" not in columns:
            op.add_column(
                "virtual_keys",
                sa.Column("jit_request_id", sa.String(length=64), nullable=True),
            )
        inspector = sa.inspect(bind)
        if not _index_exists(inspector, "virtual_keys", "ix_virtual_keys_jit_request"):
            op.create_index(
                "ix_virtual_keys_jit_request",
                "virtual_keys",
                ["jit_request_id"],
            )

    if inspector.has_table("gateway_jit_access_requests"):
        columns = {col["name"] for col in inspector.get_columns("gateway_jit_access_requests")}
        if "owner_scope_type" not in columns:
            op.add_column(
                "gateway_jit_access_requests",
                sa.Column("owner_scope_type", sa.String(length=64), nullable=False, server_default="user"),
            )
        if "owner_scope_id" not in columns:
            op.add_column(
                "gateway_jit_access_requests",
                sa.Column("owner_scope_id", sa.String(length=128), nullable=True),
            )
        if "mint_virtual_key" not in columns:
            op.add_column(
                "gateway_jit_access_requests",
                sa.Column("mint_virtual_key", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            )
        if "issued_virtual_key_id" not in columns:
            op.add_column(
                "gateway_jit_access_requests",
                sa.Column("issued_virtual_key_id", sa.String(length=64), nullable=True),
            )
        inspector = sa.inspect(bind)
        if not _index_exists(inspector, "gateway_jit_access_requests", "ix_gateway_jit_request_issued_key"):
            op.create_index(
                "ix_gateway_jit_request_issued_key",
                "gateway_jit_access_requests",
                ["issued_virtual_key_id"],
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("gateway_jit_access_requests"):
        if _index_exists(inspector, "gateway_jit_access_requests", "ix_gateway_jit_request_issued_key"):
            op.drop_index("ix_gateway_jit_request_issued_key", table_name="gateway_jit_access_requests")
        columns = {col["name"] for col in inspector.get_columns("gateway_jit_access_requests")}
        for column_name in ("issued_virtual_key_id", "mint_virtual_key", "owner_scope_id", "owner_scope_type"):
            if column_name in columns:
                op.drop_column("gateway_jit_access_requests", column_name)

    if inspector.has_table("virtual_keys"):
        if _index_exists(inspector, "virtual_keys", "ix_virtual_keys_jit_request"):
            op.drop_index("ix_virtual_keys_jit_request", table_name="virtual_keys")
        columns = {col["name"] for col in inspector.get_columns("virtual_keys")}
        if "jit_request_id" in columns:
            op.drop_column("virtual_keys", "jit_request_id")
