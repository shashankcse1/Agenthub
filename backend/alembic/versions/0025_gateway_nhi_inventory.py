"""add gateway nhi inventory table

Revision ID: 0025_gateway_nhi_inventory
Revises: 0024_gateway_entitlements
Create Date: 2026-06-08
"""

from alembic import op
import sqlalchemy as sa


revision = "0025_gateway_nhi_inventory"
down_revision = "0024_gateway_entitlements"
branch_labels = None
depends_on = None


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(idx.get("name") == index_name for idx in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("gateway_nhi_inventory"):
        op.create_table(
            "gateway_nhi_inventory",
            sa.Column("nhi_record_id", sa.String(length=64), nullable=False),
            sa.Column("source_type", sa.String(length=64), nullable=False),
            sa.Column("source_id", sa.String(length=128), nullable=False),
            sa.Column("identity_type", sa.String(length=64), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=False),
            sa.Column("environment", sa.String(length=64), nullable=False),
            sa.Column("provider_type", sa.String(length=64), nullable=False),
            sa.Column("owner_scope_type", sa.String(length=64), nullable=True),
            sa.Column("owner_scope_id", sa.String(length=128), nullable=True),
            sa.Column("credential_last_rotated_at", sa.DateTime(), nullable=True),
            sa.Column("credential_expires_at", sa.DateTime(), nullable=True),
            sa.Column("last_used_at", sa.DateTime(), nullable=True),
            sa.Column("findings", sa.Text(), nullable=False),
            sa.Column("status", sa.String(length=64), nullable=False),
            sa.Column("updated_by", sa.String(length=128), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("nhi_record_id"),
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("gateway_nhi_inventory") and not _index_exists(
        inspector,
        "gateway_nhi_inventory",
        "ix_gateway_nhi_inventory_scope",
    ):
        op.create_index(
            "ix_gateway_nhi_inventory_scope",
            "gateway_nhi_inventory",
            ["tenant_id", "environment", "status"],
            unique=False,
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("gateway_nhi_inventory") and not _index_exists(
        inspector,
        "gateway_nhi_inventory",
        "ix_gateway_nhi_inventory_owner",
    ):
        op.create_index(
            "ix_gateway_nhi_inventory_owner",
            "gateway_nhi_inventory",
            ["owner_scope_type", "owner_scope_id"],
            unique=False,
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("gateway_nhi_inventory") and not _index_exists(
        inspector,
        "gateway_nhi_inventory",
        "ix_gateway_nhi_inventory_source_unique",
    ):
        op.create_index(
            "ix_gateway_nhi_inventory_source_unique",
            "gateway_nhi_inventory",
            ["source_type", "source_id"],
            unique=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("gateway_nhi_inventory"):
        if _index_exists(inspector, "gateway_nhi_inventory", "ix_gateway_nhi_inventory_source_unique"):
            op.drop_index("ix_gateway_nhi_inventory_source_unique", table_name="gateway_nhi_inventory")
        inspector = sa.inspect(bind)
        if _index_exists(inspector, "gateway_nhi_inventory", "ix_gateway_nhi_inventory_owner"):
            op.drop_index("ix_gateway_nhi_inventory_owner", table_name="gateway_nhi_inventory")
        inspector = sa.inspect(bind)
        if _index_exists(inspector, "gateway_nhi_inventory", "ix_gateway_nhi_inventory_scope"):
            op.drop_index("ix_gateway_nhi_inventory_scope", table_name="gateway_nhi_inventory")
        op.drop_table("gateway_nhi_inventory")
