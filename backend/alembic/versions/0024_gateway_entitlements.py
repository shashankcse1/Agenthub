"""add gateway entitlements table

Revision ID: 0024_gateway_entitlements
Revises: 0023_cost_event_request_tag
Create Date: 2026-06-08
"""

from alembic import op
import sqlalchemy as sa


revision = "0024_gateway_entitlements"
down_revision = "0023_cost_event_request_tag"
branch_labels = None
depends_on = None


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(idx.get("name") == index_name for idx in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("gateway_entitlements"):
        op.create_table(
            "gateway_entitlements",
            sa.Column("entitlement_id", sa.String(length=64), nullable=False),
            sa.Column("action", sa.String(length=128), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=True),
            sa.Column("environment", sa.String(length=64), nullable=False),
            sa.Column("route_policy_id", sa.String(length=64), nullable=True),
            sa.Column("request_tag", sa.String(length=64), nullable=True),
            sa.Column("model_name", sa.String(length=255), nullable=True),
            sa.Column("tool_name", sa.String(length=255), nullable=True),
            sa.Column("allowed_roles", sa.Text(), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False),
            sa.Column("updated_by", sa.String(length=128), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("entitlement_id"),
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("gateway_entitlements") and not _index_exists(
        inspector,
        "gateway_entitlements",
        "ix_gateway_entitlements_action_scope",
    ):
        op.create_index(
            "ix_gateway_entitlements_action_scope",
            "gateway_entitlements",
            ["action", "tenant_id", "environment"],
            unique=False,
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("gateway_entitlements") and not _index_exists(
        inspector,
        "gateway_entitlements",
        "ix_gateway_entitlements_route_tag",
    ):
        op.create_index(
            "ix_gateway_entitlements_route_tag",
            "gateway_entitlements",
            ["route_policy_id", "request_tag"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("gateway_entitlements"):
        if _index_exists(inspector, "gateway_entitlements", "ix_gateway_entitlements_route_tag"):
            op.drop_index("ix_gateway_entitlements_route_tag", table_name="gateway_entitlements")
        inspector = sa.inspect(bind)
        if _index_exists(inspector, "gateway_entitlements", "ix_gateway_entitlements_action_scope"):
            op.drop_index("ix_gateway_entitlements_action_scope", table_name="gateway_entitlements")
        op.drop_table("gateway_entitlements")
