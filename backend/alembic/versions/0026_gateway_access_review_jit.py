"""add gateway access review and jit tables

Revision ID: 0026_gateway_access_review_jit
Revises: 0025_gateway_nhi_inventory
Create Date: 2026-06-08
"""

from alembic import op
import sqlalchemy as sa


revision = "0026_gateway_access_review_jit"
down_revision = "0025_gateway_nhi_inventory"
branch_labels = None
depends_on = None


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(idx.get("name") == index_name for idx in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("gateway_access_review_campaigns"):
        op.create_table(
            "gateway_access_review_campaigns",
            sa.Column("campaign_id", sa.String(length=64), nullable=False),
            sa.Column("campaign_name", sa.String(length=255), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=True),
            sa.Column("environment", sa.String(length=64), nullable=False),
            sa.Column("include_disabled", sa.Boolean(), nullable=False),
            sa.Column("status", sa.String(length=64), nullable=False),
            sa.Column("reviewer_role", sa.String(length=128), nullable=False),
            sa.Column("created_by", sa.String(length=128), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("closed_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("campaign_id"),
        )

    inspector = sa.inspect(bind)
    if not inspector.has_table("gateway_access_review_items"):
        op.create_table(
            "gateway_access_review_items",
            sa.Column("review_item_id", sa.String(length=64), nullable=False),
            sa.Column("campaign_id", sa.String(length=64), nullable=False),
            sa.Column("entitlement_id", sa.String(length=64), nullable=False),
            sa.Column("decision", sa.String(length=64), nullable=False),
            sa.Column("decision_reason", sa.Text(), nullable=True),
            sa.Column("decided_by", sa.String(length=128), nullable=True),
            sa.Column("decided_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("review_item_id"),
        )

    inspector = sa.inspect(bind)
    if not inspector.has_table("gateway_jit_access_requests"):
        op.create_table(
            "gateway_jit_access_requests",
            sa.Column("request_id", sa.String(length=64), nullable=False),
            sa.Column("entitlement_id", sa.String(length=64), nullable=False),
            sa.Column("requester_id", sa.String(length=128), nullable=False),
            sa.Column("requester_role", sa.String(length=128), nullable=False),
            sa.Column("justification", sa.Text(), nullable=False),
            sa.Column("environment", sa.String(length=64), nullable=False),
            sa.Column("requested_duration_minutes", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(length=64), nullable=False),
            sa.Column("approved_by", sa.String(length=128), nullable=True),
            sa.Column("approved_role", sa.String(length=128), nullable=True),
            sa.Column("approved_at", sa.DateTime(), nullable=True),
            sa.Column("expires_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("request_id"),
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("gateway_access_review_campaigns") and not _index_exists(
        inspector,
        "gateway_access_review_campaigns",
        "ix_gateway_access_review_campaign_scope",
    ):
        op.create_index(
            "ix_gateway_access_review_campaign_scope",
            "gateway_access_review_campaigns",
            ["environment", "status", "tenant_id"],
            unique=False,
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("gateway_access_review_items") and not _index_exists(
        inspector,
        "gateway_access_review_items",
        "ix_gateway_access_review_item_campaign",
    ):
        op.create_index(
            "ix_gateway_access_review_item_campaign",
            "gateway_access_review_items",
            ["campaign_id", "decision"],
            unique=False,
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("gateway_access_review_items") and not _index_exists(
        inspector,
        "gateway_access_review_items",
        "ix_gateway_access_review_item_entitlement",
    ):
        op.create_index(
            "ix_gateway_access_review_item_entitlement",
            "gateway_access_review_items",
            ["entitlement_id"],
            unique=False,
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("gateway_jit_access_requests") and not _index_exists(
        inspector,
        "gateway_jit_access_requests",
        "ix_gateway_jit_request_status_env",
    ):
        op.create_index(
            "ix_gateway_jit_request_status_env",
            "gateway_jit_access_requests",
            ["status", "environment"],
            unique=False,
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("gateway_jit_access_requests") and not _index_exists(
        inspector,
        "gateway_jit_access_requests",
        "ix_gateway_jit_request_entitlement",
    ):
        op.create_index(
            "ix_gateway_jit_request_entitlement",
            "gateway_jit_access_requests",
            ["entitlement_id"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("gateway_jit_access_requests"):
        if _index_exists(inspector, "gateway_jit_access_requests", "ix_gateway_jit_request_entitlement"):
            op.drop_index("ix_gateway_jit_request_entitlement", table_name="gateway_jit_access_requests")
        inspector = sa.inspect(bind)
        if _index_exists(inspector, "gateway_jit_access_requests", "ix_gateway_jit_request_status_env"):
            op.drop_index("ix_gateway_jit_request_status_env", table_name="gateway_jit_access_requests")
        op.drop_table("gateway_jit_access_requests")

    inspector = sa.inspect(bind)
    if inspector.has_table("gateway_access_review_items"):
        if _index_exists(inspector, "gateway_access_review_items", "ix_gateway_access_review_item_entitlement"):
            op.drop_index("ix_gateway_access_review_item_entitlement", table_name="gateway_access_review_items")
        inspector = sa.inspect(bind)
        if _index_exists(inspector, "gateway_access_review_items", "ix_gateway_access_review_item_campaign"):
            op.drop_index("ix_gateway_access_review_item_campaign", table_name="gateway_access_review_items")
        op.drop_table("gateway_access_review_items")

    inspector = sa.inspect(bind)
    if inspector.has_table("gateway_access_review_campaigns"):
        if _index_exists(inspector, "gateway_access_review_campaigns", "ix_gateway_access_review_campaign_scope"):
            op.drop_index("ix_gateway_access_review_campaign_scope", table_name="gateway_access_review_campaigns")
        op.drop_table("gateway_access_review_campaigns")
