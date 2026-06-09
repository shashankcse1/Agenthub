"""add gateway least privilege recommendations table

Revision ID: 0027_gateway_least_privilege
Revises: 0026_gateway_access_review_jit
Create Date: 2026-06-08
"""

from alembic import op
import sqlalchemy as sa


revision = "0027_gateway_least_privilege"
down_revision = "0026_gateway_access_review_jit"
branch_labels = None
depends_on = None


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(idx.get("name") == index_name for idx in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("gateway_least_privilege_recommendations"):
        op.create_table(
            "gateway_least_privilege_recommendations",
            sa.Column("recommendation_id", sa.String(length=64), nullable=False),
            sa.Column("entitlement_id", sa.String(length=64), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=True),
            sa.Column("environment", sa.String(length=64), nullable=False),
            sa.Column("recommendation_type", sa.String(length=64), nullable=False),
            sa.Column("rationale", sa.Text(), nullable=False),
            sa.Column("confidence_score", sa.Float(), nullable=False),
            sa.Column("current_allowed_roles", sa.Text(), nullable=False),
            sa.Column("proposed_allowed_roles", sa.Text(), nullable=False),
            sa.Column("proposed_enabled", sa.Boolean(), nullable=True),
            sa.Column("status", sa.String(length=64), nullable=False),
            sa.Column("created_by", sa.String(length=128), nullable=False),
            sa.Column("applied_by", sa.String(length=128), nullable=True),
            sa.Column("applied_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("recommendation_id"),
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("gateway_least_privilege_recommendations") and not _index_exists(
        inspector,
        "gateway_least_privilege_recommendations",
        "ix_gateway_lpr_scope_status",
    ):
        op.create_index(
            "ix_gateway_lpr_scope_status",
            "gateway_least_privilege_recommendations",
            ["tenant_id", "environment", "status"],
            unique=False,
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("gateway_least_privilege_recommendations") and not _index_exists(
        inspector,
        "gateway_least_privilege_recommendations",
        "ix_gateway_lpr_entitlement_type",
    ):
        op.create_index(
            "ix_gateway_lpr_entitlement_type",
            "gateway_least_privilege_recommendations",
            ["entitlement_id", "recommendation_type"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("gateway_least_privilege_recommendations"):
        if _index_exists(inspector, "gateway_least_privilege_recommendations", "ix_gateway_lpr_entitlement_type"):
            op.drop_index("ix_gateway_lpr_entitlement_type", table_name="gateway_least_privilege_recommendations")
        inspector = sa.inspect(bind)
        if _index_exists(inspector, "gateway_least_privilege_recommendations", "ix_gateway_lpr_scope_status"):
            op.drop_index("ix_gateway_lpr_scope_status", table_name="gateway_least_privilege_recommendations")
        op.drop_table("gateway_least_privilege_recommendations")
