"""add tenant model entitlements table

Revision ID: 0015_tenant_model_entitlements
Revises: 0014_auth_policy_revisions
Create Date: 2026-06-06
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0015_tenant_model_entitlements"
down_revision = "0014_auth_policy_revisions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("tenant_supported_model_entitlements"):
        return

    op.create_table(
        "tenant_supported_model_entitlements",
        sa.Column("tenant_model_entitlement_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("provider_type", sa.String(length=64), nullable=False),
        sa.Column("model_name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False, server_default="active"),
        sa.Column("updated_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_tenant_model_entitlements_lookup",
        "tenant_supported_model_entitlements",
        ["tenant_id", "provider_type", "status"],
        unique=False,
    )
    op.create_index(
        "ix_tenant_model_entitlements_unique",
        "tenant_supported_model_entitlements",
        ["tenant_id", "provider_type", "model_name"],
        unique=True,
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("tenant_supported_model_entitlements"):
        op.drop_index("ix_tenant_model_entitlements_unique", table_name="tenant_supported_model_entitlements")
        op.drop_index("ix_tenant_model_entitlements_lookup", table_name="tenant_supported_model_entitlements")
        op.drop_table("tenant_supported_model_entitlements")
