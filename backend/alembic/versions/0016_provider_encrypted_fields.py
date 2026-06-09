"""add encrypted fields for provider config

Revision ID: 0016_provider_encrypted_fields
Revises: 0015_tenant_model_entitlements
Create Date: 2026-06-06
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0016_provider_encrypted_fields"
down_revision = "0015_tenant_model_entitlements"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("workload_identity_federation_profiles"):
        op.execute(
            "ALTER TABLE workload_identity_federation_profiles "
            "ADD COLUMN IF NOT EXISTS role_arn_or_equivalent_encrypted TEXT"
        )
        op.execute(
            "ALTER TABLE workload_identity_federation_profiles "
            "ADD COLUMN IF NOT EXISTS bootstrap_token_encrypted TEXT"
        )

    if inspector.has_table("secret_provider_configs"):
        op.execute(
            "ALTER TABLE secret_provider_configs "
            "ADD COLUMN IF NOT EXISTS provider_address_encrypted TEXT"
        )
        op.execute(
            "ALTER TABLE secret_provider_configs "
            "ADD COLUMN IF NOT EXISTS auth_method_encrypted TEXT"
        )
        op.execute(
            "ALTER TABLE secret_provider_configs "
            "ADD COLUMN IF NOT EXISTS role_or_mount_encrypted TEXT"
        )
        op.execute(
            "ALTER TABLE secret_provider_configs "
            "ADD COLUMN IF NOT EXISTS bootstrap_token_encrypted TEXT"
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("workload_identity_federation_profiles"):
        op.execute(
            "ALTER TABLE workload_identity_federation_profiles "
            "DROP COLUMN IF EXISTS role_arn_or_equivalent_encrypted"
        )
        op.execute(
            "ALTER TABLE workload_identity_federation_profiles "
            "DROP COLUMN IF EXISTS bootstrap_token_encrypted"
        )

    if inspector.has_table("secret_provider_configs"):
        op.execute(
            "ALTER TABLE secret_provider_configs "
            "DROP COLUMN IF EXISTS provider_address_encrypted"
        )
        op.execute(
            "ALTER TABLE secret_provider_configs "
            "DROP COLUMN IF EXISTS auth_method_encrypted"
        )
        op.execute(
            "ALTER TABLE secret_provider_configs "
            "DROP COLUMN IF EXISTS role_or_mount_encrypted"
        )
        op.execute(
            "ALTER TABLE secret_provider_configs "
            "DROP COLUMN IF EXISTS bootstrap_token_encrypted"
        )
