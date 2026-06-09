"""add secret provider leases

Revision ID: 0010_secret_leases
Revises: 0009_load_cert
Create Date: 2026-06-04
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0010_secret_leases"
down_revision: Union[str, None] = "0009_load_cert"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("secret_provider_leases"):
        op.create_table(
            "secret_provider_leases",
            sa.Column("lease_id", sa.String(length=64), nullable=False),
            sa.Column("secret_provider_id", sa.String(length=64), nullable=False),
            sa.Column("secret_ref", sa.String(length=255), nullable=False),
            sa.Column("lease_ttl_seconds", sa.Integer(), nullable=False, server_default="3600"),
            sa.Column("issued_at", sa.DateTime(), nullable=False),
            sa.Column("renewed_at", sa.DateTime(), nullable=True),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
            sa.PrimaryKeyConstraint("lease_id"),
        )

    indexes = {idx["name"] for idx in inspector.get_indexes("secret_provider_leases")}
    if "ix_secret_provider_leases_provider_expiry" not in indexes:
        op.create_index(
            "ix_secret_provider_leases_provider_expiry",
            "secret_provider_leases",
            ["secret_provider_id", "expires_at"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("secret_provider_leases"):
        indexes = {idx["name"] for idx in inspector.get_indexes("secret_provider_leases")}
        if "ix_secret_provider_leases_provider_expiry" in indexes:
            op.drop_index("ix_secret_provider_leases_provider_expiry", table_name="secret_provider_leases")
        op.drop_table("secret_provider_leases")
