"""add secret provider stored values for db-type providers

Revision ID: 0028_secret_provider_stored_values
Revises: 0027_gateway_least_privilege
Create Date: 2026-06-10
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0028_secret_provider_stored_values"
down_revision: Union[str, None] = "0027_gateway_least_privilege"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("secret_provider_stored_values"):
        op.create_table(
            "secret_provider_stored_values",
            sa.Column("secret_provider_id", sa.String(length=64), nullable=False),
            sa.Column("secret_ref", sa.String(length=255), nullable=False),
            sa.Column("value_encrypted", sa.Text(), nullable=False),
            sa.Column("updated_by", sa.String(length=128), nullable=True),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("secret_provider_id", "secret_ref"),
        )

    indexes = {idx["name"] for idx in inspector.get_indexes("secret_provider_stored_values")}
    if "ix_secret_provider_stored_values_provider_ref" not in indexes:
        op.create_index(
            "ix_secret_provider_stored_values_provider_ref",
            "secret_provider_stored_values",
            ["secret_provider_id", "secret_ref"],
            unique=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("secret_provider_stored_values"):
        indexes = {idx["name"] for idx in inspector.get_indexes("secret_provider_stored_values")}
        if "ix_secret_provider_stored_values_provider_ref" in indexes:
            op.drop_index(
                "ix_secret_provider_stored_values_provider_ref",
                table_name="secret_provider_stored_values",
            )
        op.drop_table("secret_provider_stored_values")
