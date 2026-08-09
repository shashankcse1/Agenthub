"""add provider credential bindings and model credential metadata

Revision ID: 0029_provider_credential_bindings
Revises: 0028_secret_provider_stored_values
Create Date: 2026-06-10
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0029_provider_credential_bindings"
down_revision: Union[str, None] = "0028_secret_provider_stored_values"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("provider_credential_bindings"):
        op.create_table(
            "provider_credential_bindings",
            sa.Column("binding_id", sa.String(length=64), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=False),
            sa.Column("binding_name", sa.String(length=255), nullable=False),
            sa.Column("consumer_type", sa.String(length=64), nullable=False),
            sa.Column("consumer_key", sa.String(length=255), nullable=False),
            sa.Column("provider_type", sa.String(length=64), nullable=False),
            sa.Column("credential_plane", sa.String(length=32), nullable=False),
            sa.Column("secret_provider_id", sa.String(length=64), nullable=True),
            sa.Column("secret_ref", sa.String(length=255), nullable=True),
            sa.Column("workload_identity_profile_id", sa.String(length=64), nullable=True),
            sa.Column("environment", sa.String(length=32), nullable=False, server_default="dev"),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
            sa.Column("updated_by", sa.String(length=128), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("binding_id"),
        )

    if inspector.has_table("provider_credential_bindings"):
        indexes = {idx["name"] for idx in inspector.get_indexes("provider_credential_bindings")}
        if "ix_provider_credential_bindings_scope" not in indexes:
            op.create_index(
                "ix_provider_credential_bindings_scope",
                "provider_credential_bindings",
                ["tenant_id", "consumer_type", "consumer_key", "provider_type", "environment"],
                unique=True,
            )
        if "ix_provider_credential_bindings_tenant_status" not in indexes:
            op.create_index(
                "ix_provider_credential_bindings_tenant_status",
                "provider_credential_bindings",
                ["tenant_id", "status"],
                unique=False,
            )

    columns = {col["name"] for col in inspector.get_columns("supported_model_catalog_entries")}
    if "credential_source_class" not in columns:
        op.add_column(
            "supported_model_catalog_entries",
            sa.Column("credential_source_class", sa.String(length=32), nullable=False, server_default=""),
        )
    if "default_binding_id" not in columns:
        op.add_column(
            "supported_model_catalog_entries",
            sa.Column("default_binding_id", sa.String(length=64), nullable=True),
        )

    agent_columns = {col["name"] for col in inspector.get_columns("agent_configs")}
    if "credential_binding_id" not in agent_columns:
        op.add_column(
            "agent_configs",
            sa.Column("credential_binding_id", sa.String(length=64), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    agent_columns = {col["name"] for col in inspector.get_columns("agent_configs")}
    if "credential_binding_id" in agent_columns:
        op.drop_column("agent_configs", "credential_binding_id")

    columns = {col["name"] for col in inspector.get_columns("supported_model_catalog_entries")}
    if "default_binding_id" in columns:
        op.drop_column("supported_model_catalog_entries", "default_binding_id")
    if "credential_source_class" in columns:
        op.drop_column("supported_model_catalog_entries", "credential_source_class")

    if inspector.has_table("provider_credential_bindings"):
        indexes = {idx["name"] for idx in inspector.get_indexes("provider_credential_bindings")}
        if "ix_provider_credential_bindings_tenant_status" in indexes:
            op.drop_index("ix_provider_credential_bindings_tenant_status", table_name="provider_credential_bindings")
        if "ix_provider_credential_bindings_scope" in indexes:
            op.drop_index("ix_provider_credential_bindings_scope", table_name="provider_credential_bindings")
        op.drop_table("provider_credential_bindings")
