"""add virtual key guardrail policy column

Revision ID: 0021_virtual_key_guardrail_policy
Revises: 0020_directory_user_login_lockout_fields
Create Date: 2026-06-06
"""

from alembic import op
import sqlalchemy as sa


revision = "0021_virtual_key_guardrail_policy"
down_revision = "0020_directory_user_login_lockout_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("virtual_keys"):
        columns = {column["name"] for column in inspector.get_columns("virtual_keys")}
        if "guardrail_policy" not in columns:
            op.add_column(
                "virtual_keys",
                sa.Column("guardrail_policy", sa.Text(), nullable=False, server_default="{}"),
            )
            op.alter_column("virtual_keys", "guardrail_policy", server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("virtual_keys"):
        columns = {column["name"] for column in inspector.get_columns("virtual_keys")}
        if "guardrail_policy" in columns:
            op.drop_column("virtual_keys", "guardrail_policy")
