"""add directory user login lockout tracking fields

Revision ID: 0020_directory_user_login_lockout_fields
Revises: 0019_directory_user_password_hash
Create Date: 2026-06-06
"""

from alembic import op
import sqlalchemy as sa


revision = "0020_directory_user_login_lockout_fields"
down_revision = "0019_directory_user_password_hash"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("directory_users"):
        columns = {column["name"] for column in inspector.get_columns("directory_users")}
        if "failed_login_attempts" not in columns:
            op.add_column(
                "directory_users",
                sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
            )
            op.alter_column("directory_users", "failed_login_attempts", server_default=None)
        if "locked_until" not in columns:
            op.add_column("directory_users", sa.Column("locked_until", sa.DateTime(), nullable=True))
        if "last_login_at" not in columns:
            op.add_column("directory_users", sa.Column("last_login_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("directory_users"):
        columns = {column["name"] for column in inspector.get_columns("directory_users")}
        if "last_login_at" in columns:
            op.drop_column("directory_users", "last_login_at")
        if "locked_until" in columns:
            op.drop_column("directory_users", "locked_until")
        if "failed_login_attempts" in columns:
            op.drop_column("directory_users", "failed_login_attempts")
