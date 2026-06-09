"""add password hash column for directory users

Revision ID: 0019_directory_user_password_hash
Revises: 0018_directory_identity_tables
Create Date: 2026-06-06
"""

from alembic import op
import sqlalchemy as sa


revision = "0019_directory_user_password_hash"
down_revision = "0018_directory_identity_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("directory_users"):
        columns = {column["name"] for column in inspector.get_columns("directory_users")}
        if "password_hash" not in columns:
            op.add_column("directory_users", sa.Column("password_hash", sa.Text(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("directory_users"):
        columns = {column["name"] for column in inspector.get_columns("directory_users")}
        if "password_hash" in columns:
            op.drop_column("directory_users", "password_hash")
