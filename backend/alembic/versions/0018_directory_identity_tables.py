"""add directory identity tables for users groups and teams

Revision ID: 0018_directory_identity_tables
Revises: 0017_master_admin_auth_policy_backfill
Create Date: 2026-06-06
"""

from alembic import op
import sqlalchemy as sa


revision = "0018_directory_identity_tables"
down_revision = "0017_master_admin_auth_policy_backfill"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("directory_users"):
        op.create_table(
            "directory_users",
            sa.Column("user_id", sa.String(length=128), primary_key=True, nullable=False),
            sa.Column("display_name", sa.String(length=255), nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column("role_name", sa.String(length=128), nullable=False),
            sa.Column("status", sa.String(length=64), nullable=False),
            sa.Column("updated_by", sa.String(length=128), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_directory_users_status_role", "directory_users", ["status", "role_name"])

    if not inspector.has_table("directory_groups"):
        op.create_table(
            "directory_groups",
            sa.Column("group_id", sa.String(length=128), primary_key=True, nullable=False),
            sa.Column("display_name", sa.String(length=255), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("status", sa.String(length=64), nullable=False),
            sa.Column("updated_by", sa.String(length=128), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_directory_groups_status", "directory_groups", ["status"])

    if not inspector.has_table("directory_teams"):
        op.create_table(
            "directory_teams",
            sa.Column("team_id", sa.String(length=128), primary_key=True, nullable=False),
            sa.Column("display_name", sa.String(length=255), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("status", sa.String(length=64), nullable=False),
            sa.Column("updated_by", sa.String(length=128), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_directory_teams_status", "directory_teams", ["status"])

    if not inspector.has_table("directory_group_memberships"):
        op.create_table(
            "directory_group_memberships",
            sa.Column("membership_id", sa.String(length=64), primary_key=True, nullable=False),
            sa.Column("group_id", sa.String(length=128), nullable=False),
            sa.Column("user_id", sa.String(length=128), nullable=False),
            sa.Column("created_by", sa.String(length=128), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index(
            "ix_directory_group_membership_unique",
            "directory_group_memberships",
            ["group_id", "user_id"],
            unique=True,
        )

    if not inspector.has_table("directory_team_memberships"):
        op.create_table(
            "directory_team_memberships",
            sa.Column("membership_id", sa.String(length=64), primary_key=True, nullable=False),
            sa.Column("team_id", sa.String(length=128), nullable=False),
            sa.Column("user_id", sa.String(length=128), nullable=False),
            sa.Column("created_by", sa.String(length=128), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index(
            "ix_directory_team_membership_unique",
            "directory_team_memberships",
            ["team_id", "user_id"],
            unique=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("directory_team_memberships"):
        op.drop_index("ix_directory_team_membership_unique", table_name="directory_team_memberships")
        op.drop_table("directory_team_memberships")

    if inspector.has_table("directory_group_memberships"):
        op.drop_index("ix_directory_group_membership_unique", table_name="directory_group_memberships")
        op.drop_table("directory_group_memberships")

    if inspector.has_table("directory_teams"):
        op.drop_index("ix_directory_teams_status", table_name="directory_teams")
        op.drop_table("directory_teams")

    if inspector.has_table("directory_groups"):
        op.drop_index("ix_directory_groups_status", table_name="directory_groups")
        op.drop_table("directory_groups")

    if inspector.has_table("directory_users"):
        op.drop_index("ix_directory_users_status_role", table_name="directory_users")
        op.drop_table("directory_users")
