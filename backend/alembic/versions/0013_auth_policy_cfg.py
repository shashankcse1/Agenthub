"""add auth policy config table

Revision ID: 0013_auth_policy_cfg
Revises: 0012_mod_deprecate
Create Date: 2026-06-05
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0013_auth_policy_cfg"
down_revision = "0012_mod_deprecate"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("auth_policy_configs"):
        return

    op.create_table(
        "auth_policy_configs",
        sa.Column("policy_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("session_read_roles", sa.Text(), nullable=False),
        sa.Column("session_issuer_roles", sa.Text(), nullable=False),
        sa.Column("issuable_session_roles", sa.Text(), nullable=False),
        sa.Column("cross_actor_dual_approval_roles", sa.Text(), nullable=False),
        sa.Column("dual_approval_required_approver_role", sa.String(length=128), nullable=False),
        sa.Column("privileged_mfa_reauth_minutes", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("auth_policy_configs"):
        op.drop_table("auth_policy_configs")
