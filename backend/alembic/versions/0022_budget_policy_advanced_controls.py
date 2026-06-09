"""add budget policy advanced controls

Revision ID: 0022_budget_policy_advanced_controls
Revises: 0021_virtual_key_guardrail_policy
Create Date: 2026-06-08
"""

from alembic import op
import sqlalchemy as sa


revision = "0022_budget_policy_advanced_controls"
down_revision = "0021_virtual_key_guardrail_policy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("budget_policies", sa.Column("reset_timezone", sa.String(length=64), nullable=False, server_default="UTC"))
    op.add_column("budget_policies", sa.Column("reset_hour_local", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("budget_policies", sa.Column("temporary_increase_cents", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("budget_policies", sa.Column("temporary_increase_expires_at", sa.DateTime(), nullable=True))
    op.add_column("budget_policies", sa.Column("soft_alert_enabled", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("budget_policies", sa.Column("last_soft_alert_at", sa.DateTime(), nullable=True))
    op.add_column("budget_policies", sa.Column("rate_limit_tpm", sa.Integer(), nullable=True))
    op.add_column("budget_policies", sa.Column("rate_limit_rpm", sa.Integer(), nullable=True))
    op.add_column("budget_policies", sa.Column("session_iteration_cap", sa.Integer(), nullable=True))
    op.add_column("budget_policies", sa.Column("session_budget_cents", sa.Integer(), nullable=True))

    op.alter_column("budget_policies", "reset_timezone", server_default=None)
    op.alter_column("budget_policies", "reset_hour_local", server_default=None)
    op.alter_column("budget_policies", "temporary_increase_cents", server_default=None)
    op.alter_column("budget_policies", "soft_alert_enabled", server_default=None)


def downgrade() -> None:
    op.drop_column("budget_policies", "session_budget_cents")
    op.drop_column("budget_policies", "session_iteration_cap")
    op.drop_column("budget_policies", "rate_limit_rpm")
    op.drop_column("budget_policies", "rate_limit_tpm")
    op.drop_column("budget_policies", "last_soft_alert_at")
    op.drop_column("budget_policies", "soft_alert_enabled")
    op.drop_column("budget_policies", "temporary_increase_expires_at")
    op.drop_column("budget_policies", "temporary_increase_cents")
    op.drop_column("budget_policies", "reset_hour_local")
    op.drop_column("budget_policies", "reset_timezone")
