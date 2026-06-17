"""orchestration approval gates and run execution state

Revision ID: 0037_orchestration_approval_gates
Revises: 0036_orchestration_access_policy
Create Date: 2026-06-13
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0037_orchestration_approval_gates"
down_revision: Union[str, None] = "0036_orchestration_access_policy"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("orchestration_flow_runs"):
        columns = {col["name"] for col in inspector.get_columns("orchestration_flow_runs")}
        if "execution_state_json" not in columns:
            op.add_column(
                "orchestration_flow_runs",
                sa.Column("execution_state_json", sa.Text(), nullable=True),
            )

    if not inspector.has_table("orchestration_run_approval_gates"):
        op.create_table(
            "orchestration_run_approval_gates",
            sa.Column("gate_id", sa.String(length=64), primary_key=True),
            sa.Column("run_id", sa.String(length=64), nullable=False),
            sa.Column("flow_id", sa.String(length=64), nullable=False),
            sa.Column("node_id", sa.String(length=128), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
            sa.Column("approval_title", sa.String(length=512), nullable=False),
            sa.Column("required_role", sa.String(length=128), nullable=True),
            sa.Column("resolved_approver_id", sa.String(length=128), nullable=True),
            sa.Column("resolved_approver_role", sa.String(length=128), nullable=True),
            sa.Column("decided_by", sa.String(length=128), nullable=True),
            sa.Column("decided_at", sa.DateTime(), nullable=True),
            sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index(
            "ix_orchestration_approval_gates_run_status",
            "orchestration_run_approval_gates",
            ["run_id", "status"],
        )
        op.create_index(
            "ix_orchestration_approval_gates_flow_run",
            "orchestration_run_approval_gates",
            ["flow_id", "run_id"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("orchestration_run_approval_gates"):
        op.drop_index("ix_orchestration_approval_gates_flow_run", table_name="orchestration_run_approval_gates")
        op.drop_index("ix_orchestration_approval_gates_run_status", table_name="orchestration_run_approval_gates")
        op.drop_table("orchestration_run_approval_gates")

    if inspector.has_table("orchestration_flow_runs"):
        columns = {col["name"] for col in inspector.get_columns("orchestration_flow_runs")}
        if "execution_state_json" in columns:
            op.drop_column("orchestration_flow_runs", "execution_state_json")
