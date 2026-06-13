"""orchestration flow definitions and runs

Revision ID: 0035_orchestration_flows
Revises: 0034_audit_event_action_context
Create Date: 2026-06-12
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0035_orchestration_flows"
down_revision: Union[str, None] = "0034_audit_event_action_context"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("orchestration_flow_definitions"):
        op.create_table(
            "orchestration_flow_definitions",
            sa.Column("flow_id", sa.String(length=64), primary_key=True),
            sa.Column("flow_name", sa.String(length=255), nullable=False),
            sa.Column("description", sa.Text(), nullable=False, server_default=""),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="draft"),
            sa.Column("environment", sa.String(length=32), nullable=False, server_default="dev"),
            sa.Column("tenant_id", sa.String(length=128), nullable=True),
            sa.Column("trigger_type", sa.String(length=32), nullable=False, server_default="manual"),
            sa.Column("trigger_config_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("graph_json", sa.Text(), nullable=False, server_default='{"nodes":[],"edges":[]}'),
            sa.Column("approval_status", sa.String(length=32), nullable=False, server_default="pending"),
            sa.Column("metadata_version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("created_by", sa.String(length=128), nullable=False),
            sa.Column("updated_by", sa.String(length=128), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )
        op.create_index(
            "ix_orchestration_flows_env_status",
            "orchestration_flow_definitions",
            ["environment", "status"],
        )
        op.create_index(
            "ix_orchestration_flows_tenant_env",
            "orchestration_flow_definitions",
            ["tenant_id", "environment"],
        )

    if not inspector.has_table("orchestration_flow_runs"):
        op.create_table(
            "orchestration_flow_runs",
            sa.Column("run_id", sa.String(length=64), primary_key=True),
            sa.Column("flow_id", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="running"),
            sa.Column("started_at", sa.DateTime(), nullable=False),
            sa.Column("finished_at", sa.DateTime(), nullable=True),
            sa.Column("trace_id", sa.String(length=128), nullable=False),
            sa.Column("step_results_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("error_summary", sa.Text(), nullable=True),
        )
        op.create_index(
            "ix_orchestration_flow_runs_flow_started",
            "orchestration_flow_runs",
            ["flow_id", "started_at"],
        )


def downgrade() -> None:
    op.drop_index("ix_orchestration_flow_runs_flow_started", table_name="orchestration_flow_runs")
    op.drop_table("orchestration_flow_runs")
    op.drop_index("ix_orchestration_flows_tenant_env", table_name="orchestration_flow_definitions")
    op.drop_index("ix_orchestration_flows_env_status", table_name="orchestration_flow_definitions")
    op.drop_table("orchestration_flow_definitions")
