"""orchestration flow access policy

Revision ID: 0036_orchestration_access_policy
Revises: 0035_orchestration_flows
Create Date: 2026-06-12
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0036_orchestration_access_policy"
down_revision: Union[str, None] = "0035_orchestration_flows"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("orchestration_flow_definitions"):
        columns = {col["name"] for col in inspector.get_columns("orchestration_flow_definitions")}
        if "access_policy_json" not in columns:
            op.add_column(
                "orchestration_flow_definitions",
                sa.Column("access_policy_json", sa.Text(), nullable=False, server_default="{}"),
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("orchestration_flow_definitions"):
        columns = {col["name"] for col in inspector.get_columns("orchestration_flow_definitions")}
        if "access_policy_json" in columns:
            op.drop_column("orchestration_flow_definitions", "access_policy_json")
