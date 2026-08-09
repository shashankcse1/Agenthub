"""cost event cache_hit and properties_json for Helicone-class drilldown

Revision ID: 0041_cost_event_properties
Revises: 0040_orchestration_flow_revisions
Create Date: 2026-07-31
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0041_cost_event_properties"
down_revision: Union[str, None] = "0040_orchestration_flow_revisions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("cost_events"):
        return
    columns = {col["name"] for col in inspector.get_columns("cost_events")}
    if "cache_hit" not in columns:
        op.add_column(
            "cost_events",
            sa.Column("cache_hit", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
    if "properties_json" not in columns:
        op.add_column(
            "cost_events",
            sa.Column("properties_json", sa.Text(), nullable=False, server_default="{}"),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("cost_events"):
        return
    columns = {col["name"] for col in inspector.get_columns("cost_events")}
    if "properties_json" in columns:
        op.drop_column("cost_events", "properties_json")
    if "cache_hit" in columns:
        op.drop_column("cost_events", "cache_hit")
