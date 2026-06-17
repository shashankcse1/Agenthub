"""add discovery duplicate merge linkage column

Revision ID: 0031_discovery_merge
Revises: 0030_discovery_connections
Create Date: 2026-06-10
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0031_discovery_merge"
down_revision: Union[str, None] = "0030_discovery_connections"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("discovery_records"):
        return
    columns = {column["name"] for column in inspector.get_columns("discovery_records")}
    if "merged_into_discovered_agent_id" not in columns:
        op.add_column(
            "discovery_records",
            sa.Column("merged_into_discovered_agent_id", sa.String(length=64), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("discovery_records"):
        return
    columns = {column["name"] for column in inspector.get_columns("discovery_records")}
    if "merged_into_discovered_agent_id" in columns:
        op.drop_column("discovery_records", "merged_into_discovered_agent_id")
