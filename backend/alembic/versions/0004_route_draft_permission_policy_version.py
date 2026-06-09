"""add permission policy version to route draft approval events

Revision ID: 0004_route_draft_permission_policy_version
Revises: 0003_add_query_indexes
Create Date: 2026-06-04
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0004_rd_ppv"
down_revision: Union[str, None] = "0003_add_query_indexes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "route_draft_approval_events",
        sa.Column("permission_policy_version", sa.String(length=64), nullable=False, server_default="v1"),
    )


def downgrade() -> None:
    op.drop_column("route_draft_approval_events", "permission_policy_version")
