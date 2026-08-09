"""Add last_notify_json to gateway JIT access requests.

Revision ID: 0045_gateway_jit_last_notify
Revises: 0044_gateway_jit_virtual_key
Create Date: 2026-08-06
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0045_gateway_jit_last_notify"
down_revision: Union[str, None] = "0044_gateway_jit_virtual_key"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE IF EXISTS gateway_jit_access_requests "
        "ADD COLUMN IF NOT EXISTS last_notify_json TEXT"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE IF EXISTS gateway_jit_access_requests "
        "DROP COLUMN IF EXISTS last_notify_json"
    )
