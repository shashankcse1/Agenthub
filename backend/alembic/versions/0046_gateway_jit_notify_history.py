"""Add notify_history_json to gateway JIT access requests.

Revision ID: 0046_gateway_jit_notify_history
Revises: 0045_gateway_jit_last_notify
Create Date: 2026-08-06
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0046_gateway_jit_notify_history"
down_revision: Union[str, None] = "0045_gateway_jit_last_notify"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE IF EXISTS gateway_jit_access_requests "
        "ADD COLUMN IF NOT EXISTS notify_history_json TEXT"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE IF EXISTS gateway_jit_access_requests "
        "DROP COLUMN IF EXISTS notify_history_json"
    )
