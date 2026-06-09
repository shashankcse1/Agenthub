"""backfill master admin in auth policy role sets

Revision ID: 0017_master_admin_auth_policy_backfill
Revises: 0016_provider_encrypted_fields
Create Date: 2026-06-06
"""

from alembic import op
import sqlalchemy as sa
from typing import Optional


# revision identifiers, used by Alembic.
revision = "0017_master_admin_auth_policy_backfill"
down_revision = "0016_provider_encrypted_fields"
branch_labels = None
depends_on = None

MASTER_ADMIN_ROLE = "Master Admin"
AUTH_POLICY_ROLE_COLUMNS = (
    "session_read_roles",
    "session_issuer_roles",
    "issuable_session_roles",
    "cross_actor_dual_approval_roles",
)


def _append_role(raw_roles: Optional[str]) -> str:
    parsed = [item.strip() for item in str(raw_roles or "").split(",") if item.strip()]
    if MASTER_ADMIN_ROLE in parsed:
        return ",".join(parsed)
    parsed.append(MASTER_ADMIN_ROLE)
    return ",".join(parsed)


def _backfill_table(bind: sa.Connection, table_name: str) -> None:
    inspector = sa.inspect(bind)
    if not inspector.has_table(table_name):
        return

    rows = bind.execute(sa.text(f"SELECT * FROM {table_name}"))
    for row in rows.mappings().all():
        updates: dict[str, str] = {}
        for column in AUTH_POLICY_ROLE_COLUMNS:
            updated = _append_role(row.get(column))
            if updated != str(row.get(column) or ""):
                updates[column] = updated

        if not updates:
            continue

        where_column = "policy_id" if "policy_id" in row else "revision_id"
        updates[where_column] = str(row[where_column])
        set_clause = ", ".join(f"{column} = :{column}" for column in updates if column != where_column)
        bind.execute(
            sa.text(f"UPDATE {table_name} SET {set_clause} WHERE {where_column} = :{where_column}"),
            updates,
        )


def upgrade() -> None:
    bind = op.get_bind()
    _backfill_table(bind, "auth_policy_configs")
    _backfill_table(bind, "auth_policy_config_revisions")


def downgrade() -> None:
    # Data-only backfill is intentionally non-reversible.
    return
