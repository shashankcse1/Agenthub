"""add query indexes for audit and schedules

Revision ID: 0003_add_query_indexes
Revises: 0002_policy_schedule_jobs
Create Date: 2026-06-02
"""

from typing import Sequence, Union

from alembic import op
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = "0003_add_query_indexes"
down_revision: Union[str, None] = "0002_policy_schedule_jobs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _index_names(table_name: str) -> set[str]:
    bind = op.get_bind()
    inspector = inspect(bind)
    return {idx["name"] for idx in inspector.get_indexes(table_name)}


def upgrade() -> None:
    audit_indexes = _index_names("audit_events")
    if "ix_audit_events_resource_lookup" not in audit_indexes:
        op.create_index(
            "ix_audit_events_resource_lookup",
            "audit_events",
            ["resource_type", "resource_id", "timestamp"],
            unique=False,
        )
    if "ix_audit_events_action_actor_time" not in audit_indexes:
        op.create_index(
            "ix_audit_events_action_actor_time",
            "audit_events",
            ["action_type", "actor_id", "timestamp"],
            unique=False,
        )

    schedule_indexes = _index_names("policy_schedule_jobs")
    if "ix_policy_schedule_jobs_filter" not in schedule_indexes:
        op.create_index(
            "ix_policy_schedule_jobs_filter",
            "policy_schedule_jobs",
            ["environment", "optimize_for", "enabled", "created_at"],
            unique=False,
        )


def downgrade() -> None:
    audit_indexes = _index_names("audit_events")
    if "ix_audit_events_resource_lookup" in audit_indexes:
        op.drop_index("ix_audit_events_resource_lookup", table_name="audit_events")
    if "ix_audit_events_action_actor_time" in audit_indexes:
        op.drop_index("ix_audit_events_action_actor_time", table_name="audit_events")

    schedule_indexes = _index_names("policy_schedule_jobs")
    if "ix_policy_schedule_jobs_filter" in schedule_indexes:
        op.drop_index("ix_policy_schedule_jobs_filter", table_name="policy_schedule_jobs")
