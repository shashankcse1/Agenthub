"""add execution checkpoints table

Revision ID: 0008_ckpt_resume
Revises: 0007_ctrl_sess_rd
Create Date: 2026-06-04
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0008_ckpt_resume"
down_revision: Union[str, None] = "0007_ctrl_sess_rd"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("execution_checkpoints"):
        op.create_table(
            "execution_checkpoints",
            sa.Column("checkpoint_id", sa.String(length=64), nullable=False),
            sa.Column("session_id", sa.String(length=128), nullable=False),
            sa.Column("agent_id", sa.String(length=64), nullable=False),
            sa.Column("stage_name", sa.String(length=128), nullable=False),
            sa.Column("state_payload", sa.Text(), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
            sa.Column("created_by", sa.String(length=128), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("resumed_by", sa.String(length=128), nullable=True),
            sa.Column("resumed_at", sa.DateTime(), nullable=True),
            sa.Column("resume_count", sa.Integer(), nullable=False, server_default="0"),
            sa.PrimaryKeyConstraint("checkpoint_id"),
        )

    indexes = {idx["name"] for idx in inspector.get_indexes("execution_checkpoints")}
    if "ix_execution_checkpoints_session_created" not in indexes:
        op.create_index(
            "ix_execution_checkpoints_session_created",
            "execution_checkpoints",
            ["session_id", "created_at"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("execution_checkpoints"):
        indexes = {idx["name"] for idx in inspector.get_indexes("execution_checkpoints")}
        if "ix_execution_checkpoints_session_created" in indexes:
            op.drop_index("ix_execution_checkpoints_session_created", table_name="execution_checkpoints")
        op.drop_table("execution_checkpoints")
