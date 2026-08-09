"""opt-in encrypted content columns for openai_file_records

Revision ID: 0043_openai_file_content_store
Revises: 0042_gateway_log_export_jobs
Create Date: 2026-08-02
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0043_openai_file_content_store"
down_revision: Union[str, None] = "0042_gateway_log_export_jobs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("openai_file_records"):
        return
    columns = {col["name"] for col in inspector.get_columns("openai_file_records")}
    if "content_encrypted" not in columns:
        op.add_column(
            "openai_file_records",
            sa.Column("content_encrypted", sa.Text(), nullable=False, server_default=""),
        )
    if "content_sha256" not in columns:
        op.add_column(
            "openai_file_records",
            sa.Column("content_sha256", sa.String(length=64), nullable=False, server_default=""),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("openai_file_records"):
        return
    columns = {col["name"] for col in inspector.get_columns("openai_file_records")}
    if "content_sha256" in columns:
        op.drop_column("openai_file_records", "content_sha256")
    if "content_encrypted" in columns:
        op.drop_column("openai_file_records", "content_encrypted")
