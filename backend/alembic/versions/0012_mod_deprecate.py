"""add module deprecation metadata

Revision ID: 0012_mod_deprecate
Revises: 0011_module_artifact_provenance
Create Date: 2026-06-04
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0012_mod_deprecate"
down_revision = "0011_module_artifact_provenance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("module_definitions") as batch_op:
        batch_op.add_column(sa.Column("replacement_module_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("migration_guidance", sa.Text(), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("deprecation_timeline", sa.String(length=255), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("deprecated_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("module_definitions") as batch_op:
        batch_op.drop_column("deprecated_at")
        batch_op.drop_column("deprecation_timeline")
        batch_op.drop_column("migration_guidance")
        batch_op.drop_column("replacement_module_id")
