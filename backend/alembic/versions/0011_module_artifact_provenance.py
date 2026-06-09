"""add module artifact provenance metadata

Revision ID: 0011_module_artifact_provenance
Revises: 0010_secret_leases
Create Date: 2026-06-04
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0011_module_artifact_provenance"
down_revision = "0010_secret_leases"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("module_definitions") as batch_op:
        batch_op.add_column(sa.Column("artifact_signature", sa.String(length=255), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("provenance_ref", sa.String(length=1024), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("security_review_ticket", sa.String(length=128), nullable=False, server_default=""))


def downgrade() -> None:
    with op.batch_alter_table("module_definitions") as batch_op:
        batch_op.drop_column("security_review_ticket")
        batch_op.drop_column("provenance_ref")
        batch_op.drop_column("artifact_signature")
