"""make finding updated timestamp required

Revision ID: e583b0b7aa1c
Revises: 241e63791eb7
"""

from alembic import op
import sqlalchemy as sa


revision = "e583b0b7aa1c"
down_revision = "241e63791eb7"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.alter_column(
            "updated_at",
            existing_type=sa.DateTime(),
            nullable=False,
        )


def downgrade():
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.alter_column(
            "updated_at",
            existing_type=sa.DateTime(),
            nullable=True,
        )