"""add finding fingerprint and updated timestamp

Revision ID: 241e63791eb7
Revises:
Create Date: 2026-09-29
"""

from alembic import op
import sqlalchemy as sa


revision = "241e63791eb7"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "updated_at",
                sa.DateTime(),
                nullable=True
            )
        )

        batch_op.add_column(
            sa.Column(
                "fingerprint",
                sa.String(length=64),
                nullable=True
            )
        )

        batch_op.create_index(
            "ix_findings_fingerprint",
            ["fingerprint"],
            unique=False
        )

    op.execute(
        """
        UPDATE findings
        SET updated_at = created_at
        WHERE updated_at IS NULL
        """
    )


def downgrade():
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_index("ix_findings_fingerprint")
        batch_op.drop_column("fingerprint")
        batch_op.drop_column("updated_at")