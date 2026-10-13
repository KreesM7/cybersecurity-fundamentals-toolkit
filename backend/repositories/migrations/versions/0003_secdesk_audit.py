"""Add local launch acknowledgments without commands, credentials or output."""

import sqlalchemy as sa

from alembic import context, op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if context.config.attributes["scope"] == "workspace":
        op.create_table(
            "secdesk_audit",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("tool_id", sa.String(64), nullable=False),
            sa.Column("mode", sa.String(16), nullable=False),
            sa.Column("event", sa.String(16), nullable=False),
            sa.Column("authorized", sa.Boolean(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )

        op.create_table(
            "secdesk_findings",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("identity", sa.String(64), nullable=False, unique=True),
            sa.Column("tool_id", sa.String(64), nullable=False),
            sa.Column("title", sa.String(200), nullable=False),
            sa.Column("severity", sa.String(16), nullable=False),
            sa.Column("target", sa.String(200), nullable=False),
            sa.Column("evidence", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )


def downgrade() -> None:
    raise RuntimeError("Restore a backup instead of destructively downgrading workspace data")
