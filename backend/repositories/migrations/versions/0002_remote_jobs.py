"""Record remote job identities without confusing separate framework instances."""

import sqlalchemy as sa

from alembic import context, op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if context.config.attributes["scope"] == "workspace":
        op.add_column("job_associations", sa.Column("remote_job_id", sa.String(20), nullable=True))
        op.add_column("job_associations", sa.Column("execution_id", sa.String(64), nullable=True))


def downgrade() -> None:
    raise RuntimeError("Restore a backup instead of destructively downgrading workspace data")
