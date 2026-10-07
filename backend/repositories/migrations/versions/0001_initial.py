"""Initial separate catalog and workspace schemas, frozen at revision 0001."""

from datetime import datetime
from typing import Any

import sqlalchemy as sa

from alembic import context, op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def uid(name: str = "id", **kwargs: Any) -> sa.Column[str]:
    return sa.Column(name, sa.String(36), **kwargs)


def text(name: str, length: int | None = None, **kwargs: Any) -> sa.Column[str]:
    return sa.Column(name, sa.String(length) if length else sa.Text(), nullable=False, **kwargs)


def timestamp(name: str = "created_at") -> sa.Column[datetime]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=False)


def fk(
    name: str, target: str, *, nullable: bool = True, ondelete: str | None = None
) -> sa.Column[str]:
    return sa.Column(
        name, sa.String(36), sa.ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


def upgrade() -> None:
    scope = context.config.attributes["scope"]
    if scope == "catalog":
        op.create_table(
            "workspaces", uid(primary_key=True), text("name", 100), text("description"), timestamp()
        )
        op.create_table(
            "selection",
            sa.Column("id", sa.Integer(), primary_key=True),
            fk("workspace_id", "workspaces.id", nullable=False),
            sa.CheckConstraint("id = 1"),
        )
        op.create_table(
            "mutation_outcomes",
            uid("workspace_id", primary_key=True),
            uid("request_id", primary_key=True),
            text("operation", 200),
            text("fingerprint", 64),
            text("state", 16),
            sa.Column("result", sa.JSON()),
            sa.CheckConstraint("state IN ('pending','complete','unknown')"),
        )
        op.create_index("ix_mutation_outcomes_workspace_id", "mutation_outcomes", ["workspace_id"])
        return
    op.create_table(
        "targets",
        uid(primary_key=True),
        text("address", 15, unique=True),
        text("hostname", 253),
        sa.Column("ports", sa.JSON(), nullable=False),
        text("status", 24),
        text("notes"),
        timestamp(),
        timestamp("updated_at"),
        sa.CheckConstraint("status IN ('not_scanned','open','exploited','session_active')"),
    )
    op.create_table(
        "notes",
        sa.Column("id", sa.Integer(), primary_key=True),
        text("text"),
        sa.CheckConstraint("id = 1"),
    )
    op.create_table(
        "framework_instances",
        uid(primary_key=True),
        text("identity", 253, unique=True),
        text("endpoint", 253),
        timestamp(),
    )
    op.create_table(
        "job_associations",
        uid(primary_key=True),
        fk("target_id", "targets.id", ondelete="SET NULL"),
        fk("framework_id", "framework_instances.id"),
        text("module_id", 200),
        text("status", 24),
        timestamp(),
    )
    op.create_table(
        "remote_sessions",
        uid(primary_key=True),
        fk("framework_id", "framework_instances.id", nullable=False),
        text("remote_id", 100),
        fk("target_id", "targets.id", ondelete="SET NULL"),
        fk("job_id", "job_associations.id", ondelete="SET NULL"),
        text("status", 24),
        timestamp(),
    )
    op.create_table(
        "module_favorites", sa.Column("module_id", sa.String(200), primary_key=True), timestamp()
    )
    op.create_table(
        "module_recent", uid(primary_key=True), text("module_id", 200), timestamp("used_at")
    )
    op.create_table(
        "console_history",
        uid(primary_key=True),
        fk("framework_id", "framework_instances.id"),
        text("redacted_text"),
        timestamp(),
    )
    op.create_table(
        "vault_config",
        sa.Column("id", sa.Integer(), primary_key=True),
        text("kdf", 50),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("salt", sa.LargeBinary(), nullable=False),
        sa.Column("encrypted_check", sa.LargeBinary(), nullable=False),
    )
    op.create_table(
        "encrypted_credentials",
        uid(primary_key=True),
        sa.Column("vault_id", sa.Integer(), sa.ForeignKey("vault_config.id"), nullable=False),
        fk("target_id", "targets.id", ondelete="SET NULL"),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        timestamp(),
    )
    op.create_table("reports", uid(primary_key=True), text("title", 200), timestamp())
    op.create_table(
        "artifacts",
        uid(primary_key=True),
        fk("report_id", "reports.id"),
        fk("job_id", "job_associations.id"),
        text("name", 200),
        text("media_type", 200),
        text("relative_path", 253),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        text("sha256", 64),
        timestamp(),
    )
    indexes = {
        "targets": ("hostname", "status"),
        "job_associations": ("target_id", "framework_id"),
        "remote_sessions": ("framework_id", "target_id", "job_id"),
        "module_recent": ("module_id", "used_at"),
        "console_history": ("framework_id", "created_at"),
        "encrypted_credentials": ("target_id",),
        "artifacts": ("report_id", "job_id"),
    }
    for table, columns in indexes.items():
        for column in columns:
            op.create_index(f"ix_{table}_{column}", table, [column])


def downgrade() -> None:
    # Destructive downgrade is deliberately unavailable in the application.
    raise RuntimeError("Restore a backup instead of destructively downgrading workspace data")
