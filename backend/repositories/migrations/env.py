"""Use the caller's transaction and explicit catalog/workspace migration scope."""

from alembic import context

config = context.config
connection = config.attributes.get("connection")
if config.attributes.get("scope") not in {"catalog", "workspace"}:
    raise ValueError("Migration requires catalog or workspace scope")
if connection is None:
    raise RuntimeError("Migrate through WorkspaceService with its protected connection")
context.configure(connection=connection, transactional_ddl=True)
with context.begin_transaction():
    context.run_migrations()
