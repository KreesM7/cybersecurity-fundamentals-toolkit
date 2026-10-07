Versioned scripts live in the Python package `backend.repositories.migrations` so
wheels and frozen applications can resolve them through `importlib.resources`.
WorkspaceService runs `alembic upgrade head` on its protected async SQLite
connection using `run_sync`, with an explicit `catalog` or `workspace` scope.
Schema creation and revision stamping share one transaction. Failed upgrades keep
the original database, expose an actionable error, and never reset or erase it.
