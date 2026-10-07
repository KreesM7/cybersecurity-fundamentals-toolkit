"""Private async SQLite engines, packaged transactional migrations and mutation persistence."""

from importlib import resources
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Literal, cast
from uuid import UUID

from alembic.config import Config
from sqlalchemy import event, update
from sqlalchemy.engine import URL, Connection, CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import ConnectionPoolEntry

from alembic import command
from backend.models import MutationOutcome
from backend.mutations import MutationConflictError, MutationRecord
from backend.platform_utils import assert_private_path, protect_private_path


class WorkspaceStartupError(RuntimeError):
    """Local data cannot be opened/migrated; restore/repair it without destructive resets."""


def private_engine(path: Path) -> AsyncEngine:
    """Reject existing unsafe paths and create DB files inside an owner-only directory."""
    protect_private_path(path.parent, directory=True)
    if path.exists():
        assert_private_path(path)
    else:
        path.touch(mode=0o600, exist_ok=False)
        protect_private_path(path)
    engine = create_async_engine(URL.create("sqlite+aiosqlite", database=str(path)))

    @event.listens_for(engine.sync_engine, "connect")
    def sqlite_connect(connection: Any, record: ConnectionPoolEntry) -> None:
        # Explicit BEGIN ensures SQLite DDL + Alembic stamping roll back together.
        connection.isolation_level = None
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA journal_mode=DELETE")
        cursor.close()

    @event.listens_for(engine.sync_engine, "begin")
    def sqlite_begin(connection: Connection) -> None:
        connection.exec_driver_sql("BEGIN")

    return engine


def _upgrade(connection: Connection, scope: Literal["catalog", "workspace"]) -> None:
    # Explicitly copy packaged .py scripts, including from zip/frozen resource readers.
    package = resources.files("backend.repositories.migrations")
    with TemporaryDirectory(prefix="toolkit-migrations-") as temporary:
        scripts = Path(temporary)
        (scripts / "versions").mkdir()
        (scripts / "env.py").write_bytes(package.joinpath("env.py").read_bytes())
        for revision in package.joinpath("versions").iterdir():
            if revision.name.endswith(".py") and revision.name != "__init__.py":
                (scripts / "versions" / revision.name).write_bytes(revision.read_bytes())
        config = Config()
        config.set_main_option("script_location", str(scripts).replace("%", "%%"))
        config.attributes.update(connection=connection, scope=scope)
        command.upgrade(config, "head")


async def migrate(engine: AsyncEngine, scope: Literal["catalog", "workspace"]) -> None:
    """Run the packaged Alembic revision in the async engine's actual transaction."""
    try:
        async with engine.begin() as connection:
            await connection.run_sync(_upgrade, scope)
    except Exception as exc:
        raise WorkspaceStartupError(
            f"Cannot open or migrate {scope} database. Preserve it and restore a backup or repair "
            "the local database before restarting."
        ) from exc


class SQLAlchemyMutationStore:
    """Durable catalog store; constructor receives WorkspaceService.catalog_sessions."""

    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self.sessions = sessions

    async def get(self, workspace_id: UUID, request_id: UUID) -> MutationRecord | None:
        async with self.sessions() as session:
            row = await session.get(MutationOutcome, (str(workspace_id), str(request_id)))
            if row is None:
                return None
            return MutationRecord(
                workspace_id,
                request_id,
                row.operation,
                row.fingerprint,
                "complete" if row.state == "complete" else "unknown",
                row.result,
            )

    async def reserve(self, record: MutationRecord) -> bool:
        try:
            async with self.sessions.begin() as session:
                session.add(
                    MutationOutcome(
                        workspace_id=str(record.workspace_id),
                        request_id=str(record.request_id),
                        operation=record.operation,
                        fingerprint=record.fingerprint,
                        state=record.state,
                        result=record.result,
                    )
                )
            return True
        except IntegrityError:
            return False

    async def finish(self, record: MutationRecord) -> None:
        async with self.sessions.begin() as session:
            result = await session.execute(
                update(MutationOutcome)
                .where(
                    MutationOutcome.workspace_id == str(record.workspace_id),
                    MutationOutcome.request_id == str(record.request_id),
                    MutationOutcome.operation == record.operation,
                    MutationOutcome.fingerprint == record.fingerprint,
                )
                .values(state=record.state, result=record.result)
            )
            if cast(CursorResult[Any], result).rowcount != 1:
                raise MutationConflictError(
                    "Mutation identity changed while completing the operation"
                )
