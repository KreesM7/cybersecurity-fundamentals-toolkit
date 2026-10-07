"""Stable workspace identities with refcounted engines and immutable resource leases."""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from backend.database import WorkspaceStartupError, migrate, private_engine
from backend.models import Notes, Selection, Workspace
from backend.platform_utils import assert_private_path, protect_private_path, remove_private_tree
from shared.workspaces import WorkspaceCreate, WorkspaceView


class WorkspaceConflictError(ValueError):
    """Active workspaces and leased resources cannot be deleted or closed."""


class WorkspaceNotFoundError(LookupError):
    """The UUID does not exist in the catalog or a target does not exist in its workspace."""


WorkspaceConflict = WorkspaceConflictError
WorkspaceNotFound = WorkspaceNotFoundError


@dataclass
class _CachedEngine:
    engine: AsyncEngine
    sessions: async_sessionmaker[AsyncSession]
    references: int = 0


class WorkspaceLease:
    """Capture an engine/session factory until release; active selection cannot retarget it."""

    def __init__(
        self, owner: "WorkspaceService", workspace_id: UUID, cached: _CachedEngine
    ) -> None:
        self.workspace_id = workspace_id
        self.engine = cached.engine
        self.sessions = cached.sessions
        self._owner = owner
        self._released = False

    async def release(self) -> None:
        """Idempotently drop one reference, including job cleanup and async context exit."""
        async with self._owner._lock:
            if not self._released:
                self._owner._engines[self.workspace_id].references -= 1
                self._released = True

    async def __aenter__(self) -> "WorkspaceLease":
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.release()


class WorkspaceService:
    """One catalog and UUID-scoped databases; caller drains local jobs before close."""

    def __init__(self, profile: Path) -> None:
        self.profile = profile.absolute()
        self._lock = asyncio.Lock()
        self._engines: dict[UUID, _CachedEngine] = {}
        self._catalog_engine: AsyncEngine | None = None
        self._catalog_sessions: async_sessionmaker[AsyncSession] | None = None
        self._active_id: UUID | None = None

    @property
    def active_id(self) -> UUID:
        """Current selection; capture it before queuing a job or beginning a mutation."""
        if self._active_id is None:
            raise RuntimeError("Workspace service is not started")
        return self._active_id

    @property
    def catalog_engine(self) -> AsyncEngine:
        if self._catalog_engine is None:
            raise RuntimeError("Workspace service is not started")
        return self._catalog_engine

    @property
    def catalog_sessions(self) -> async_sessionmaker[AsyncSession]:
        if self._catalog_sessions is None:
            raise RuntimeError("Workspace service is not started")
        return self._catalog_sessions

    async def start(self) -> None:
        """Migrate private storage; preserve corrupt data and fail with local repair guidance."""
        async with self._lock:
            if self._active_id is not None:
                return
            protect_private_path(self.profile, directory=True)
            protect_private_path(self.profile / "workspaces", directory=True)
            self._catalog_engine = private_engine(self.profile / "catalog.db")
            self._catalog_sessions = async_sessionmaker(
                self._catalog_engine, expire_on_commit=False
            )
            try:
                await migrate(self._catalog_engine, "catalog")
                async with self.catalog_sessions() as session:
                    selected = await session.get(Selection, 1)
                    rows = (
                        await session.scalars(select(Workspace).order_by(Workspace.created_at))
                    ).all()
                if selected is None:
                    if not rows:
                        workspace = await self._create(WorkspaceCreate(name="Default"))
                        selected_id = workspace.id
                    else:
                        selected_id = UUID(rows[0].id)
                    async with self.catalog_sessions.begin() as session:
                        session.add(Selection(id=1, workspace_id=str(selected_id)))
                else:
                    selected_id = UUID(selected.workspace_id)
                await self._get(selected_id)
                await self._engine_for(selected_id)
                self._active_id = selected_id
            except BaseException as exc:
                for cached in self._engines.values():
                    await cached.engine.dispose()
                self._engines.clear()
                await self._catalog_engine.dispose()
                self._catalog_engine = None
                self._catalog_sessions = None
                if isinstance(exc, Exception) and not isinstance(exc, WorkspaceStartupError):
                    raise WorkspaceStartupError(
                        "Cannot initialize catalog selection. Preserve the local databases and "
                        "restore a backup or repair catalog identities before restarting."
                    ) from exc
                raise

    async def close(self) -> None:
        """Dispose only after callers have awaited jobs and released every lease."""
        async with self._lock:
            if any(item.references for item in self._engines.values()):
                raise WorkspaceConflictError(
                    "Release workspace leases and await jobs before closing"
                )
            for item in self._engines.values():
                await item.engine.dispose()
            self._engines.clear()
            if self._catalog_engine is not None:
                await self._catalog_engine.dispose()
            self._catalog_engine = None
            self._catalog_sessions = None
            self._active_id = None

    @staticmethod
    def _uuid(identifier: UUID) -> UUID:
        if not isinstance(identifier, UUID) or identifier.int == 0:
            raise WorkspaceNotFoundError("Workspace UUID does not exist")
        return identifier

    async def _get(self, identifier: UUID) -> Workspace:
        self._uuid(identifier)
        async with self.catalog_sessions() as session:
            row = await session.get(Workspace, str(identifier))
            if row is None:
                raise WorkspaceNotFoundError("Workspace UUID does not exist")
            return row

    def _view(self, row: Workspace) -> WorkspaceView:
        return WorkspaceView(
            id=UUID(row.id),
            name=row.name,
            description=row.description,
            created_at=row.created_at.replace(tzinfo=UTC),
            active=UUID(row.id) == self._active_id,
        )

    async def list(self) -> list[WorkspaceView]:
        async with self.catalog_sessions() as session:
            rows = (
                await session.scalars(
                    select(Workspace).order_by(Workspace.created_at, Workspace.id)
                )
            ).all()
            return [self._view(row) for row in rows]

    async def get(self, identifier: UUID) -> WorkspaceView:
        return self._view(await self._get(identifier))

    async def _engine_for(self, identifier: UUID) -> _CachedEngine:
        if identifier not in self._engines:
            # UUID existence is checked by the caller before any path construction.
            directory = self.profile / "workspaces" / str(identifier)
            if not directory.exists() or not (directory / "data.db").exists():
                raise WorkspaceStartupError(
                    "Workspace database is missing. Restore its local backup before restarting"
                )
            assert_private_path(directory)
            engine = private_engine(directory / "data.db")
            try:
                await migrate(engine, "workspace")
            except BaseException:
                await engine.dispose()
                raise
            self._engines[identifier] = _CachedEngine(
                engine, async_sessionmaker(engine, expire_on_commit=False)
            )
        return self._engines[identifier]

    async def _create(self, data: WorkspaceCreate) -> WorkspaceView:
        identifier = uuid4()
        directory = self.profile / "workspaces" / str(identifier)
        engine = private_engine(directory / "data.db")
        try:
            await migrate(engine, "workspace")
            sessions = async_sessionmaker(engine, expire_on_commit=False)
            async with sessions.begin() as session:
                session.add(Notes(id=1, text=""))
            row = Workspace(
                id=str(identifier),
                name=data.name,
                description=data.description,
                created_at=datetime.now(UTC),
            )
            async with self.catalog_sessions.begin() as session:
                session.add(row)
            self._engines[identifier] = _CachedEngine(engine, sessions)
            return self._view(row)
        except BaseException:
            await engine.dispose()
            # This UUID is generated locally and never catalogued on failed creation.
            remove_private_tree(directory, self.profile / "workspaces")
            raise

    async def create(self, data: WorkspaceCreate) -> WorkspaceView:
        async with self._lock:
            return await self._create(data)

    async def activate(self, identifier: UUID) -> WorkspaceView:
        async with self._lock:
            row = await self._get(identifier)
            await self._engine_for(identifier)
            async with self.catalog_sessions.begin() as session:
                selection = await session.get(Selection, 1)
                assert selection is not None
                selection.workspace_id = str(identifier)
            self._active_id = identifier
            return self._view(row)

    async def delete(self, identifier: UUID) -> None:
        async with self._lock:
            await self._get(identifier)
            if identifier == self.active_id or (
                identifier in self._engines and self._engines[identifier].references
            ):
                raise WorkspaceConflictError("Active or leased workspace cannot be deleted")
            cached = self._engines.pop(identifier, None)
            if cached is not None:
                await cached.engine.dispose()
            # Commit catalog removal first. A filesystem failure leaves recoverable orphan
            # data; it never leaves a catalog row pointing to irreversibly erased data.
            async with self.catalog_sessions.begin() as session:
                row = await session.get(Workspace, str(identifier))
                await session.delete(row)
            remove_private_tree(
                self.profile / "workspaces" / str(identifier), self.profile / "workspaces"
            )

    async def lease(self, workspace_id: UUID | None = None) -> WorkspaceLease:
        async with self._lock:
            identifier = self.active_id if workspace_id is None else workspace_id
            await self._get(identifier)
            cached = await self._engine_for(identifier)
            cached.references += 1
            return WorkspaceLease(self, identifier, cached)

    async def get_notes(self, identifier: UUID) -> str:
        async with await self.lease(identifier) as lease:
            async with lease.sessions() as session:
                row = await session.get(Notes, 1)
                return row.text if row else ""

    async def set_notes(self, identifier: UUID, text: str) -> str:
        if not isinstance(text, str) or len(text) > 100000:
            raise ValueError("Notes must contain at most 100000 characters")
        async with await self.lease(identifier) as lease:
            async with lease.sessions.begin() as session:
                row = await session.get(Notes, 1)
                if row is None:
                    session.add(Notes(id=1, text=text))
                else:
                    row.text = text
        return text
