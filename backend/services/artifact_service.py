"""UUID-owned artifact files; user filenames and paths are never storage identities."""

import asyncio
import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import select

from backend.models import Artifact
from backend.platform_utils import assert_private_path, atomic_private_write, protect_private_path
from backend.services.workspace_service import WorkspaceService
from shared.payloads import ArtifactView

MAX_ARTIFACT = 8 * 1024 * 1024


class ArtifactService:
    def __init__(self, workspaces: WorkspaceService) -> None:
        self.workspaces = workspaces

    async def create(
        self,
        workspace_id: UUID,
        name: str,
        data: bytes,
        media_type: str = "application/octet-stream",
        report_id: UUID | None = None,
    ) -> ArtifactView:
        if not data or len(data) > MAX_ARTIFACT or Path(name).name != name or len(name) > 200:
            raise ValueError("Invalid artifact")
        identifier = uuid4()
        async with await self.workspaces.lease(workspace_id) as lease:
            directory = self.workspaces.profile / "workspaces" / str(workspace_id) / "artifacts"
            protect_private_path(directory, directory=True)
            path = directory / str(identifier)
            write = asyncio.create_task(asyncio.to_thread(atomic_private_write, path, data))
            try:
                await asyncio.shield(write)
            except asyncio.CancelledError:
                from backend.jobs import _drain

                await _drain(write)
                path.unlink(missing_ok=True)
                raise
            digest = hashlib.sha256(data).hexdigest()
            try:
                async with lease.sessions.begin() as session:
                    session.add(
                        Artifact(
                            id=str(identifier),
                            name=name,
                            media_type=media_type,
                            report_id=str(report_id) if report_id else None,
                            job_id=None,
                            relative_path=str(identifier),
                            size_bytes=len(data),
                            sha256=digest,
                            created_at=datetime.now(UTC),
                        )
                    )
            except BaseException:
                path.unlink(missing_ok=True)
                raise
            return ArtifactView(
                id=identifier,
                workspace_id=workspace_id,
                name=name,
                media_type=media_type,
                size_bytes=len(data),
                sha256=digest,
            )

    async def list(self, workspace_id: UUID) -> list[ArtifactView]:
        async with await self.workspaces.lease(workspace_id) as lease:
            async with lease.sessions() as session:
                rows = await session.scalars(
                    select(Artifact).order_by(Artifact.created_at.desc()).limit(1000)
                )
                return [
                    ArtifactView(
                        id=UUID(row.id),
                        workspace_id=workspace_id,
                        name=row.name,
                        media_type=row.media_type,
                        size_bytes=row.size_bytes,
                        sha256=row.sha256,
                    )
                    for row in rows
                ]

    async def get(self, workspace_id: UUID, identifier: str | UUID) -> Path:
        identifier = UUID(str(identifier))
        async with await self.workspaces.lease(workspace_id) as lease:
            async with lease.sessions() as session:
                row = await session.get(Artifact, str(identifier))
                if row is None or row.relative_path != str(identifier):
                    raise KeyError("Artifact is not in this workspace")
                path = (
                    self.workspaces.profile
                    / "workspaces"
                    / str(workspace_id)
                    / "artifacts"
                    / str(identifier)
                )
                assert_private_path(path)
                if (
                    not path.is_file()
                    or path.stat().st_size != row.size_bytes
                    or row.size_bytes > MAX_ARTIFACT
                ):
                    raise ValueError("Artifact is unavailable or changed")
                return path

    async def read(self, workspace_id: UUID, identifier: UUID) -> bytes:
        # Hold the lease until bytes are read, so workspace deletion cannot race a download.
        async with await self.workspaces.lease(workspace_id):
            return await asyncio.to_thread((await self.get(workspace_id, identifier)).read_bytes)
