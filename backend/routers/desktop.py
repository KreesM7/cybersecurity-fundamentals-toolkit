"""Authenticated desktop preferences, counts and release notifications."""

from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Header, Request
from sqlalchemy import func, select

from backend.models import RemoteSession, Report, Target
from backend.services.desktop_service import DesktopService
from backend.services.workspace_service import WorkspaceService
from shared.desktop import (
    DashboardSummary,
    DesktopSettings,
    UpdateNotice,
    UpdateProgress,
    UpdateRequest,
)

router = APIRouter(tags=["desktop"])


@router.get("/settings", response_model=DesktopSettings)
async def settings(request: Request) -> DesktopSettings:
    return cast(DesktopService, request.app.state.desktop).settings.model_copy()


@router.put("/settings", response_model=DesktopSettings)
async def save_settings(
    request: Request,
    data: DesktopSettings,
    request_id: Annotated[UUID, Header(alias="X-Request-ID")],
) -> DesktopSettings:
    async def action() -> DesktopSettings:
        return await cast(DesktopService, request.app.state.desktop).update(data)

    result = await request.app.state.mutations.execute(
        UUID(int=0), request_id, "settings.save", data.model_dump(mode="json"), action
    )
    return DesktopSettings.model_validate(result)


@router.get("/updates", response_model=UpdateNotice)
async def updates(request: Request) -> UpdateNotice:
    return cast(DesktopService, request.app.state.desktop).visible_notice()


@router.get("/dashboard", response_model=DashboardSummary)
async def dashboard(request: Request, workspace_id: UUID) -> DashboardSummary:
    service = cast(WorkspaceService, request.app.state.workspaces)
    async with await service.lease(workspace_id) as lease:
        async with lease.sessions() as session:
            counts = [
                int(await session.scalar(select(func.count()).select_from(model)) or 0)
                for model in (Target, RemoteSession, Report)
            ]
    return DashboardSummary(
        workspace_id=workspace_id,
        targets=counts[0],
        recorded_sessions=counts[1],
        saved_reports=counts[2],
        running_jobs=sum(
            row.status in {"queued", "running", "cancelling"}
            for row in request.app.state.jobs.list(workspace_id)
        ),
    )


@router.get("/updates/progress", response_model=UpdateProgress)
async def update_progress(request: Request) -> UpdateProgress:
    return cast(DesktopService, request.app.state.desktop).updater.progress.model_copy()


@router.post("/updates/download", response_model=UpdateProgress, status_code=202)
async def download_update(
    request: Request,
    data: UpdateRequest,
    request_id: Annotated[UUID, Header(alias="X-Request-ID")],
) -> UpdateProgress:
    async def action() -> UpdateProgress:
        return await cast(DesktopService, request.app.state.desktop).download_update(data.version)

    result = await request.app.state.mutations.execute(
        UUID(int=0), request_id, "update.download", data.model_dump(mode="json"), action
    )
    return UpdateProgress.model_validate(result)


@router.post("/updates/apply", response_model=UpdateProgress, status_code=202)
async def apply_update(
    request: Request,
    data: UpdateRequest,
    request_id: Annotated[UUID, Header(alias="X-Request-ID")],
) -> UpdateProgress:
    async def action() -> UpdateProgress:
        return await cast(DesktopService, request.app.state.desktop).apply_update(data.version)

    result = await request.app.state.mutations.execute(
        UUID(int=0), request_id, "update.apply", data.model_dump(mode="json"), action
    )
    return UpdateProgress.model_validate(result)
