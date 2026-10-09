"""Typed browser endpoints, not an arbitrary RPC method gateway."""

from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Header, Query, Request

from backend.services.module_service import ModuleService
from shared.modules import (
    FavoriteChange,
    ModuleDetail,
    ModuleKind,
    ModuleLaunch,
    ModuleLibrary,
    ModulePath,
    ModuleRun,
    ModuleSearch,
    Rank,
)

router = APIRouter(prefix="/modules", tags=["modules"])
RequestID = Annotated[UUID, Header(alias="X-Request-ID")]


def service(request: Request) -> ModuleService:
    return cast(ModuleService, request.app.state.modules)


@router.get("/search", response_model=ModuleSearch)
async def search(
    request: Request,
    query: Annotated[str, Query(max_length=200, pattern=r"^[^\x00-\x1f]*$")] = "",
    kind: ModuleKind = "",
    rank: Rank = "",
    platform: Annotated[str, Query(max_length=50, pattern=r"^[A-Za-z0-9_-]*$")] = "",
) -> ModuleSearch:
    return await service(request).search(query, kind, rank, platform)


@router.get("/info", response_model=ModuleDetail)
async def info(request: Request, path: Annotated[str, Query(max_length=200)]) -> ModuleDetail:
    return await service(request).detail(ModulePath(path=path).path)


@router.get("/library", response_model=ModuleLibrary)
async def library(request: Request, workspace_id: UUID | None = None) -> ModuleLibrary:
    return await service(request).library(workspace_id or request.app.state.workspaces.active_id)


@router.post("/favorites", response_model=ModuleLibrary)
async def favorite(
    request: Request, data: FavoriteChange, request_id: RequestID, workspace_id: UUID | None = None
) -> ModuleLibrary:
    workspace = workspace_id or request.app.state.workspaces.active_id

    async def action() -> ModuleLibrary:
        return await service(request).favorite(workspace, data)

    result = await request.app.state.mutations.execute(
        workspace, request_id, "module.favorite", data.model_dump(mode="json"), action
    )
    return ModuleLibrary.model_validate(result)


@router.post("/run", response_model=ModuleLaunch)
async def launch(request: Request, data: ModuleRun, request_id: RequestID) -> ModuleLaunch:
    return await service(request).launch(data, request_id)
