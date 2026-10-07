"""Catalog mutations share the zero UUID replay scope; notes belong to their own workspace."""

from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, Response

from backend.services.workspace_service import WorkspaceService
from shared.workspaces import WorkspaceCreate, WorkspaceNotes, WorkspaceView

router = APIRouter(prefix="/workspaces", tags=["workspaces"])
RequestID = Annotated[UUID, Header(alias="X-Request-ID")]
CATALOG_SCOPE = UUID(int=0)


def service(request: Request) -> WorkspaceService:
    return cast(WorkspaceService, request.app.state.workspaces)


Service = Annotated[WorkspaceService, Depends(service)]


@router.get("/", response_model=list[WorkspaceView])
async def listing(workspaces: Service) -> list[WorkspaceView]:
    return await workspaces.list()


@router.post("/", status_code=201, response_model=WorkspaceView)
async def create(
    data: WorkspaceCreate, request: Request, request_id: RequestID, workspaces: Service
) -> WorkspaceView:
    async def action() -> WorkspaceView:
        result = await workspaces.create(data)
        await request.app.state.events.publish(
            "workspace-created", result.model_dump(mode="json"), workspace_id=result.id
        )
        return result

    result = await request.app.state.mutations.execute(
        CATALOG_SCOPE, request_id, "workspace.create", data.model_dump(mode="json"), action
    )
    return WorkspaceView.model_validate(result)


@router.get("/{identifier}", response_model=WorkspaceView)
async def get(identifier: UUID, workspaces: Service) -> WorkspaceView:
    return await workspaces.get(identifier)


@router.delete("/{identifier}", status_code=204)
async def delete(
    identifier: UUID, request: Request, request_id: RequestID, workspaces: Service
) -> Response:
    async def action() -> None:
        await workspaces.delete(identifier)
        await request.app.state.events.publish(
            "workspace-deleted", {"id": str(identifier)}, workspace_id=identifier
        )

    await request.app.state.mutations.execute(
        CATALOG_SCOPE, request_id, "workspace.delete", {"id": str(identifier)}, action
    )
    return Response(status_code=204)


@router.post("/{identifier}/activate", response_model=WorkspaceView)
async def activate(
    identifier: UUID, request: Request, request_id: RequestID, workspaces: Service
) -> WorkspaceView:
    old_active = workspaces.active_id

    async def action() -> WorkspaceView:
        result = await workspaces.activate(identifier)
        await request.app.state.events.publish(
            "workspace-activated",
            {"previous_id": str(old_active), "id": str(identifier)},
            workspace_id=identifier,
        )
        return result

    result = await request.app.state.mutations.execute(
        CATALOG_SCOPE, request_id, "workspace.activate", {"id": str(identifier)}, action
    )
    return WorkspaceView.model_validate(result)


@router.get("/{identifier}/notes", response_model=WorkspaceNotes)
async def get_notes(identifier: UUID, workspaces: Service) -> WorkspaceNotes:
    return WorkspaceNotes(notes=await workspaces.get_notes(identifier))


@router.put("/{identifier}/notes", response_model=WorkspaceNotes)
async def set_notes(
    identifier: UUID,
    data: WorkspaceNotes,
    request: Request,
    request_id: RequestID,
    workspaces: Service,
) -> WorkspaceNotes:
    async def action() -> WorkspaceNotes:
        return WorkspaceNotes(notes=await workspaces.set_notes(identifier, data.notes))

    result = await request.app.state.mutations.execute(
        identifier, request_id, "workspace.notes", data.model_dump(mode="json"), action
    )
    return WorkspaceNotes.model_validate(result)
