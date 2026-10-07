"""Target endpoints capture active workspace IDs before mutation replay or async dispatch."""

import hashlib
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, File, Header, Query, Request, Response, UploadFile
from pydantic import JsonValue

from backend.services.target_service import MAX_XML_BYTES, TargetService
from shared.workspaces import (
    TargetBulk,
    TargetCreate,
    TargetStatus,
    TargetTransfer,
    TargetUpdate,
    TargetView,
)

router = APIRouter(prefix="/targets", tags=["targets"])
RequestID = Annotated[UUID, Header(alias="X-Request-ID")]


def service(request: Request) -> TargetService:
    workspaces = request.app.state.workspaces
    return TargetService(workspaces, workspaces.active_id)


Service = Annotated[TargetService, Depends(service)]


@router.get("/", response_model=list[TargetView])
async def listing(
    targets: Service,
    status: TargetStatus | None = None,
    query: Annotated[str, Query(max_length=253)] = "",
) -> list[TargetView]:
    return await targets.list(status, query)


@router.post("/", status_code=201, response_model=TargetView)
async def create(
    data: TargetCreate, request: Request, request_id: RequestID, targets: Service
) -> TargetView:
    async def action() -> TargetView:
        return await targets.create(data)

    result = await request.app.state.mutations.execute(
        targets.workspace_id, request_id, "target.create", data.model_dump(mode="json"), action
    )
    return TargetView.model_validate(result)


@router.post("/bulk", status_code=201, response_model=list[TargetView])
async def bulk(
    data: TargetBulk, request: Request, request_id: RequestID, targets: Service
) -> list[TargetView]:
    async def action() -> list[JsonValue]:
        return [row.model_dump(mode="json") for row in await targets.bulk(data)]

    result = await request.app.state.mutations.execute(
        targets.workspace_id, request_id, "target.bulk", data.model_dump(mode="json"), action
    )
    return [TargetView.model_validate(row) for row in result]


@router.post("/import/nmap", status_code=201, response_model=list[TargetView])
async def import_nmap(
    request: Request, request_id: RequestID, targets: Service, file: Annotated[UploadFile, File()]
) -> list[TargetView]:
    try:
        data = await file.read(MAX_XML_BYTES + 1)
    finally:
        await file.close()
    # Validate the complete document before reservation, then persist it atomically.
    records = targets.parse_nmap(data)

    async def action() -> list[JsonValue]:
        return [row.model_dump(mode="json") for row in await targets.add_many(records)]

    result = await request.app.state.mutations.execute(
        targets.workspace_id,
        request_id,
        "target.import-nmap",
        {"sha256": hashlib.sha256(data).hexdigest()},
        action,
    )
    return [TargetView.model_validate(row) for row in result]


@router.get("/export")
async def export(targets: Service, format: Literal["json", "csv", "nmap"] = "json") -> Response:
    data, media_type = await targets.export(format)
    return Response(data, media_type=media_type)


@router.get("/{identifier}", response_model=TargetView)
async def get(identifier: UUID, targets: Service) -> TargetView:
    return await targets.get(identifier)


@router.patch("/{identifier}", response_model=TargetView)
async def update(
    identifier: UUID, data: TargetUpdate, request: Request, request_id: RequestID, targets: Service
) -> TargetView:
    async def action() -> TargetView:
        return await targets.update(identifier, data)

    result = await request.app.state.mutations.execute(
        targets.workspace_id,
        request_id,
        "target.update",
        {"id": str(identifier), "changes": data.model_dump(mode="json", exclude_unset=True)},
        action,
    )
    return TargetView.model_validate(result)


@router.delete("/{identifier}", status_code=204)
async def delete(
    identifier: UUID, request: Request, request_id: RequestID, targets: Service
) -> Response:
    async def action() -> None:
        await targets.delete(identifier)

    await request.app.state.mutations.execute(
        targets.workspace_id, request_id, "target.delete", {"id": str(identifier)}, action
    )
    return Response(status_code=204)


@router.post("/{identifier}/use-as-rhosts", response_model=TargetTransfer)
async def use_as_rhosts(
    identifier: UUID, request: Request, request_id: RequestID, targets: Service
) -> TargetTransfer:
    async def action() -> TargetTransfer:
        target = await targets.get(identifier)
        result = TargetTransfer(
            target_id=identifier, workspace_id=targets.workspace_id, rhosts=target.address
        )
        await request.app.state.events.publish(
            "target-transfer", result.model_dump(mode="json"), workspace_id=targets.workspace_id
        )
        return result

    result = await request.app.state.mutations.execute(
        targets.workspace_id, request_id, "target.use-as-rhosts", {"id": str(identifier)}, action
    )
    return TargetTransfer.model_validate(result)
