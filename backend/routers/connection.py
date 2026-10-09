"""Explicit framework connection; passwords are never returned in API responses."""

from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Header, Request

from backend.services.metasploit_service import MetasploitService
from shared.framework import Confirmation, ConnectionStatus, RpcConnect

router = APIRouter(prefix="/connection", tags=["connection"])
RequestID = Annotated[UUID, Header(alias="X-Request-ID")]


def service(request: Request) -> MetasploitService:
    return cast(MetasploitService, request.app.state.framework)


@router.get("", response_model=ConnectionStatus)
async def status(request: Request) -> ConnectionStatus:
    return service(request).status()


@router.post("/connect", response_model=ConnectionStatus)
async def connect(data: RpcConnect, request: Request, request_id: RequestID) -> ConnectionStatus:
    workspace = request.app.state.workspaces.active_id

    async def action() -> ConnectionStatus:
        return await service(request).connect(data)

    payload = data.model_dump(mode="json")
    payload["password"] = data.password.get_secret_value() if data.password else None
    result = await request.app.state.mutations.execute(
        workspace, request_id, "framework.connect", payload, action, secret=True
    )
    return ConnectionStatus.model_validate(result)


@router.post("/disconnect", response_model=ConnectionStatus)
async def disconnect(
    request: Request, request_id: RequestID, data: Confirmation
) -> ConnectionStatus:
    async def action() -> ConnectionStatus:
        return await service(request).disconnect(confirmed=data.confirmed)

    result = await request.app.state.mutations.execute(
        request.app.state.workspaces.active_id,
        request_id,
        "framework.disconnect",
        data.model_dump(mode="json"),
        action,
    )
    return ConnectionStatus.model_validate(result)


@router.get("/shutdown-check")
async def shutdown_check(request: Request) -> dict[str, bool]:
    return {"confirmation_required": await service(request).shutdown_check()}


@router.post("/fallback", response_model=ConnectionStatus)
async def fallback(data: Confirmation, request: Request, request_id: RequestID) -> ConnectionStatus:
    async def action() -> ConnectionStatus:
        return await service(request).connect_fallback(confirmed=data.confirmed)

    result = await request.app.state.mutations.execute_external(
        request.app.state.workspaces.active_id,
        request_id,
        "framework.fallback",
        data.model_dump(mode="json"),
        action,
    )
    return ConnectionStatus.model_validate(result)
