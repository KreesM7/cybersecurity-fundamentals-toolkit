"""Explicit scoped remote actions and private terminal reads."""

from typing import Annotated, Literal, cast
from uuid import UUID

from fastapi import APIRouter, Header, Query, Request
from pydantic import SecretStr

from backend.services.activity_service import ActivityService
from shared.activity import (
    ActionResult,
    ActivitySnapshot,
    ConsoleHandle,
    ConsoleOpen,
    RemoteAction,
    TerminalCommand,
    TerminalOutput,
)

router = APIRouter(prefix="/activity", tags=["activity"])
RequestID = Annotated[UUID, Header(alias="X-Request-ID")]


def service(request: Request) -> ActivityService:
    return cast(ActivityService, request.app.state.activity)


@router.get("", response_model=ActivitySnapshot)
async def snapshot(request: Request, workspace_id: UUID) -> ActivitySnapshot:
    return await service(request).snapshot(workspace_id)


@router.post("/claim", response_model=ActionResult)
async def claim(request: Request, data: RemoteAction, request_id: RequestID) -> ActionResult:
    async def action() -> ActionResult:
        await service(request).claim(data)
        return ActionResult(status="imported")

    value = await request.app.state.mutations.execute(
        data.workspace_id, request_id, "activity.claim", data.model_dump(mode="json"), action
    )
    return ActionResult.model_validate(value)


@router.post("/stop", response_model=ActionResult)
async def stop(request: Request, data: RemoteAction, request_id: RequestID) -> ActionResult:
    async def action() -> ActionResult:
        await service(request).stop(data)
        return ActionResult(status="stopped")

    value = await request.app.state.mutations.execute_external(
        data.workspace_id, request_id, "activity.stop", data.model_dump(mode="json"), action
    )
    return ActionResult.model_validate(value)


@router.post("/console", response_model=ConsoleHandle)
async def console(request: Request, data: ConsoleOpen, request_id: RequestID) -> ConsoleHandle:
    async def action() -> ConsoleHandle:
        return await service(request).open_console(data)

    value = await request.app.state.mutations.execute_external(
        data.workspace_id, request_id, "console.open", data.model_dump(mode="json"), action
    )
    return ConsoleHandle.model_validate(value)


@router.post("/command", response_model=ActionResult)
async def command(request: Request, data: TerminalCommand, request_id: RequestID) -> ActionResult:
    async def action() -> ActionResult:
        await service(request).command(data)
        return ActionResult(status="submitted")

    payload = data.model_dump(mode="json")
    payload["command"] = data.command.get_secret_value()
    value = await request.app.state.mutations.execute_external(
        data.workspace_id, request_id, "terminal.command", payload, action
    )
    return ActionResult.model_validate(value)


@router.post("/console/close", response_model=ActionResult)
async def close_console(
    request: Request, data: ConsoleHandle, request_id: RequestID
) -> ActionResult:
    async def action() -> ActionResult:
        await service(request).close_console(data)
        return ActionResult(status="closed")

    value = await request.app.state.mutations.execute_external(
        data.workspace_id, request_id, "console.close", data.model_dump(mode="json"), action
    )
    return ActionResult.model_validate(value)


@router.get("/output", response_model=TerminalOutput)
async def output(
    request: Request,
    workspace_id: UUID,
    framework_id: UUID,
    remote_id: Annotated[str, Query(pattern=r"^[0-9]{1,20}$")],
    kind: Literal["console", "shell", "meterpreter"],
    since: Annotated[int, Query(ge=0)] = 0,
) -> TerminalOutput:
    data = TerminalCommand(
        workspace_id=workspace_id,
        framework_id=framework_id,
        remote_id=remote_id,
        kind=kind,
        command=SecretStr(""),
    )
    return await service(request).output(data, since)


@router.get("/history", response_model=list[str])
async def history(request: Request, workspace_id: UUID) -> list[str]:
    return await service(request).history(workspace_id)
