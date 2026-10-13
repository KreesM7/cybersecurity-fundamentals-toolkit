"""Authenticated, passive environment checks executed off the event loop."""

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Annotated, TypeVar, cast
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Request

from backend.services.secdesk_findings import SecDeskFindings
from backend.services.secdesk_service import SecDeskService
from shared.secdesk import (
    FindingImport,
    FindingImportResult,
    FindingSource,
    FindingView,
    NativeAudit,
    NativeHandle,
    NativeInput,
    NativeLaunch,
    NativeResize,
    NativeSnapshot,
)
from toolkit.secdesk.registry import Check, doctor, load_registry, prerequisites

router = APIRouter(prefix="/secdesk", tags=["secdesk"])


@router.get("/doctor", response_model=list[Check])
async def environment() -> list[Check]:
    def inspect() -> list[Check]:
        return [doctor(tool) for tool in load_registry()]

    try:
        return await asyncio.to_thread(inspect)
    except (OSError, ValueError) as error:
        raise HTTPException(
            503, "Tool manifests could not be loaded. Check installation."
        ) from error


T = TypeVar("T")


async def guarded(request: Request, action: Callable[[], Awaitable[T]]) -> T:
    try:
        return await action()
    except ValueError as error:
        detail = request.app.state.events.redactor.text(str(error))[:1000]
        raise HTTPException(422, detail) from error


RequestID = Annotated[UUID, Header(alias="X-Request-ID")]


def service(request: Request) -> SecDeskService:
    return cast(SecDeskService, request.app.state.secdesk)


@router.post("/launch", response_model=NativeSnapshot)
async def launch(data: NativeLaunch, request: Request, request_id: RequestID) -> NativeSnapshot:
    async def action() -> NativeSnapshot:
        return await guarded(request, lambda: service(request).open(data))

    result = await request.app.state.mutations.execute(
        data.workspace_id, request_id, "secdesk.launch", data.model_dump(mode="json"), action
    )
    return NativeSnapshot.model_validate_json(json.dumps(result))


@router.get("/session/{session_id}", response_model=NativeSnapshot)
async def snapshot(session_id: UUID, workspace_id: UUID, request: Request) -> NativeSnapshot:
    return service(request).snapshot(NativeHandle(id=session_id, workspace_id=workspace_id))


@router.post("/input", response_model=NativeSnapshot)
async def input_text(data: NativeInput, request: Request, request_id: RequestID) -> NativeSnapshot:
    async def action() -> NativeSnapshot:
        return await guarded(request, lambda: service(request).input(data))

    payload = {
        "id": str(data.id),
        "workspace_id": str(data.workspace_id),
        "text": data.text.get_secret_value(),
    }
    result = await request.app.state.mutations.execute(
        data.workspace_id, request_id, "secdesk.input", payload, action, secret=True
    )
    return NativeSnapshot.model_validate_json(json.dumps(result))


@router.post("/resize", response_model=NativeSnapshot)
async def resize(data: NativeResize, request: Request, request_id: RequestID) -> NativeSnapshot:
    async def action() -> NativeSnapshot:
        return await guarded(request, lambda: service(request).resize(data))

    result = await request.app.state.mutations.execute(
        data.workspace_id,
        request_id,
        "secdesk.resize",
        data.model_dump(mode="json"),
        action,
        secret=True,
    )
    return NativeSnapshot.model_validate_json(json.dumps(result))


@router.post("/close", response_model=NativeSnapshot)
async def close(data: NativeHandle, request: Request, request_id: RequestID) -> NativeSnapshot:
    async def action() -> NativeSnapshot:
        return await guarded(request, lambda: service(request).stop(data))

    result = await request.app.state.mutations.execute(
        data.workspace_id,
        request_id,
        "secdesk.close",
        data.model_dump(mode="json"),
        action,
        secret=True,
    )
    return NativeSnapshot.model_validate_json(json.dumps(result))


@router.get("/audit", response_model=list[NativeAudit])
async def audit(workspace_id: UUID, request: Request) -> list[NativeAudit]:
    return await service(request).audit(workspace_id)


@router.get("/sessions", response_model=list[NativeSnapshot])
async def sessions(workspace_id: UUID, request: Request) -> list[NativeSnapshot]:
    await service(request).workspaces.get(workspace_id)
    return [
        item.snapshot.model_copy()
        for item in service(request).owned.values()
        if item.snapshot.workspace_id == workspace_id
    ]


@router.get("/companion/ports")
async def companion_ports() -> list[dict[str, object]]:
    from toolkit.secdesk.companion import ports

    try:
        return [port.model_dump() for port in await asyncio.to_thread(ports)]
    except (OSError, ImportError) as error:
        raise HTTPException(
            503, "USB metadata unavailable; reinstall the serial runtime"
        ) from error


@router.post("/console")
async def record_console(
    data: NativeLaunch, request: Request, request_id: RequestID
) -> dict[str, str]:
    async def action() -> dict[str, str]:
        await guarded(request, lambda: service(request).record_console(data))
        return {"status": "acknowledged"}

    result = await request.app.state.mutations.execute(
        data.workspace_id, request_id, "secdesk.console", data.model_dump(mode="json"), action
    )
    return cast(dict[str, str], result)


@router.get("/findings")
async def finding_list(workspace_id: UUID, request: Request) -> list[FindingView]:
    return await cast(SecDeskFindings, request.app.state.secdesk_findings).listing(workspace_id)


async def import_findings(
    data: FindingImport, request: Request, request_id: UUID
) -> FindingImportResult:
    async def action() -> FindingImportResult:
        return await cast(SecDeskFindings, request.app.state.secdesk_findings).import_records(data)

    result = await request.app.state.mutations.execute(
        data.workspace_id,
        request_id,
        "secdesk.findings.import",
        data.model_dump(mode="json"),
        action,
        secret=True,
    )
    return FindingImportResult.model_validate_json(json.dumps(result))


@router.post("/findings/import", response_model=FindingImportResult)
async def finding_import(
    data: FindingImport, request: Request, request_id: RequestID
) -> FindingImportResult:
    return await import_findings(data, request, request_id)


@router.post("/findings/upload", response_model=FindingImportResult)
async def finding_upload(request: Request, request_id: RequestID) -> FindingImportResult:
    from pathlib import PurePosixPath

    from starlette.datastructures import UploadFile
    from starlette.formparsers import MultiPartException

    from backend.routers.tools import RAMMultipart
    from toolkit.secdesk.findings import read_findings

    parser = RAMMultipart(
        request.headers, request.stream(), max_files=1, max_fields=1, max_part_size=16384
    )
    try:
        form = await parser.parse()
    except MultiPartException as error:
        raise HTTPException(422, "Send one normalized findings file and JSON options") from error
    try:
        upload, raw = form.get("file"), form.get("options")
        if not isinstance(upload, UploadFile) or not isinstance(raw, str):
            raise HTTPException(422, "Send a file and source options")
        content = await upload.read(5 * 1024 * 1024 + 1)
        if len(content) > 5 * 1024 * 1024:
            raise HTTPException(413, "Findings file exceeds 5 MiB")
        try:
            source = FindingSource.model_validate_json(raw)
            suffix = PurePosixPath(upload.filename or "").suffix
            records = await asyncio.to_thread(read_findings, content, suffix)
        except ValueError as error:
            raise HTTPException(
                422, "Malformed findings; use the documented normalized format"
            ) from error
        return await import_findings(
            FindingImport(**source.model_dump(), records=records), request, request_id
        )
    finally:
        await form.close()


@router.get("/prerequisites", response_model=list[Check])
async def startup_prerequisites() -> list[Check]:
    return await asyncio.to_thread(prerequisites)
