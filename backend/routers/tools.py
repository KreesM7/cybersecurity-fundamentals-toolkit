"""Authenticated tool jobs; uploaded contents and secret mutations stay in RAM."""

import hashlib
import json
from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Request
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser

from backend.jobs import JobSnapshot
from backend.services.tool_service import MAX_FILE_BYTES, ToolService
from shared.tools import InterfaceView, PasswordOptions, ToolOptions, ToolView, options_adapter

router = APIRouter(prefix="/tools", tags=["tools"])
RequestID = Annotated[UUID, Header(alias="X-Request-ID")]


def service(request: Request) -> ToolService:
    return cast(ToolService, request.app.state.tools)


@router.get("", response_model=list[ToolView])
async def listing(request: Request) -> list[ToolView]:
    return await service(request).list()


@router.get("/interfaces", response_model=list[InterfaceView])
async def interfaces(request: Request) -> list[InterfaceView]:
    return await service(request).interfaces()


async def submit(
    tool_id: str,
    options: ToolOptions,
    request: Request,
    request_id: UUID,
    upload: bytes | None = None,
    filename: str = "",
) -> JobSnapshot:
    tools = service(request)
    workspace_id = tools.workspaces.active_id
    secret = isinstance(options, PasswordOptions)
    payload = (
        options.transport_dump()
        if isinstance(options, PasswordOptions)
        else options.model_dump(mode="json")
    )
    if upload is not None:
        payload = {
            "options": payload,
            "filename": filename,
            "sha256": hashlib.sha256(upload).hexdigest(),
        }

    async def action() -> JobSnapshot:
        try:
            return await tools.submit(tool_id, options, upload, filename, workspace_id=workspace_id)
        except ValueError as exc:
            raise HTTPException(422, detail=str(exc)) from exc

    result = await request.app.state.mutations.execute(
        workspace_id, request_id, f"tool.{tool_id}.run", payload, action, secret=secret
    )
    return JobSnapshot.model_validate_json(json.dumps(result))


@router.post("/{tool_id}/run", response_model=JobSnapshot, status_code=202)
async def run(
    tool_id: str, options: ToolOptions, request: Request, request_id: RequestID
) -> JobSnapshot:
    return await submit(tool_id, options, request, request_id)


class RAMMultipart(MultiPartParser):
    # The whole authenticated envelope is already bounded to 26 MiB by middleware.
    # Keep its <=25 MiB upload in RAM rather than SpooledTemporaryFile disk rollover.
    spool_max_size = 26 * 1024 * 1024


@router.post("/{tool_id}/upload", response_model=JobSnapshot, status_code=202)
async def upload(tool_id: str, request: Request, request_id: RequestID) -> JobSnapshot:
    parser = RAMMultipart(
        request.headers, request.stream(), max_files=1, max_fields=1, max_part_size=1024 * 1024
    )
    try:
        form = await parser.parse()
    except MultiPartException as exc:
        # The parser closes any partial upload buffers before propagating errors.
        raise HTTPException(
            422, detail="Invalid multipart upload. Send one file and one JSON options field."
        ) from exc
    try:
        file, raw_options = form.get("file"), form.get("options")
        if not isinstance(file, UploadFile) or not isinstance(raw_options, str):
            raise HTTPException(422, detail="Upload a file and JSON options.")
        data = await file.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise HTTPException(413, detail="Input exceeds the 25 MiB upload limit.")
        try:
            options = options_adapter.validate_json(raw_options)
        except ValueError as exc:
            raise HTTPException(422, detail="Invalid tool upload options.") from exc
        return await submit(tool_id, options, request, request_id, data, file.filename or "upload")
    finally:
        await form.close()
