"""Authenticated RAM-only static-inspection jobs with the shared lifecycle."""

import hashlib
import json
from pathlib import PurePosixPath
from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Request
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException

from backend.jobs import JobContext, JobManager, JobSnapshot
from backend.routers.tools import RAMMultipart
from backend.services.tool_service import MAX_FILE_BYTES
from backend.services.workspace_service import WorkspaceService
from shared.lowrea import LowreaOptions
from toolkit.lowrea.static import inspect_bytes
from toolkit.task_context import TaskContext

router = APIRouter(prefix="/lowrea", tags=["lowrea"])


@router.post("/inspect", response_model=JobSnapshot, status_code=202)
async def inspect(
    request: Request, request_id: Annotated[UUID, Header(alias="X-Request-ID")]
) -> JobSnapshot:
    parser = RAMMultipart(
        request.headers, request.stream(), max_files=1, max_fields=1, max_part_size=1024 * 1024
    )
    try:
        form = await parser.parse()
    except MultiPartException as error:
        raise HTTPException(
            422, detail="Send one artifact file and one JSON options field."
        ) from error
    try:
        artifact, raw = form.get("file"), form.get("options")
        if not isinstance(artifact, UploadFile) or not isinstance(raw, str):
            raise HTTPException(422, detail="Supply an artifact and inspection options.")
        try:
            options = LowreaOptions.model_validate_json(raw)
        except ValueError as error:
            raise HTTPException(422, detail="Invalid static-inspection options.") from error
        data = await artifact.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise HTTPException(413, detail="Desktop inspection uploads are limited to 25 MiB.")
        filename = PurePosixPath((artifact.filename or "artifact").replace("\\", "/")).name[:255]
        workspaces = cast(WorkspaceService, request.app.state.workspaces)
        workspace_id = options.workspace_id or workspaces.active_id

        async def action() -> JobSnapshot:
            lease = await workspaces.lease(workspace_id)

            async def work(context: JobContext) -> object:
                await context.progress("Inspecting static artifact")
                try:
                    evidence = await context.run_sync(
                        lambda: inspect_bytes(
                            data, options, filename, TaskContext(context.cancel_event)
                        )
                    )
                    return evidence.record()
                except ValueError as error:
                    return {"error": {"code": "invalid_artifact_or_range", "message": str(error)}}

            try:
                return await cast(JobManager, request.app.state.jobs).submit(
                    "lowrea", lease.workspace_id, work, cleanup=lease.release
                )
            except BaseException:
                await lease.release()
                raise

        result = await request.app.state.mutations.execute(
            workspace_id,
            request_id,
            "lowrea.inspect",
            {
                "options": options.model_dump(mode="json"),
                "filename": filename,
                "sha256": hashlib.sha256(data).hexdigest(),
            },
            action,
        )
        return JobSnapshot.model_validate_json(json.dumps(result))
    finally:
        await form.close()
