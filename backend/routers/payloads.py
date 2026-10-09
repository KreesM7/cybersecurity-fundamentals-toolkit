"""Generation jobs and authenticated managed downloads."""

from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Header, Request, Response

from backend.jobs import JobSnapshot
from backend.services.artifact_service import ArtifactService
from backend.services.payload_service import PayloadService
from shared.payloads import ArtifactView, PayloadCatalog, PayloadRequest

router = APIRouter(tags=["payloads", "artifacts"])


@router.get("/payloads/catalog", response_model=PayloadCatalog)
async def catalog(request: Request) -> PayloadCatalog:
    return await cast(PayloadService, request.app.state.payloads).catalog()


@router.post("/payloads/generate", response_model=JobSnapshot)
async def generate(
    request: Request,
    data: PayloadRequest,
    request_id: Annotated[UUID, Header(alias="X-Request-ID")],
) -> JobSnapshot:
    return await cast(PayloadService, request.app.state.payloads).generate(data, request_id)


@router.get("/artifacts", response_model=list[ArtifactView])
async def artifacts(request: Request, workspace_id: UUID) -> list[ArtifactView]:
    return await cast(ArtifactService, request.app.state.artifacts).list(workspace_id)


@router.get("/artifacts/{identifier}/download")
async def download(request: Request, identifier: UUID, workspace_id: UUID) -> Response:
    data = await cast(ArtifactService, request.app.state.artifacts).read(workspace_id, identifier)
    return Response(
        data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment", "X-Content-Type-Options": "nosniff"},
    )
