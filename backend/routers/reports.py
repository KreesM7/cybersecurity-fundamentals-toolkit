"""Background report generation with stable mutation identities."""

from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Header, Request

from backend.jobs import JobSnapshot
from backend.services.report_service import ReportService
from shared.reports import ReportRequest

router = APIRouter(tags=["reports"])


@router.post("/reports/generate", response_model=JobSnapshot)
async def generate(
    request: Request, data: ReportRequest, request_id: Annotated[UUID, Header(alias="X-Request-ID")]
) -> JobSnapshot:
    return await cast(ReportService, request.app.state.reports).generate(data, request_id)
