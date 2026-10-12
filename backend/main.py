"""Authenticated application composition and orderly workspace/task lifetime."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, cast
from uuid import UUID

from fastapi import FastAPI, Header, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse

from backend.auth import authenticate_websocket, install_auth
from backend.database import SQLAlchemyMutationStore
from backend.events import EventHub, EventMessage, SlowConsumerError
from backend.jobs import JobManager, JobQueueFullError, JobSnapshot
from backend.mutations import (
    MutationCapacityError,
    MutationConflictError,
    MutationCoordinator,
    UnknownOutcomeError,
)
from backend.redaction import Redactor, install_logging_redaction
from backend.request_limits import RequestBodyLimit, WebSocketLimits
from backend.routers import (
    activity,
    connection,
    desktop,
    modules,
    payloads,
    reports,
    targets,
    tools,
    vault,
    workspaces,
)
from backend.services.activity_service import ActivityService
from backend.services.artifact_service import ArtifactService
from backend.services.desktop_service import DesktopService
from backend.services.metasploit_service import MetasploitService
from backend.services.module_service import ModuleService
from backend.services.payload_service import PayloadService
from backend.services.report_service import ReportService
from backend.services.rpc_transport import RpcFailure
from backend.services.tool_service import ToolService
from backend.services.vault_service import VaultAccessError, VaultService
from backend.services.workspace_service import (
    WorkspaceConflictError,
    WorkspaceNotFoundError,
    WorkspaceService,
)
from shared.schemas import HealthResponse


class PrivateAPI(FastAPI):
    """Document the bearer check performed by the shared REST authentication middleware."""

    def openapi(self) -> dict[str, Any]:
        if self.openapi_schema is None:
            schema = get_openapi(title=self.title, version=self.version, routes=self.routes)
            schema.setdefault("components", {}).setdefault("securitySchemes", {})["HTTPBearer"] = {
                "type": "http",
                "scheme": "bearer",
                "description": "Private instance token.",
            }
            schema["security"] = [{"HTTPBearer": []}]
            self.openapi_schema = schema
        return self.openapi_schema


def create_app(
    instance_token: str,
    instance_id: str,
    profile: Path,
    *,
    allowed_origins: set[str] | None = None,
) -> FastAPI:
    """Build a protected app; bootstrap supplies its reserved loopback TLS socket."""
    install_logging_redaction()
    if not instance_id:
        raise ValueError("Instance identity is required")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        service = WorkspaceService(profile)
        hub = EventHub()
        jobs = JobManager(hub)
        await service.start()
        app.state.workspaces = service
        app.state.events = hub
        app.state.jobs = jobs
        tool_service: ToolService | None = None
        framework = MetasploitService(profile, hub)
        app.state.framework = framework
        try:
            app.state.mutations = MutationCoordinator(
                SQLAlchemyMutationStore(service.catalog_sessions), profile=profile
            )
            app.state.desktop = DesktopService(profile, hub)
            await app.state.desktop.start()
            tool_service = ToolService(service, jobs)
            app.state.tools = tool_service
            app.state.modules = ModuleService(service, framework, hub, app.state.mutations)
            app.state.activity = ActivityService(app.state.modules)
            app.state.vault = VaultService(service, hub)
            await app.state.vault.start()
            app.state.artifacts = ArtifactService(service)
            app.state.reports = ReportService(
                service, app.state.artifacts, jobs, app.state.mutations
            )
            app.state.payloads = PayloadService(
                app.state.modules, app.state.artifacts, jobs, app.state.mutations
            )
            yield
        finally:
            if hasattr(app.state, "desktop"):
                await app.state.desktop.close()
            if hasattr(app.state, "vault"):
                await app.state.vault.close()
            try:
                await jobs.close()
            finally:
                try:
                    try:
                        try:
                            if hasattr(app.state, "activity"):
                                await app.state.activity.close()
                        finally:
                            await framework.close()
                    finally:
                        if tool_service is not None:
                            await tool_service.close()
                finally:
                    try:
                        await hub.close()
                    finally:
                        await service.close()

    app = PrivateAPI(
        title="Cybersecurity Fundamentals Toolkit",
        version="2.0.0",
        lifespan=lifespan,
        redoc_url=None,
        telemetry={
            "tracing": False,
            "metrics": False,
            "logs": False,
            "operation_spans": False,
            "auto_configure": False,
        },
    )
    app.state.profile = profile
    app.state.instance_id = instance_id
    app.state.instance_token = instance_token
    app.add_middleware(RequestBodyLimit)
    app.add_middleware(WebSocketLimits)
    origins = allowed_origins or set()
    install_auth(app, instance_token, allowed_origins=origins)
    app.include_router(workspaces.router, prefix="/api/v1")
    app.include_router(targets.router, prefix="/api/v1")
    app.include_router(tools.router, prefix="/api/v1")
    app.include_router(connection.router, prefix="/api/v1")
    app.include_router(modules.router, prefix="/api/v1")
    app.include_router(payloads.router, prefix="/api/v1")
    app.include_router(activity.router, prefix="/api/v1")
    app.include_router(vault.router, prefix="/api/v1")
    app.include_router(reports.router, prefix="/api/v1")
    app.include_router(desktop.router, prefix="/api/v1")

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Error input/context/message can repeat passwords or arbitrary uploaded contents.
        return JSONResponse(
            {
                "detail": "Invalid request fields.",
                "fields": [
                    {"location": list(item["loc"]), "type": item["type"]} for item in exc.errors()
                ],
            },
            status_code=422,
        )

    async def known_error(request: Request, exc: Exception) -> JSONResponse:
        if isinstance(exc, (MutationConflictError, UnknownOutcomeError, WorkspaceConflictError)):
            status, detail = 409, str(exc)
        elif isinstance(exc, VaultAccessError):
            status, detail = 423, str(exc)
        elif isinstance(exc, RpcFailure):
            status, detail = 503, str(exc)
        elif isinstance(exc, (MutationCapacityError, JobQueueFullError)):
            status, detail = 429, str(exc)
        elif isinstance(exc, (KeyError, WorkspaceNotFoundError)):
            status, detail = 404, "Requested item was not found in this workspace."
        else:
            status, detail = (
                422,
                "Invalid operation or input. Check the selected workspace and fields.",
            )
        return JSONResponse({"detail": Redactor().text(detail)}, status_code=status)

    for exception in (
        MutationConflictError,
        UnknownOutcomeError,
        WorkspaceConflictError,
        WorkspaceNotFoundError,
        MutationCapacityError,
        JobQueueFullError,
        KeyError,
        ValueError,
        RpcFailure,
        VaultAccessError,
    ):
        app.add_exception_handler(exception, known_error)

    @app.get("/api/v1/health", response_model=HealthResponse, tags=["system"])
    async def health() -> HealthResponse:
        """Identify this authenticated backend instance."""
        return HealthResponse(instance_id=instance_id)

    def state(request: Request) -> tuple[WorkspaceService, JobManager]:
        return cast(WorkspaceService, request.app.state.workspaces), cast(
            JobManager, request.app.state.jobs
        )

    @app.get("/api/v1/jobs", response_model=list[JobSnapshot], tags=["jobs"])
    async def list_jobs(request: Request, workspace_id: UUID | None = None) -> list[JobSnapshot]:
        """Get a snapshot for one workspace; job association never changes on selection."""
        service, jobs = state(request)
        return jobs.list(workspace_id or service.active_id)

    @app.get("/api/v1/jobs/{job_id}", response_model=JobSnapshot, tags=["jobs"])
    async def get_job(
        job_id: UUID, request: Request, workspace_id: UUID | None = None
    ) -> JobSnapshot:
        """Read a memory-only result in its original workspace."""
        service, jobs = state(request)
        return jobs.get(job_id, workspace_id or service.active_id)

    @app.post("/api/v1/jobs/{job_id}/cancel", status_code=204, tags=["jobs"])
    async def cancel_job(
        job_id: UUID,
        request: Request,
        request_id: Annotated[UUID, Header(alias="X-Request-ID")],
        workspace_id: UUID | None = None,
    ) -> Response:
        """Cancel a job and wait for its owned worker before releasing storage."""
        service, jobs = state(request)
        scope = workspace_id or service.active_id

        async def action() -> None:
            await jobs.cancel(job_id, scope)

        await request.app.state.mutations.execute(
            scope, request_id, "job.cancel", {"id": str(job_id)}, action
        )
        return Response(status_code=204)

    @app.delete("/api/v1/jobs/{job_id}", status_code=204, tags=["jobs"])
    async def clear_job(
        job_id: UUID,
        request: Request,
        request_id: Annotated[UUID, Header(alias="X-Request-ID")],
        workspace_id: UUID | None = None,
    ) -> Response:
        """Cancel and erase the result, including password-analysis results, from memory."""
        service, jobs = state(request)
        scope = workspace_id or service.active_id

        async def action() -> None:
            await jobs.clear(job_id, scope)

        await request.app.state.mutations.execute(
            scope, request_id, "job.clear", {"id": str(job_id)}, action
        )
        return Response(status_code=204)

    @app.get("/api/v1/events", response_model=list[EventMessage], tags=["events"])
    async def recent_events(
        request: Request, workspace_id: UUID | None = None
    ) -> list[EventMessage]:
        """Read bounded, redacted recent history after a stream disconnect."""
        hub = cast(EventHub, request.app.state.events)
        return [
            row for row in hub.recent if workspace_id is None or row.workspace_id == workspace_id
        ]

    @app.websocket("/ws/events")
    @app.websocket("/ws/jobs")
    async def event_stream(websocket: WebSocket) -> None:
        if not await authenticate_websocket(websocket, instance_token, origins):
            return
        channel = websocket.url.path.rsplit("/", 1)[-1]
        service = cast(WorkspaceService, websocket.app.state.workspaces)
        hub = cast(EventHub, websocket.app.state.events)
        raw_workspace = websocket.query_params.get("workspace_id")
        try:
            scope = UUID(raw_workspace) if raw_workspace else None
            if scope is not None:
                await service.get(scope)
            subscription = hub.subscribe(channel, scope)
        except (ValueError, WorkspaceNotFoundError, SlowConsumerError):
            await websocket.close(code=1008, reason="Stream scope unavailable; reload REST state.")
            return
        await websocket.accept()

        async def send_events() -> None:
            while True:
                await websocket.send_json((await subscription.receive()).model_dump(mode="json"))

        async def detect_disconnect() -> None:
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    return
                await websocket.close(code=1003, reason="This stream does not accept commands.")
                return

        sender = asyncio.create_task(send_events())
        receiver = asyncio.create_task(detect_disconnect())
        closed = asyncio.create_task(subscription.closed.wait())
        tasks = (sender, receiver, closed)
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if closed in done:
                raise SlowConsumerError("Reload REST state before reconnecting.")
            for task in done:
                task.result()
        except SlowConsumerError:
            # A blocked transport write must not prevent the overflow signal from closing us.
            sender.cancel()
            receiver.cancel()
            await asyncio.gather(sender, receiver, return_exceptions=True)
            try:
                async with asyncio.timeout(1):
                    await websocket.close(
                        code=1013, reason="Reload REST state before reconnecting."
                    )
            except (TimeoutError, WebSocketDisconnect, RuntimeError):
                pass
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            hub.unsubscribe(subscription)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    return app
