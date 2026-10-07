"""Two running analysis jobs, 32 waiting jobs and cooperative cancellation."""

from __future__ import annotations

import asyncio
import json
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Event
from typing import TypeVar
from uuid import UUID, uuid4

from pydantic import JsonValue, TypeAdapter

from backend.events import EventHub
from shared.schemas import SchemaModel

T = TypeVar("T")
_json: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)


class JobQueueFullError(RuntimeError):
    """Submission would exceed the advertised bounded analysis capacity."""


class JobSnapshot(SchemaModel):
    """Memory-only job result attached permanently to its original workspace."""

    id: UUID
    workspace_id: UUID
    tool_id: str
    status: str
    created_at: datetime
    updated_at: datetime
    progress: str = ""
    result: JsonValue = None
    error: str | None = None


@dataclass
class JobContext:
    cancel_event: Event
    hub: EventHub
    workspace_id: UUID
    job_id: UUID

    def check(self) -> None:
        if self.cancel_event.is_set():
            raise asyncio.CancelledError("Job cancelled.")

    async def progress(self, message: str) -> None:
        self.check()
        await self.hub.publish(
            "jobs",
            {"id": str(self.job_id), "progress": message[:1000]},
            workspace_id=self.workspace_id,
        )

    async def run_sync(self, function: Callable[[], T]) -> T:
        """Wait for an owned worker to finish before releasing its workspace lease."""
        self.check()
        worker = asyncio.create_task(asyncio.to_thread(function))
        try:
            result = await asyncio.shield(worker)
            self.check()
            return result
        except asyncio.CancelledError:
            self.cancel_event.set()
            await asyncio.gather(worker, return_exceptions=True)
            raise


@dataclass
class JobRecord:
    snapshot: JobSnapshot
    work: Callable[[JobContext], Awaitable[object]] | None
    context: JobContext
    cleanup: Callable[[], Awaitable[None]] | None
    task: asyncio.Task[None] | None = None
    started: bool = False
    finished: bool = False


class JobManager:
    def __init__(self, hub: EventHub) -> None:
        self.hub = hub
        self.records: dict[UUID, JobRecord] = {}
        self._queue: deque[UUID] = deque()
        self._active: set[UUID] = set()
        self._closed = False

    @property
    def active_count(self) -> int:
        return len(self._active)

    @property
    def queued_count(self) -> int:
        return len(self._queue)

    async def submit(
        self,
        tool_id: str,
        workspace_id: UUID,
        work: Callable[[JobContext], Awaitable[object]],
        *,
        cleanup: Callable[[], Awaitable[None]] | None = None,
    ) -> JobSnapshot:
        if self._closed or (len(self._active) >= 2 and len(self._queue) >= 32):
            raise JobQueueFullError(
                "Analysis capacity reached: two active and 32 queued. Try later."
            )
        if len(self.records) >= 1000:
            completed = next(
                (
                    key
                    for key, record in self.records.items()
                    if record.snapshot.status in ("succeeded", "failed", "cancelled")
                ),
                None,
            )
            if completed is None:
                raise JobQueueFullError("Job result capacity reached.")
            del self.records[completed]
        job_id, instant = uuid4(), datetime.now(UTC)
        snapshot = JobSnapshot(
            id=job_id,
            workspace_id=workspace_id,
            tool_id=tool_id,
            status="queued",
            created_at=instant,
            updated_at=instant,
        )
        record = JobRecord(
            snapshot, work, JobContext(Event(), self.hub, workspace_id, job_id), cleanup
        )
        self.records[job_id] = record
        if len(self._active) < 2:
            self._start(record)
        else:
            self._queue.append(job_id)
        await self._publish(record)
        return record.snapshot.model_copy(deep=True)

    def _start(self, record: JobRecord) -> None:
        self._active.add(record.snapshot.id)
        record.snapshot.status = "running"
        record.snapshot.updated_at = datetime.now(UTC)
        record.task = asyncio.create_task(self._run(record), name="toolkit-analysis")

    async def _run(self, record: JobRecord) -> None:
        record.started = True
        try:
            work = record.work
            assert work is not None
            record.snapshot.result = _json.validate_python(await work(record.context))
            json.dumps(record.snapshot.result, allow_nan=False)
            record.context.check()
            record.snapshot.status = "succeeded"
        except asyncio.CancelledError:
            record.snapshot.status = "cancelled"
            record.snapshot.result = None
        except Exception:
            # Unexpected exception text may contain inputs; never copy it into events.
            record.snapshot.status = "failed"
            record.snapshot.error = (
                "Analysis failed. Check input and readiness; retry with a new request ID."
            )
            record.snapshot.result = None
        finally:
            await self._finish(record)

    async def _finish(self, record: JobRecord) -> None:
        if not record.finished:
            record.finished = True
            record.work = None
            record.snapshot.updated_at = datetime.now(UTC)
            try:
                cleanup = record.cleanup
                record.cleanup = None
                if cleanup is not None:
                    await cleanup()
            except Exception:
                record.snapshot.status = "failed"
                record.snapshot.result = None
                record.snapshot.error = (
                    "Task cleanup failed. Restart before deleting this workspace."
                )
            finally:
                self._active.discard(record.snapshot.id)
                await self._publish(record)
                while self._queue and len(self._active) < 2 and not self._closed:
                    self._start(self.records[self._queue.popleft()])

    async def _publish(self, record: JobRecord) -> None:
        await self.hub.publish(
            "jobs",
            {
                "id": str(record.snapshot.id),
                "status": record.snapshot.status,
                "tool_id": record.snapshot.tool_id,
            },
            workspace_id=record.snapshot.workspace_id,
        )

    def get(self, job_id: UUID, workspace_id: UUID) -> JobSnapshot:
        record = self.records[job_id]
        if record.snapshot.workspace_id != workspace_id:
            raise KeyError("Job is not associated with this workspace.")
        return record.snapshot.model_copy(deep=True)

    def list(self, workspace_id: UUID) -> list[JobSnapshot]:
        return [
            record.snapshot.model_copy(deep=True)
            for record in self.records.values()
            if record.snapshot.workspace_id == workspace_id
        ]

    async def cancel(self, job_id: UUID, workspace_id: UUID) -> None:
        record = self.records[job_id]
        if record.snapshot.workspace_id != workspace_id:
            raise KeyError("Job is not associated with this workspace.")
        record.context.cancel_event.set()
        if job_id in self._queue:
            self._queue.remove(job_id)
            record.snapshot.status = "cancelled"
            record.snapshot.updated_at = datetime.now(UTC)
            await self._finish(record)
        elif record.task is not None and not record.task.done():
            record.task.cancel()
            await asyncio.gather(record.task, return_exceptions=True)
            if not record.started:
                record.snapshot.status = "cancelled"
                await self._finish(record)

    async def wait_idle(self) -> None:
        while self._active or self._queue:
            tasks = [self.records[key].task for key in tuple(self._active)]
            await asyncio.gather(
                *(task for task in tasks if task is not None), return_exceptions=True
            )

    async def clear(self, job_id: UUID, workspace_id: UUID) -> None:
        await self.cancel(job_id, workspace_id)
        record = self.records.pop(job_id)
        record.snapshot.result = None
        record.snapshot.progress = ""
        record.snapshot.error = None

    async def close(self) -> None:
        self._closed = True
        for job_id in tuple(self._queue) + tuple(self._active):
            await self.cancel(job_id, self.records[job_id].snapshot.workspace_id)
