"""Seven-tool presentation state; all I/O belongs to the client worker."""

import asyncio
import ssl
from uuid import UUID

import httpx
from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from frontend.viewmodels.base_vm import BaseViewModel
from shared.tools import EmptyResponse, InterfacesList, ToolJob, ToolOptions, ToolsList


class ToolsViewModel(BaseViewModel):
    tools_changed = pyqtSignal(object)
    interfaces_changed = pyqtSignal(object)
    job_changed = pyqtSignal(str, object)
    tool_error = pyqtSignal(str, str)

    def __init__(
        self,
        base_url: str,
        ssl_context: ssl.SSLContext,
        instance_token: str,
        *,
        transport: httpx.ASGITransport | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(base_url, ssl_context, instance_token, transport=transport, parent=parent)
        self._jobs: dict[str, ToolJob] = {}
        self._pending: dict[UUID, tuple[str, str, int]] = {}
        self._generation: dict[str, int] = {}
        self._polling: set[str] = set()
        self._cancel_pending: set[tuple[str, int]] = set()
        self.mutation_completed.connect(self._receive)
        self.request_failed.connect(self._failed)
        self._timer = QTimer(self)
        self._timer.setInterval(400)
        self._timer.timeout.connect(self._poll)
        self._timer.start()

    def refresh_tools(self) -> None:
        request_id = self.run_get("/api/v1/tools", ToolsList)
        self._pending[request_id] = ("tools", "", 0)

    def refresh_interfaces(self) -> None:
        request_id = self.run_get("/api/v1/tools/interfaces", InterfacesList)
        self._pending[request_id] = ("interfaces", "", 0)

    def submit(self, options: ToolOptions, filename: str | None = None) -> UUID:
        tool_id = options.kind
        self.clear(tool_id)
        generation = self._generation.get(tool_id, 0)
        if filename is None:
            request_id = self.run_mutation("POST", f"/api/v1/tools/{tool_id}/run", ToolJob, options)
        else:
            request_id = self.run_upload(
                f"/api/v1/tools/{tool_id}/upload", ToolJob, options, filename
            )
        self._pending[request_id] = ("submit", tool_id, generation)
        return request_id

    def cancel(self, tool_id: str) -> None:
        job = self._jobs.get(tool_id)
        if job is None:
            self._cancel_pending.add((tool_id, self._generation.get(tool_id, 0)))
            return
        if job is not None:
            request_id = self.run_mutation(
                "POST", self._path(job) + "/cancel" + self._scope(job), EmptyResponse
            )
            self._pending[request_id] = ("cancel", tool_id, self._generation.get(tool_id, 0))

    @staticmethod
    def _path(job: ToolJob) -> str:
        return f"/api/v1/jobs/{job.id}"

    @staticmethod
    def _scope(job: ToolJob) -> str:
        return f"?workspace_id={job.workspace_id}"

    def _erase(self, job: ToolJob) -> None:
        self.run_mutation("DELETE", self._path(job) + self._scope(job), EmptyResponse)

    def clear(self, tool_id: str) -> None:
        self._cancel_pending = {entry for entry in self._cancel_pending if entry[0] != tool_id}
        self._generation[tool_id] = self._generation.get(tool_id, 0) + 1
        job = self._jobs.pop(tool_id, None)
        self._polling.discard(tool_id)
        if job is not None:
            self._erase(job)

    def _receive(self, request_id: object, response: object) -> None:
        if not isinstance(request_id, UUID):
            return
        entry = self._pending.pop(request_id, None)
        if entry is None:
            return
        operation, tool_id, generation = entry
        if operation == "tools" and isinstance(response, ToolsList):
            self.tools_changed.emit(response.root)
        elif operation == "interfaces" and isinstance(response, InterfacesList):
            self.interfaces_changed.emit(response.root)
        elif isinstance(response, ToolJob):
            self._polling.discard(tool_id)
            if generation != self._generation.get(tool_id, 0):
                if operation == "submit":
                    self._erase(response)
                return
            self._jobs[tool_id] = response
            self.job_changed.emit(tool_id, response)
            if operation == "submit" and (tool_id, generation) in self._cancel_pending:
                self._cancel_pending.discard((tool_id, generation))
                self.cancel(tool_id)

    def _failed(self, request_id: object, message: str) -> None:
        if isinstance(request_id, UUID):
            entry = self._pending.pop(request_id, None)
            if entry is not None:
                _, tool_id, generation = entry
                self._polling.discard(tool_id)
                if generation == self._generation.get(tool_id, 0):
                    self.tool_error.emit(tool_id, message)

    def _poll(self) -> None:
        for tool_id, job in tuple(self._jobs.items()):
            if job.status in ("queued", "running") and tool_id not in self._polling:
                request_id = self.run_get(self._path(job) + self._scope(job), ToolJob)
                self._pending[request_id] = ("poll", tool_id, self._generation.get(tool_id, 0))
                self._polling.add(tool_id)

    def close(self) -> None:
        if not self.is_running:
            return
        self._timer.stop()
        # Drain this window's pending requests first, so late submissions are also erased.
        try:
            future = asyncio.run_coroutine_threadsafe(
                self._worker.clear_owned_jobs(), self._worker._loop
            )
            future.result(timeout=20)
        finally:
            self._jobs.clear()
            self._pending.clear()
            self._cancel_pending.clear()
            super().close()
