"""GUI-thread ViewModel and its independently owned asyncio client thread."""

import asyncio
import ssl
from collections.abc import Mapping
from concurrent.futures import Future
from pathlib import Path
from uuid import UUID, uuid4

import httpx
from pydantic import BaseModel
from PyQt6.QtCore import QObject, QThread, pyqtSignal, pyqtSlot

from backend.redaction import Redactor
from frontend.api_client import MAX_UPLOAD_BYTES, ApiClient, ApiError, validate_connection
from frontend.ws_client import WebSocketClient
from shared.schemas import HealthResponse, SchemaModel
from shared.tools import EmptyResponse, ToolJob


class ClientWorker(QThread):
    """Own an asyncio loop and its client, delivering results through Qt signals."""

    health_received = pyqtSignal(object)
    message_received = pyqtSignal(object)
    mutation_completed = pyqtSignal(object, object)
    request_failed = pyqtSignal(object, str)
    failed = pyqtSignal(str)

    def __init__(
        self,
        base_url: str,
        context: ssl.SSLContext,
        token: str,
        transport: httpx.ASGITransport | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._connection = (base_url, context, token)
        self._transport = transport
        self._loop = asyncio.new_event_loop()
        self._client: ApiClient | None = None
        self._websocket: WebSocketClient | None = None
        self._closed = False
        self._owned_jobs: dict[UUID, UUID] = {}

    def run(self) -> None:
        asyncio.set_event_loop(self._loop)
        try:
            self._client = ApiClient(*self._connection, transport=self._transport)
            self._websocket = WebSocketClient(*self._connection)
            self._loop.run_forever()
        finally:
            self._loop.run_until_complete(self._shutdown())
            self._loop.run_until_complete(self._loop.shutdown_asyncgens())
            self._loop.run_until_complete(self._loop.shutdown_default_executor())
            self._loop.close()

    async def _health(self) -> None:
        try:
            if self._client is None:
                raise RuntimeError("API client has not started")
            self.health_received.emit(await self._client.health())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.failed.emit(f"Backend request failed ({type(exc).__name__})")

    def refresh_health(self) -> Future[None]:
        """Schedule without blocking the caller's GUI thread."""
        if self._closed:
            raise RuntimeError("Client worker is closed")
        return asyncio.run_coroutine_threadsafe(self._health(), self._loop)

    async def _watch(self, path: str) -> None:
        delay = 1
        while not self._closed:
            try:
                if self._websocket is None:
                    raise RuntimeError("Websocket client has not started")
                async for message in self._websocket.messages(path):
                    delay = 1
                    self.message_received.emit(message)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.failed.emit("Live updates disconnected; reloading state and reconnecting.")
            self.message_received.emit('{"topic":"resync"}')
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30)

    def watch_events(self, path: str) -> Future[None]:
        """Consume a stream on the client loop without blocking Qt."""
        if self._closed:
            raise RuntimeError("Client worker is closed")
        return asyncio.run_coroutine_threadsafe(self._watch(path), self._loop)

    async def _mutation(
        self,
        method: str,
        path: str,
        response_type: type[BaseModel],
        body: SchemaModel | None,
        request_id: UUID,
        headers: Mapping[str, str] | None,
    ) -> None:
        try:
            if self._client is None:
                raise RuntimeError("API client has not started")
            response = await self._client.request(
                method, path, response_type, body, request_id=request_id, headers=headers
            )
            if isinstance(response, ToolJob):
                self._owned_jobs[response.id] = response.workspace_id
            elif method == "DELETE" and path.startswith("/api/v1/jobs/"):
                self._owned_jobs.pop(UUID(path.split("/")[-1].split("?")[0]), None)
            self.mutation_completed.emit(request_id, response)
        except asyncio.CancelledError:
            raise
        except ApiError as exc:
            self.request_failed.emit(request_id, Redactor().text(str(exc)))
            self.failed.emit(Redactor().text(str(exc)))
        except Exception as exc:
            self.request_failed.emit(request_id, f"Backend action failed ({type(exc).__name__})")
            self.failed.emit(f"Backend action failed ({type(exc).__name__})")

    def run_mutation(
        self,
        method: str,
        path: str,
        response_type: type[BaseModel],
        body: SchemaModel | None,
        request_id: UUID,
        headers: Mapping[str, str] | None,
    ) -> Future[None]:
        """Schedule exactly one request using the action identity supplied by the GUI."""
        if self._closed:
            raise RuntimeError("Client worker is closed")
        return asyncio.run_coroutine_threadsafe(
            self._mutation(method, path, response_type, body, request_id, headers), self._loop
        )

    def run_get(self, path: str, response_type: type[BaseModel], request_id: UUID) -> Future[None]:
        return self.run_mutation("GET", path, response_type, None, request_id, None)

    async def _upload(
        self,
        path: str,
        response_type: type[BaseModel],
        body: SchemaModel,
        filename: str,
        request_id: UUID,
    ) -> None:
        try:
            if self._client is None:
                raise RuntimeError("API client has not started")

            def read() -> bytes:
                if not Path(filename).is_file():
                    raise FileNotFoundError("Choose a readable regular file.")
                with Path(filename).open("rb") as source:
                    return source.read(MAX_UPLOAD_BYTES + 1)

            content = await asyncio.to_thread(read)
            response = await self._client.upload(
                path, response_type, body, content, Path(filename).name, request_id=request_id
            )
            if isinstance(response, ToolJob):
                self._owned_jobs[response.id] = response.workspace_id
            self.mutation_completed.emit(request_id, response)
        except asyncio.CancelledError:
            raise
        except ApiError as exc:
            self.request_failed.emit(request_id, Redactor().text(str(exc)))
            self.failed.emit(Redactor().text(str(exc)))
        except OSError:
            self.request_failed.emit(
                request_id, "Selected file could not be read. Choose a readable regular file."
            )
            self.failed.emit("Selected file could not be read. Choose a readable regular file.")
        except Exception as exc:
            self.request_failed.emit(request_id, f"Backend upload failed ({type(exc).__name__})")
            self.failed.emit(f"Backend upload failed ({type(exc).__name__})")

    def run_upload(
        self,
        path: str,
        response_type: type[BaseModel],
        body: SchemaModel,
        filename: str,
        request_id: UUID,
    ) -> Future[None]:
        if self._closed:
            raise RuntimeError("Client worker is closed")
        return asyncio.run_coroutine_threadsafe(
            self._upload(path, response_type, body, filename, request_id), self._loop
        )

    async def _download(self, path: str, destination: str, request_id: UUID) -> None:
        try:
            if self._client is None:
                raise RuntimeError("Client unavailable")
            await self._client.download(path, destination)
            self.mutation_completed.emit(request_id, EmptyResponse())
        except asyncio.CancelledError:
            raise
        except Exception:
            self.request_failed.emit(
                request_id, "Could not save the artifact. Check the destination and retry."
            )

    def download(self, path: str, destination: str, request_id: UUID) -> None:
        if self._closed:
            raise RuntimeError("Client worker is closed")
        asyncio.run_coroutine_threadsafe(self._download(path, destination, request_id), self._loop)

    async def _shutdown(self) -> None:
        current = asyncio.current_task()
        pending = [task for task in asyncio.all_tasks() if task is not current]
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        if self._client is not None:
            await self._client.close()

    async def clear_owned_jobs(self) -> None:
        """Drain submissions, then erase every job created/observed by this tool client."""
        current = asyncio.current_task()
        pending = [task for task in asyncio.all_tasks() if task is not current]
        # No stream is required for tool polling; leave optional event readers to shutdown.
        actions = [
            task
            for task in pending
            if getattr(task.get_coro(), "__name__", "") in ("_mutation", "_upload")
        ]
        await asyncio.gather(*actions, return_exceptions=True)
        if self._client is not None:
            for job_id, workspace_id in tuple(self._owned_jobs.items()):
                try:
                    await self._client.request(
                        "DELETE",
                        f"/api/v1/jobs/{job_id}?workspace_id={workspace_id}",
                        EmptyResponse,
                        request_id=uuid4(),
                    )
                except ApiError:
                    pass  # Already cleared jobs return 404; remaining shutdown still proceeds.
        self._owned_jobs.clear()

    def close(self) -> None:
        """Cancel work, close sockets, stop the loop and join the owned thread."""
        if self._closed:
            return
        self._closed = True
        self._loop.call_soon_threadsafe(self._loop.stop)
        if not self.wait(5000):
            raise RuntimeError("API client did not shut down within five seconds")


class BaseViewModel(QObject):
    """Expose backend state through signals on the main Qt thread."""

    health_changed = pyqtSignal(object)
    message_received = pyqtSignal(object)
    mutation_completed = pyqtSignal(object, object)
    request_failed = pyqtSignal(object, str)
    error_changed = pyqtSignal(str)

    def __init__(
        self,
        base_url: str,
        ssl_context: ssl.SSLContext,
        instance_token: str,
        *,
        transport: httpx.ASGITransport | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        validate_connection(base_url, ssl_context, instance_token)
        self.health: HealthResponse | None = None
        self._worker = ClientWorker(base_url, ssl_context, instance_token, transport, self)
        self._worker.health_received.connect(self._accept_health)
        self._worker.message_received.connect(self._accept_message)
        self._worker.mutation_completed.connect(self._accept_mutation)
        self._worker.request_failed.connect(self.request_failed)
        self._worker.failed.connect(self.error_changed)
        self._worker.start()

    @pyqtSlot(object)
    def _accept_health(self, value: object) -> None:
        if not isinstance(value, HealthResponse):
            raise TypeError("Worker delivered an invalid health model")
        self.health = value
        self.health_changed.emit(value)

    @pyqtSlot()
    def refresh_health(self) -> None:
        """Ask the async client for current backend health."""
        self._worker.refresh_health()

    @pyqtSlot(object)
    def _accept_message(self, message: object) -> None:
        if not isinstance(message, (str, bytes)):
            raise TypeError("Worker delivered an invalid stream message")
        self.message_received.emit(message)

    def watch_events(self, path: str) -> None:
        """Receive API events through the owned async websocket worker."""
        self._worker.watch_events(path)

    @pyqtSlot(object, object)
    def _accept_mutation(self, request_id: object, response: object) -> None:
        if not isinstance(request_id, UUID) or not isinstance(response, BaseModel):
            raise TypeError("Worker delivered an invalid action result")
        self.mutation_completed.emit(request_id, response)

    def run_mutation(
        self,
        method: str,
        path: str,
        response_type: type[BaseModel],
        body: SchemaModel | None = None,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> UUID:
        """Create one action ID and queue its single authenticated mutation request."""
        if method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("Expected a mutation method")
        request_id = uuid4()
        self._worker.run_mutation(
            method,
            path,
            response_type,
            body.model_copy(deep=True) if body else None,
            request_id,
            dict(headers) if headers else None,
        )
        return request_id

    def run_get(self, path: str, response_type: type[BaseModel]) -> UUID:
        request_id = uuid4()
        self._worker.run_get(path, response_type, request_id)
        return request_id

    def run_upload(
        self, path: str, response_type: type[BaseModel], body: SchemaModel, filename: str
    ) -> UUID:
        request_id = uuid4()
        self._worker.run_upload(path, response_type, body, filename, request_id)
        return request_id

    @property
    def is_running(self) -> bool:
        return self._worker.isRunning()

    def close(self) -> None:
        """Shutdown is part of the owning window/application lifecycle."""
        self._worker.close()
