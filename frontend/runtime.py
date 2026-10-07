"""The desktop's sole backend bootstrap boundary; views use only API ViewModels."""

from __future__ import annotations

import asyncio
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal

from backend.bootstrap import (
    BackendInstance,
    prepare_backend,
    read_locator,
    verify_existing,
    wait_ready,
)
from backend.tls import TLSMaterial


class BackendThread(QThread):
    """Own the Uvicorn loop; the GUI and client run on their own threads."""

    ready = pyqtSignal(object, object, bool)
    failed = pyqtSignal(str)

    def __init__(self, profile: Path) -> None:
        super().__init__()
        self.profile = profile
        self.instance: BackendInstance | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_requested = False

    def run(self) -> None:
        try:
            asyncio.run(self._serve())
        except Exception as exc:
            # No credentials, headers, request bodies or library exception text enter this signal.
            self.failed.emit(
                f"Backend could not start ({type(exc).__name__}). "
                "Check profile permissions and prerequisites."
            )

    async def _serve(self) -> None:
        self._loop = asyncio.get_running_loop()
        existing = read_locator(self.profile)
        if existing is not None and await verify_existing(self.profile, existing):
            tls_path = self.profile / "tls"
            material = TLSMaterial(
                tls_path / "ca.pem",
                tls_path / "server.pem",
                tls_path / "server-key.pem",
                existing.certificate_fingerprint,
            )
            if not self._stop_requested:
                self.ready.emit(existing, material, False)
            return
        if self._stop_requested:
            return
        self.instance = prepare_backend(self.profile)
        server = asyncio.create_task(self.instance.serve())
        try:
            await wait_ready(self.instance.locator, self.instance.tls)
            if self._stop_requested:
                self.instance.stop()
            else:
                self.ready.emit(self.instance.locator, self.instance.tls, True)
            await server
        finally:
            self.instance.stop()
            await asyncio.gather(server, return_exceptions=True)

    def stop(self) -> None:
        """Stop only this thread's server; an authenticated existing instance is left running."""
        self._stop_requested = True
        if self._loop is not None and self._loop.is_running() and self.instance is not None:
            self._loop.call_soon_threadsafe(self.instance.stop)
