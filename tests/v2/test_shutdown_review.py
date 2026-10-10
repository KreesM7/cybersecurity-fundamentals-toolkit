"""Independent review regressions: pipe pressure, failed control channels and Qt ownership."""

import asyncio
import sys
import time
from threading import Event
from uuid import uuid4

import pytest

from backend.events import EventHub
from backend.jobs import JobContext
from backend.services.pty_transport import PtyTransport


async def test_payload_cancel_drains_full_output_pipe(tmp_path, monkeypatch):
    from backend.services import payload_service

    done = tmp_path / "reaped"
    fixture = tmp_path / "writer.py"
    fixture.write_text(
        "import json,sys,threading,time,os,pathlib\n"
        "threading.Thread(target=lambda:(time.sleep(10),os._exit(5)),daemon=True).start()\n"
        "sys.stdin.readline()\n"
        "for _ in range(2000):\n"
        " print(json.dumps({'type':'progress','message':'x'*1000}),flush=True)\n"
        "sys.stdin.read()\n"
        f"pathlib.Path({str(done)!r}).write_text('reaped')\n"
    )
    monkeypatch.setattr(
        payload_service, "payload_host_argv", lambda: [sys.executable, str(fixture)]
    )
    entered = asyncio.Event()

    async def pause(_self, _message):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(JobContext, "progress", pause)
    context = JobContext(Event(), EventHub(), uuid4(), uuid4())
    task = asyncio.create_task(payload_service.run_generator({}, context))
    await asyncio.wait_for(entered.wait(), 10)
    await asyncio.sleep(0.2)  # helper fills the pipe while progress delivery is paused
    start = time.monotonic()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert time.monotonic() - start < 5
    assert done.read_text() == "reaped"


@pytest.mark.parametrize("failure", [OSError, TimeoutError, ValueError])
async def test_pty_failed_cancel_helper_still_closes_and_reaps(tmp_path, monkeypatch, failure):
    from backend.services import pty_transport

    fixture = tmp_path / "pty.py"
    fixture.write_text(
        "import json,sys\n"
        f"print(json.dumps({{'v':1,'type':'ready','id':'{uuid4()}','version':'6.5.3'}}),flush=True)\n"
        "sys.stdin.read()\nprint('x'*300000,flush=True)\n"
    )

    async def failed(*_args, **_kwargs):
        raise failure("fixture")

    monkeypatch.setattr(pty_transport, "run_process", failed)
    transport = PtyTransport(
        [sys.executable, str(fixture)], lambda _: None, cancel_argv=["fixture"]
    )
    await transport.start()
    await asyncio.wait_for(transport.close(), 5)
    assert transport.process.returncode == 0
    assert transport.identity is None


def test_desktop_retains_backend_and_processes_events_past_old_shutdown_budget(tmp_path):
    from PyQt6.QtCore import QTimer
    from PyQt6.QtWidgets import QApplication, QLabel

    from frontend.runtime import BackendThread, finish_backend

    class DelayedBackend(BackendThread):
        def run(self):
            self.msleep(15200)

    application = QApplication.instance() or QApplication([])
    status = QLabel()
    backend = DelayedBackend(tmp_path)
    ticks = []
    timer = QTimer()
    timer.timeout.connect(lambda: ticks.append(True))
    timer.start(100)
    backend.start()
    try:
        finish_backend(backend, application, status)
        assert not backend.isRunning()
        assert len(ticks) >= 100
        assert not status.isVisible()
    finally:
        timer.stop()
        backend.wait()


async def test_artifact_download_rejects_same_size_tampering(tmp_path):
    from backend.main import create_app

    app = create_app("e" * 64, "artifact-integrity", tmp_path)
    async with app.router.lifespan_context(app):
        scope = app.state.workspaces.active_id
        artifact = await app.state.artifacts.create(scope, "fixture.bin", b"original")
        path = await app.state.artifacts.get(scope, artifact.id)
        path.write_bytes(b"modified")
        with pytest.raises(ValueError, match="changed"):
            await app.state.artifacts.read(scope, artifact.id)
