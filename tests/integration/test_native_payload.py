"""Generate, but never execute, an artifact with the dedicated installed msfvenom."""

import asyncio
import os
from pathlib import Path
from threading import Event
from uuid import uuid4

import pytest

from backend.events import EventHub
from backend.jobs import JobContext
from backend.services.payload_service import run_generator


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(
    not Path("/opt/toolkit-msf/payload-host.py").exists()
    and os.environ.get("TOOLKIT_MSF_INTEGRATION") != "1",
    reason="Dedicated generator required",
)
async def test_native_generation_and_cancellation():
    context = JobContext(Event(), EventHub(), uuid4(), uuid4())
    data = {
        "payload": "linux/x64/shell_reverse_tcp",
        "format": "raw",
        "encoder": "",
        "iterations": 1,
        "lhost": "127.0.0.1",
        "lport": 4444,
    }
    content = await run_generator(data, context)
    assert 16 < len(content) < 4096
    assert any(event.data.get("progress") for event in context.hub.recent)
    task = asyncio.create_task(run_generator(data, context))
    await asyncio.sleep(0.3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 15)


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(
    not Path("/opt/toolkit-msf/payload-host.py").exists()
    and os.environ.get("TOOLKIT_MSF_INTEGRATION") != "1",
    reason="Dedicated generator required",
)
async def test_native_generator_metadata_and_managed_output(tmp_path):
    from backend.main import create_app
    from shared.payloads import PayloadRequest

    app = create_app("f" * 64, "generator-lab", tmp_path)
    async with app.router.lifespan_context(app):
        connection = await app.state.framework.connect_fallback(confirmed=True)
        scope = app.state.workspaces.active_id
        job = await app.state.payloads.generate(
            PayloadRequest(
                workspace_id=scope,
                framework_id=connection.instance_id,
                payload="linux/x64/shell_reverse_tcp",
                format="raw",
                encoder="generic/none",
                lhost="127.0.0.1",
                lport=4444,
                confirmed=True,
            ),
            uuid4(),
        )
        for _ in range(300):
            snapshot = app.state.jobs.get(job.id, scope)
            if snapshot.status not in {"queued", "running"}:
                break
            await asyncio.sleep(0.1)
        assert snapshot.status == "succeeded", snapshot
        path = await app.state.artifacts.get(scope, snapshot.result["artifact_id"])
        assert 16 < path.stat().st_size < 4096
