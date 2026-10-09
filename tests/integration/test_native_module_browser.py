"""Actual metadata and launch against an owned loopback HTTP fixture in Toolkit-MSF."""

import asyncio
import os
from pathlib import Path
from uuid import uuid4

import pytest

from backend.main import create_app
from shared.modules import ModuleRun


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(
    os.name == "nt" or not Path("/opt/toolkit-msf/pty-host.py").exists(),
    reason="Dedicated native lab required",
)
async def test_native_search_metadata_and_loopback_module_launch(tmp_path):
    app = create_app("f" * 64, "module-lab", tmp_path)
    seen = asyncio.Event()

    async def respond(reader, writer):
        try:
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            seen.set()
            body = b"<html><title>Owned toolkit fixture</title></html>"
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(respond, "127.0.0.1", 0)
    async with server, app.router.lifespan_context(app):
        status = await app.state.framework.connect_fallback(confirmed=True)
        modules = app.state.modules
        matches = await modules.search("scanner/http/title", "auxiliary", "", "")
        assert any(row.path == "auxiliary/scanner/http/title" for row in matches.modules)
        detail = await modules.detail("auxiliary/scanner/http/title")
        assert any(item.name == "RHOSTS" for item in detail.options)
        result = await modules.launch(
            ModuleRun(
                path=detail.path,
                workspace_id=app.state.workspaces.active_id,
                framework_id=detail.framework_id,
                confirmed=True,
                options={"RHOSTS": "127.0.0.1", "RPORT": server.sockets[0].getsockname()[1]},
            ),
            uuid4(),
        )
        assert result.remote_job_id is not None and result.execution_id
        await asyncio.wait_for(seen.wait(), 10)
        assert status.instance_id == str(result.framework_id)
