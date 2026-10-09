"""Owned fixture exercises service ownership and real terminal calls; no remote OS executes."""

import asyncio
import os
import socket
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import SecretStr

from backend.main import create_app
from shared.activity import ConsoleOpen, RemoteAction, TerminalCommand
from shared.workspaces import WorkspaceCreate


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(
    os.name == "nt" or not Path("/opt/toolkit-msf/pty-host.py").exists(),
    reason="Dedicated native loopback lab required",
)
async def test_native_session_job_and_console_service(tmp_path):
    app = create_app("f" * 64, "activity-lab", tmp_path)
    async with app.router.lifespan_context(app):
        framework = app.state.framework
        activity = app.state.activity
        connection = await framework.connect_fallback(confirmed=True)
        identity = UUID(connection.instance_id)
        scope = app.state.workspaces.active_id
        console = await activity.open_console(
            ConsoleOpen(workspace_id=scope, framework_id=identity)
        )
        command = TerminalCommand(
            **console.model_dump(), kind="console", command=SecretStr("version")
        )
        await activity.command(command)
        output = []
        for _ in range(20):
            output.extend((await activity.output(command)).lines)
            if "Framework" in "\n".join(output):
                break
            await asyncio.sleep(0.1)
        assert "Framework" in "\n".join(output)
        await activity.close_console(console)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        job = await framework.run_module(
            "exploit/multi/handler",
            {
                "PAYLOAD": "generic/shell_reverse_tcp",
                "LHOST": "127.0.0.1",
                "LPORT": port,
                "AutoVerifySession": False,
                "ExitOnSession": False,
                "InitialAutoRunScript": "",
                "AutoRunScript": "",
            },
            owned=True,
        )
        for _ in range(30):
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                break
            except OSError:
                await asyncio.sleep(0.1)
        else:
            pytest.fail("Fixture handler unavailable")
        try:
            writer.write(b"fixture banner\n")
            await writer.drain()
            for _ in range(30):
                state = await activity.snapshot(scope)
                sessions = [row for row in state.items if row.kind == "session"]
                if sessions:
                    break
                await asyncio.sleep(0.1)
            session = sessions[0]
            claim = RemoteAction(
                workspace_id=scope,
                framework_id=identity,
                remote_id=session.remote_id,
                kind="session",
                confirmed=True,
            )
            await activity.claim(claim)
            second = await app.state.workspaces.create(WorkspaceCreate(name="Second"))
            await app.state.workspaces.activate(second.id)
            assert not any(
                row.kind == "session" for row in (await activity.snapshot(second.id)).items
            )
            command = TerminalCommand(
                workspace_id=scope,
                framework_id=identity,
                remote_id=session.remote_id,
                kind="shell",
                command=SecretStr("fixture-command"),
            )
            await activity.command(command)
            assert await asyncio.wait_for(reader.readline(), 3) == b"fixture-command\n"
            writer.write(b"fixture-response\n")
            await writer.drain()
            assert "fixture-response" in "\n".join((await activity.output(command)).lines)
            await activity.stop(claim)
            job_claim = RemoteAction(
                workspace_id=scope,
                framework_id=identity,
                remote_id=str(job["job_id"]),
                kind="job",
                confirmed=True,
            )
            await activity.claim(job_claim)
            await activity.stop(job_claim)
        finally:
            writer.close()
            await writer.wait_closed()
