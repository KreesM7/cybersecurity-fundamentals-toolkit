"""Real private PTY operations against the dedicated Metasploit installation."""

import asyncio
import os
import socket
from pathlib import Path
from uuid import uuid4

import pytest

from backend.platform_utils import framework_host_argv
from backend.services.pty_transport import PtyTransport


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(
    not Path("/opt/toolkit-msf/pty-host.py").exists()
    and os.environ.get("TOOLKIT_MSF_INTEGRATION") != "1",
    reason="Dedicated installed PTY host required",
)
async def test_native_pty_metadata_console_jobs_and_owned_shutdown():
    token = uuid4().hex
    lines = []
    transport = PtyTransport(
        framework_host_argv(token),
        lines.append,
        cancel_argv=framework_host_argv(token, cancel=True),
    )
    try:
        await transport.start()
        assert transport.identity
        assert (await transport.call("core.version"))["version"]
        assert (await transport.call("module.auxiliary"))["modules"]
        options = await transport.call("module.options", ["auxiliary", "scanner/http/title"])
        assert "RHOSTS" in options
        assert await transport.call("session.list") == {}
        assert await transport.call("job.list") == {}
        console = (await transport.call("console.create"))["id"]
        await transport.call("console.write", [console, "version\n"])
        chunks = []
        for _ in range(20):
            data = await transport.call("console.read", [console])
            chunks.append(data.get("data", ""))
            if "Framework" in "".join(chunks):
                break
            await asyncio.sleep(0.1)
        assert "Framework" in "".join(chunks)
        await transport.call("console.destroy", [console])
        # A Python TCP fixture represents the remote shell. No OS command is executed.
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        job = await transport.call(
            "module.execute",
            [
                "exploit",
                "multi/handler",
                {
                    "PAYLOAD": "generic/shell_reverse_tcp",
                    "LHOST": "127.0.0.1",
                    "LPORT": port,
                    "AutoVerifySession": False,
                    "ExitOnSession": False,
                    "InitialAutoRunScript": "",
                    "AutoRunScript": "",
                },
            ],
        )
        assert job["job_id"] is not None
        for _ in range(30):
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                break
            except OSError:
                await asyncio.sleep(0.1)
        else:
            pytest.fail("Owned loopback handler did not start")
        try:
            writer.write(b"fixture banner\n")
            await writer.drain()
            for _ in range(30):
                sessions = await transport.call("session.list")
                if sessions:
                    break
                await asyncio.sleep(0.1)
            assert sessions
            identifier = next(iter(sessions))
            await transport.call("session.shell_write", [identifier, "fixture-command\n"])
            received = await asyncio.wait_for(reader.readline(), 3)
            assert received == b"fixture-command\n"
            writer.write(b"fixture-response\n")
            await writer.drain()
            result = await transport.call("session.shell_read", [identifier])
            assert "fixture-response" in result["data"]
            await transport.call("session.stop", [identifier])
            await transport.call("job.stop", [str(job["job_id"])])
            assert await transport.call("session.list") == {}
        finally:
            writer.close()
            await writer.wait_closed()
    finally:
        await transport.close()
    assert transport.process.returncode is not None
