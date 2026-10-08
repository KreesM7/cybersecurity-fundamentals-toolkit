"""Owned, loopback-only Metasploit RPC smoke test; never executes a module."""

import asyncio
import json
import secrets
import socket
import ssl
import sys
from pathlib import Path

import pytest

from backend.events import EventHub
from backend.services.metasploit_service import MetasploitService
from backend.services.rpc_transport import RpcFailure, RpcTransport
from shared.framework import RpcConnect


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(
    sys.platform == "win32" or not Path("/opt/metasploit-framework").exists(),
    reason="Dedicated native Metasploit lab is required",
)
async def test_actual_verified_rpc_identity_metadata_and_shutdown(tmp_path):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    launcher = Path(__file__).resolve().parents[2] / "scripts/start-msfrpc.py"
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        str(launcher),
        "--profile",
        str(tmp_path / "rpc"),
        "--port",
        str(port),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    password = secrets.token_urlsafe(32)
    assert process.stdin and process.stdout and process.stderr
    errors = asyncio.create_task(process.stderr.read(65537))
    client = None
    try:
        process.stdin.write((password + "\n").encode())
        await process.stdin.drain()
        async with asyncio.timeout(60):
            for _ in range(100):
                line = await process.stdout.readline()
                if not line:
                    diagnostic = await errors
                    pytest.fail(
                        "RPC fixture failed before ready: "
                        + diagnostic.decode(errors="replace")[-2000:]
                    )
                if line.startswith(b'{"ready":'):
                    identity = json.loads(line)["instance_id"]
                    break
            else:
                pytest.fail("RPC ready record missing")
        endpoint = f"https://127.0.0.1:{port}/api/"
        untrusted = RpcTransport(endpoint, ssl.create_default_context())
        with pytest.raises(RpcFailure):
            await untrusted.login("msf", password)
        await untrusted.close()
        context = ssl.create_default_context(cafile=str(tmp_path / "rpc/rpc-cert.pem"))
        client = RpcTransport(endpoint, context)
        assert await client.login("msf", password) == identity
        service = MetasploitService(tmp_path / "desktop", EventHub())
        try:
            await service.connect(
                RpcConnect(
                    port=port, password=password, ca_pem=(tmp_path / "rpc/rpc-cert.pem").read_text()
                )
            )
            assert "auxiliary/scanner/http/title" in await service.get_modules()
            info = await service.get_module_info("auxiliary/scanner/http/title")
            assert "RHOSTS" in info["options"]
        finally:
            await service.close()
        assert (await client.call("core.version"))["version"]
        assert (await client.call("module.auxiliary"))["modules"]
        assert await client.call("session.list") == {}
        assert await client.call("job.list") == {}
        await client.close()
        client = RpcTransport(endpoint, context)
        assert await client.login("msf", password) == identity
    finally:
        if client:
            await client.close()
        if process.returncode is None:
            process.terminate()
        await asyncio.wait_for(process.wait(), 15)
        await asyncio.wait_for(errors, 5)
    with socket.socket() as probe:
        probe.settimeout(1)
        assert probe.connect_ex(("127.0.0.1", port)) != 0
