import asyncio
from uuid import uuid4

import pytest

from backend.events import EventHub
from backend.services.metasploit_service import MetasploitService
from backend.services.rpc_transport import RpcFailure
from shared.framework import RpcConnect


class FixtureTransport:
    def __init__(self, *args, **kwargs):
        self.identity = None
        self.closed = False
        self.calls = []

    async def login(self, user, password):
        assert user == "msf" and password == "secret"
        self.identity = str(uuid4())
        return self.identity

    async def call(self, method, args=None):
        self.calls.append((method, args))
        if method in ("session.list", "job.list"):
            return {}
        return {"modules": ["test/path"]}

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_service_missing_setup_stays_offline_and_connects_without_secret_events(
    tmp_path, monkeypatch
):
    from backend.services import metasploit_service as module
    from backend.tls import ensure_tls

    material = ensure_tls(tmp_path / "certificates")
    monkeypatch.setattr(module, "RpcTransport", FixtureTransport)
    hub = EventHub()
    service = MetasploitService(tmp_path, hub)
    assert service.status().state == "Offline"
    data = RpcConnect(password="secret", ca_pem=material.ca_cert.read_text())
    result = await service.connect(data)
    assert result.state == "RPCConnected"
    modules = await service.get_modules()
    assert "auxiliary/test/path" in modules
    assert "secret" not in repr(list(hub.recent))
    assert "secret" not in (tmp_path / "rpc.json").read_text()
    transport = service.transport
    await service.disconnect()
    assert transport.closed
    assert service.status().state == "Offline"
    await service.close()


@pytest.mark.asyncio
async def test_reconnect_refuses_a_different_framework_without_repeating_command(
    tmp_path, monkeypatch
):
    from backend.services import metasploit_service as module
    from backend.tls import ensure_tls

    material = ensure_tls(tmp_path / "certificates")
    monkeypatch.setattr(module, "RpcTransport", FixtureTransport)
    service = MetasploitService(tmp_path, EventHub())
    await service.connect(RpcConnect(password="secret", ca_pem=material.ca_cert.read_text()))
    original = service.status().instance_id
    transport = service.transport
    attempts = 0

    async def failed(method, args=None):
        nonlocal attempts
        attempts += 1
        raise RpcFailure("Fixture connection lost")

    monkeypatch.setattr(transport, "call", failed)
    with pytest.raises(RpcFailure):
        await service.run_module("auxiliary/test", {}, owned=True)
    await asyncio.wait_for(service._reconnect_task, 3)
    assert attempts == 1
    assert service.status().state == "Offline"
    assert service.status().instance_id == original
    assert "instance changed" in service.status().message
    await service.close()


@pytest.mark.asyncio
async def test_connection_api_authentication_and_invalid_certificate(tmp_path):
    import httpx

    from backend.main import create_app

    token = "f" * 64
    app = create_app(token, "connection-test", tmp_path)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://127.0.0.1"
        ) as client:
            assert (await client.get("/api/v1/connection")).status_code == 401
            client.headers["Authorization"] = "Bearer " + token
            assert (await client.get("/api/v1/connection")).json()["state"] == "Offline"
            reply = await client.post(
                "/api/v1/connection/connect",
                headers={"X-Request-ID": str(uuid4())},
                json={"password": "private-connection-input", "ca_pem": "not a certificate"},
            )
            assert reply.status_code == 422
            assert "private-connection-input" not in reply.text
            assert app.state.framework.status().state == "Offline"


@pytest.mark.asyncio
async def test_invalid_module_path_never_reaches_transport(tmp_path):
    service = MetasploitService(tmp_path, EventHub())
    for path in ("../auxiliary/test", "unknown/test", "auxiliary/a;quit", "auxiliary//test"):
        with pytest.raises(ValueError):
            await service.get_module_info(path)
    with pytest.raises(RpcFailure):
        await service.get_sessions()
    await service.close()
