"""Protocol fixtures exercise secure RPC boundaries without executing modules."""

import asyncio
import ssl
from uuid import uuid4

import httpx
import msgpack
import pytest

from backend.services.rpc_transport import RpcFailure, RpcTransport


@pytest.mark.asyncio
async def test_temporary_login_serialization_and_logout():
    calls = []
    active = 0
    peak = 0
    identity = str(uuid4())

    async def server(request):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        call = msgpack.unpackb(request.content)
        calls.append(call)
        await asyncio.sleep(0.01)
        active -= 1
        replies = {
            "auth.login": {"result": "success", "token": "TEMPfixture"},
            "toolkit.identity": {"id": identity, "version": "6.5.3"},
            "core.version": {"version": "6.5.3"},
            "auth.logout": {"result": "success"},
        }
        return httpx.Response(200, content=msgpack.packb(replies[call[0]]))

    rpc = RpcTransport(
        "https://127.0.0.1:55553/api/",
        ssl.create_default_context(),
        transport=httpx.MockTransport(server),
    )
    assert await rpc.login("msf", "private") == identity
    await asyncio.gather(*(rpc.call("core.version") for _ in range(4)))
    await rpc.close()
    assert peak == 1
    assert [c[0] for c in calls].count("auth.login") == 1
    assert calls[-1] == ["auth.logout", "TEMPfixture", "TEMPfixture"]
    assert "auth.token_generate" not in [c[0] for c in calls]
    assert rpc.token is None


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["redirect", "oversize", "malformed", "timeout"])
async def test_failed_calls_are_bounded_sanitized_and_never_retried(mode):
    calls = 0

    async def server(request):
        nonlocal calls
        calls += 1
        if mode == "redirect":
            return httpx.Response(302, headers={"Location": "https://127.0.0.1/other"})
        if mode == "oversize":
            return httpx.Response(200, content=b"x" * (4 * 1024 * 1024 + 1))
        if mode == "malformed":
            return httpx.Response(200, content=b"secret raw error")
        raise httpx.ReadTimeout("secret raw error")

    rpc = RpcTransport(
        "https://127.0.0.1:55553/api/",
        ssl.create_default_context(),
        transport=httpx.MockTransport(server),
    )
    rpc.token = "TEMPfixture"
    try:
        with pytest.raises(RpcFailure) as failure:
            await rpc.call("module.execute", ["auxiliary", "test", {}])
        assert "secret" not in str(failure.value)
        assert calls == 1
    finally:
        rpc.token = None
        await rpc.close()


def test_rpc_requires_tls_and_literal_endpoint():
    for url in (
        "http://127.0.0.1:55553/api/",
        "https://user:pass@127.0.0.1/api/",
        "https://example.com/api/",
        "https://127.0.0.1/api/?token=x",
    ):
        with pytest.raises(ValueError):
            RpcTransport(url, ssl.create_default_context())
