"""Structured fallback framing and uncertain-outcome behavior."""

import asyncio
import sys
from uuid import uuid4

import pytest

from backend.services.pty_transport import PtyTransport
from backend.services.rpc_transport import RpcFailure


@pytest.mark.asyncio
async def test_pty_ready_interleaved_output_and_serialized_calls(tmp_path):
    identity = str(uuid4())
    fixture = tmp_path / "bridge.py"
    fixture.write_text(
        "import json,sys\n"
        f"print(json.dumps({{'v':1,'type':'ready','id':'{identity}','version':'6.5.3'}}),flush=True)\n"
        "for line in sys.stdin:\n"
        " r=json.loads(line)\n"
        " print(json.dumps({'v':1,'type':'output','text':'interleaved'}),flush=True)\n"
        " print(json.dumps({'v':1,'type':'result','id':r['id'],"
        "'data':{'method':r['method']}}),flush=True)\n"
    )
    output = []
    transport = PtyTransport([sys.executable, str(fixture)], output.append)
    await transport.start()
    assert transport.identity == identity
    replies = await asyncio.gather(transport.call("core.version"), transport.call("session.list"))
    assert replies == [{"method": "core.version"}, {"method": "session.list"}]
    assert output == ["interleaved", "interleaved"]
    await transport.close()
    assert transport.process.returncode is not None


@pytest.mark.asyncio
async def test_pty_unknown_reply_is_not_replayed(tmp_path):
    fixture = tmp_path / "bad.py"
    fixture.write_text(
        "import json,sys\n"
        + f"print(json.dumps({{'v':1,'type':'ready','id':'{uuid4()}',"
        + "'version':'6.5.3'}),flush=True)\n"
        + "sys.stdin.readline()\n"
        + 'print(\'{"v":1,"type":"result","id":"wrong","data":{}}\',flush=True)\n'
    )
    transport = PtyTransport([sys.executable, str(fixture)], lambda _: None)
    await transport.start()
    try:
        with pytest.raises(RpcFailure, match="uncertain"):
            await transport.call("module.execute", ["auxiliary", "test", {}])
        assert transport.failed
        with pytest.raises(RpcFailure):
            await transport.call("module.execute", ["auxiliary", "test", {}])
    finally:
        await transport.close()
