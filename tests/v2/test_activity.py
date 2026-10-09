import asyncio
from uuid import uuid4

import httpx
import pytest

from backend.main import create_app
from shared.framework import ConnectionStatus
from shared.workspaces import WorkspaceCreate


class RemoteFixture:
    def __init__(self):
        self.identity = str(uuid4())
        self.calls = []
        self._connection_lock = asyncio.Lock()

    def status(self):
        return ConnectionStatus(state="RPCConnected", instance_id=self.identity)

    async def get_sessions(self):
        return {"1": {"type": "shell", "tunnel_peer": "127.0.0.1:4444"}}

    async def get_jobs(self):
        return {"2": "Fixture"}

    async def call(self, method, args=None):
        self.calls.append((method, args))
        return (
            {"id": "0"}
            if method == "console.create"
            else {"data": "password=fixture-secret\nhello\n"}
        )

    async def kill_session(self, identifier):
        return await self.call("session.stop", [identifier])

    async def kill_job(self, identifier):
        return await self.call("job.stop", [identifier])

    async def interact_session(self, identifier, kind, command=None):
        return await self.call("session." + kind, [identifier, command])


@pytest.mark.asyncio
async def test_workspace_claim_stop_and_command_replay_redaction(tmp_path):
    app = create_app("f" * 64, "activity-test", tmp_path)
    async with app.router.lifespan_context(app):
        framework = RemoteFixture()
        app.state.modules.framework = framework
        first = app.state.workspaces.active_id
        second = (await app.state.workspaces.create(WorkspaceCreate(name="Second"))).id
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app),
            base_url="https://127.0.0.1",
            headers={"Authorization": "Bearer " + "f" * 64},
        ) as client:

            async def post(route, body, identifier=None):
                return await client.post(
                    "/api/v1/activity/" + route,
                    json=body,
                    headers={"X-Request-ID": str(identifier or uuid4())},
                )

            data = {
                "workspace_id": str(first),
                "framework_id": framework.identity,
                "remote_id": "1",
                "kind": "session",
                "confirmed": True,
            }
            assert (await post("stop", data)).status_code == 409
            assert (await post("claim", data)).status_code == 200
            other = data | {"workspace_id": str(second)}
            assert (await post("claim", other)).status_code == 409
            assert (await post("stop", other)).status_code == 409
            assert (await post("stop", data | {"confirmed": False})).status_code == 422
            snapshot = await client.get("/api/v1/activity", params={"workspace_id": str(second)})
            assert all(item["remote_id"] != "1" for item in snapshot.json()["items"])
            console = await post(
                "console", {"workspace_id": str(first), "framework_id": framework.identity}
            )
            assert console.status_code == 200, console.text
            command = {
                "workspace_id": str(first),
                "framework_id": framework.identity,
                "remote_id": "0",
                "kind": "console",
                "command": "set PASSWORD fixture-secret",
            }
            request_id = uuid4()
            assert (await post("command", command, request_id)).status_code == 200
            assert (await post("command", command, request_id)).status_code == 200
            assert len([call for call in framework.calls if call[0] == "console.write"]) == 1
            assert (
                await post("command", command | {"command": "version"}, request_id)
            ).status_code == 409
            response = await client.get(
                "/api/v1/activity/output",
                params={key: value for key, value in command.items() if key != "command"},
            )
            assert response.status_code == 200, response.text
            assert "fixture-secret" not in response.text and "hello" in response.text
            assert (
                await post("command", command | {"workspace_id": str(second)})
            ).status_code == 409
            assert (await post("stop", data)).status_code == 200
            history = (
                await client.get("/api/v1/activity/history", params={"workspace_id": str(first)})
            ).json()
            assert history == ["set [arguments redacted]"]
            framework.identity = str(uuid4())
            assert (await post("command", command)).status_code == 409
    assert not any(b"fixture-secret" in path.read_bytes() for path in tmp_path.rglob("*.db"))


@pytest.mark.asyncio
async def test_event_reconnect_requests_rest_resync_without_mutations():
    from types import SimpleNamespace
    from frontend.viewmodels.base_vm import ClientWorker

    received = []

    class Stream:
        attempts = 0

        async def messages(self, path):
            self.attempts += 1
            if self.attempts == 1:
                raise RuntimeError("Fixture queue overflow")
            yield '{"topic":"activity"}'
            await asyncio.Event().wait()

    stream = Stream()
    worker = SimpleNamespace(
        _closed=False,
        _websocket=stream,
        failed=SimpleNamespace(emit=lambda _: None),
        message_received=SimpleNamespace(emit=received.append),
    )
    task = asyncio.create_task(ClientWorker._watch(worker, "/ws/events"))
    try:
        for _ in range(150):
            if len(received) == 2:
                break
            await asyncio.sleep(0.01)
        assert received == ['{"topic":"resync"}', '{"topic":"activity"}']
        assert stream.attempts == 2
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
