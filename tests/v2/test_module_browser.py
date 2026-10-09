import asyncio
from uuid import uuid4

import httpx
import pytest

from backend.main import create_app
from shared.framework import ConnectionStatus


class FrameworkFixture:
    def __init__(self):
        self.identity = str(uuid4())
        self.calls = []
        self._connection_lock = asyncio.Lock()

    def status(self):
        return ConnectionStatus(state="RPCConnected", instance_id=self.identity)

    async def call(self, method, args=None):
        self.calls.append((method, args))
        return {
            "modules": [
                {
                    "fullname": "auxiliary/scanner/test",
                    "name": "Fixture",
                    "rank": "normal",
                    "type": "auxiliary",
                }
            ]
        }

    async def get_module_info(self, path):
        return {
            "path": path,
            "info": {"name": "Fixture", "description": "Owned fixture"},
            "options": {
                "RHOSTS": {"type": "addressrange", "required": True, "desc": "Targets"},
                "RPORT": {"type": "port", "required": True, "default": 80},
                "SSL": {"type": "bool", "default": False},
                "MODE": {"type": "enum", "enums": ["one", "two"], "default": "one"},
                "PASSWORD": {"type": "string"},
            },
        }

    async def run_module(self, path, options, *, owned):
        assert owned
        self.calls.append(("execute", options))
        await asyncio.sleep(0)
        return {"job_id": 7, "uuid": str(uuid4())}


@pytest.mark.asyncio
async def test_search_favorites_transfer_launch_and_idempotency(tmp_path):
    app = create_app("f" * 64, "module-test", tmp_path)
    async with app.router.lifespan_context(app):
        fixture = FrameworkFixture()
        app.state.modules.framework = fixture
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app),
            base_url="https://127.0.0.1",
            headers={"Authorization": "Bearer " + "f" * 64},
        ) as client:
            query = "/api/v1/modules/search?query=test&kind=auxiliary&rank=normal&platform=linux"
            first = await client.get(query)
            assert first.status_code == 200, first.text
            assert first.json()["modules"][0]["path"] == "auxiliary/scanner/test"
            await client.get(query)
            assert len(fixture.calls) == 1
            assert "platform:linux" in fixture.calls[0][1][0]
            path = "auxiliary/scanner/test"
            headers = {"X-Request-ID": str(uuid4())}
            assert (
                await client.post(
                    "/api/v1/modules/favorites",
                    json={"path": path, "enabled": True},
                    headers=headers,
                )
            ).status_code == 200
            assert (await client.get("/api/v1/modules/library")).json()["favorites"] == [path]
            detail = await client.get("/api/v1/modules/info", params={"path": path})
            assert detail.status_code == 200, detail.text
            target = await client.post(
                "/api/v1/targets/",
                json={"address": "127.0.0.1"},
                headers={"X-Request-ID": str(uuid4())},
            )
            assert target.status_code == 201, target.text
            transfer = await client.post(
                f"/api/v1/targets/{target.json()['id']}/use-as-rhosts",
                headers={"X-Request-ID": str(uuid4())},
            )
            assert transfer.json()["rhosts"] == "127.0.0.1"
            data = {
                "path": path,
                "framework_id": fixture.identity,
                "workspace_id": target.json()["workspace_id"],
                "confirmed": True,
                "target_id": target.json()["id"],
                "options": {"RHOSTS": "127.0.0.1", "PASSWORD": "private-fixture-value"},
            }
            headers = {"X-Request-ID": str(uuid4())}
            launched = await client.post("/api/v1/modules/run", json=data, headers=headers)
            assert launched.status_code == 200, launched.text
            assert launched.json()["remote_job_id"] == "7"
            assert (
                await client.post("/api/v1/modules/run", json=data, headers=headers)
            ).json() == launched.json()
            assert len([x for x in fixture.calls if x[0] == "execute"]) == 1
            data["options"]["RPORT"] = 81
            assert (
                await client.post("/api/v1/modules/run", json=data, headers=headers)
            ).status_code == 409
            assert (await client.get("/api/v1/modules/library")).json()["recent"] == [path]
            assert "private-fixture-value" not in repr(list(app.state.events.recent))
    assert not any(
        b"private-fixture-value" in file.read_bytes() for file in tmp_path.rglob("*.sqlite*")
    )


@pytest.mark.asyncio
async def test_invalid_options_and_stale_framework_never_execute(tmp_path):
    app = create_app("f" * 64, "module-test", tmp_path)
    async with app.router.lifespan_context(app):
        fixture = FrameworkFixture()
        app.state.modules.framework = fixture
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app),
            base_url="https://127.0.0.1",
            headers={"Authorization": "Bearer " + "f" * 64},
        ) as client:
            data = {
                "path": "auxiliary/scanner/test",
                "framework_id": fixture.identity,
                "workspace_id": str(app.state.workspaces.active_id),
                "confirmed": True,
                "options": {"RHOSTS": "127.0.0.1"},
            }
            for options in (
                {},
                {"RHOSTS": "file:/etc/passwd"},
                {"RHOSTS": "10.0.0.0/8"},
                {"RHOSTS": "127.0.0.1", "RPORT": 65536},
                {"RHOSTS": "127.0.0.1", "UNKNOWN": "x"},
                {"RHOSTS": "127.0.0.1", "MODE": "invalid"},
            ):
                data["options"] = options
                reply = await client.post(
                    "/api/v1/modules/run", json=data, headers={"X-Request-ID": str(uuid4())}
                )
                assert reply.status_code == 422, reply.text
            data["options"] = {"RHOSTS": "127.0.0.1"}
            data["framework_id"] = str(uuid4())
            assert (
                await client.post(
                    "/api/v1/modules/run", json=data, headers={"X-Request-ID": str(uuid4())}
                )
            ).status_code == 409
            assert not fixture.calls
