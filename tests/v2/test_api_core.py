"""Application lifecycle, authenticated persistence and bounded event channels."""

from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from backend.main import create_app

TOKEN = "b" * 64
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def test_websocket_uses_bearer_rejects_query_auth_and_streams_redacted_events(
    tmp_path: Path,
) -> None:
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    app = create_app(TOKEN, "ws", tmp_path)
    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/ws/events?token={TOKEN}"):
                raise AssertionError("Query authentication was accepted")
        with client.websocket_connect("/ws/events", headers=AUTH) as socket:
            response = client.post(
                "/api/v1/workspaces/",
                json={"name": "WS Lab"},
                headers={**AUTH, "X-Request-ID": str(uuid4())},
            )
            assert response.status_code == 201
            event = socket.receive_json()
            assert event["topic"] == "workspace-created"
            assert event["data"]["name"] == "WS Lab"
            assert TOKEN not in str(event)


async def test_lifecycle_persistence_mutations_and_private_docs(tmp_path: Path) -> None:
    app = create_app(TOKEN, "core-test", tmp_path)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://127.0.0.1"
        ) as client:
            assert (await client.get("/api/v1/workspaces/")).status_code == 401
            assert (await client.get("/docs")).status_code == 401
            client.headers.update(AUTH)
            assert (await client.get("/docs")).status_code == 200
            spec = (await client.get("/openapi.json")).json()
            assert spec["components"]["securitySchemes"]["HTTPBearer"]["scheme"] == "bearer"
            initial = (await client.get("/api/v1/workspaces/")).json()
            assert len(initial) == 1 and initial[0]["active"]
            request_id = str(uuid4())
            response = await client.post(
                "/api/v1/workspaces/", json={"name": "Lab"}, headers={"X-Request-ID": request_id}
            )
            assert response.status_code == 201
            again = await client.post(
                "/api/v1/workspaces/", json={"name": "Lab"}, headers={"X-Request-ID": request_id}
            )
            assert again.json() == response.json()
            conflict = await client.post(
                "/api/v1/workspaces/", json={"name": "Other"}, headers={"X-Request-ID": request_id}
            )
            assert conflict.status_code == 409
            assert (await client.get("/api/v1/jobs")).json() == []
            events = (await client.get("/api/v1/events")).json()
            assert any(item["topic"] == "workspace-created" for item in events)
    restarted = create_app(TOKEN, "second", tmp_path)
    async with restarted.router.lifespan_context(restarted):
        assert len(await restarted.state.workspaces.list()) == 2


async def test_errors_never_echo_untrusted_input_and_body_is_bounded(tmp_path: Path) -> None:
    app = create_app(TOKEN, "errors", tmp_path)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://127.0.0.1", headers=AUTH
        ) as client:
            response = await client.post(
                "/api/v1/targets/",
                json={"address": "sensitive-invalid-input"},
                headers={"X-Request-ID": str(uuid4())},
            )
            assert response.status_code == 422
            assert "sensitive-invalid-input" not in response.text
            response = await client.put(
                f"/api/v1/workspaces/{uuid4()}/notes", content=b"x" * (1024 * 1024 + 1)
            )
            assert response.status_code == 413
            assert (await client.get("/api/v1/health")).status_code == 200


async def test_job_api_is_workspace_scoped_and_clear_cancels_input(tmp_path: Path) -> None:
    app = create_app(TOKEN, "jobs", tmp_path)
    async with app.router.lifespan_context(app):
        workspace = app.state.workspaces.active_id

        async def work(context: object) -> dict[str, str]:
            return {"result": "ready"}

        job = await app.state.jobs.submit("fixture", workspace, work)
        await app.state.jobs.wait_idle()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://127.0.0.1", headers=AUTH
        ) as client:
            response = await client.get(f"/api/v1/jobs/{job.id}")
            assert response.json()["result"] == {"result": "ready"}
            assert (
                await client.get(f"/api/v1/jobs/{job.id}?workspace_id={uuid4()}")
            ).status_code == 404
            assert (
                await client.delete(
                    f"/api/v1/jobs/{job.id}", headers={"X-Request-ID": str(uuid4())}
                )
            ).status_code == 204
            assert (await client.get(f"/api/v1/jobs/{job.id}")).status_code == 404
