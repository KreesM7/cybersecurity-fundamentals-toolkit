import asyncio
import base64
import sys
from uuid import uuid4

import pytest

from backend.main import create_app
from shared.modules import ModuleDetail, OptionSpec
from shared.payloads import PayloadRequest


@pytest.mark.asyncio
async def test_payload_job_streams_and_artifact_is_workspace_scoped(tmp_path, monkeypatch):
    from backend.services import payload_service

    fixture = tmp_path / "venom.py"
    fixture.write_text(
        "import json,sys\njson.loads(sys.stdin.readline())\n"
        "print(json.dumps({'type':'progress','message':'Generating fixture'}),flush=True)\n"
        "print(json.dumps({'type':'data','base64':'"
        + base64.b64encode(b"fixture-artifact").decode()
        + "'}),flush=True)\nprint(json.dumps({'type':'end','ok':True}),flush=True)\n"
    )
    monkeypatch.setattr(
        payload_service, "payload_host_argv", lambda: [sys.executable, str(fixture)]
    )
    app = create_app("f" * 64, "payload-test", tmp_path / "profile")
    async with app.router.lifespan_context(app):
        service = app.state.payloads
        identity = uuid4()
        monkeypatch.setattr(service.modules, "identity", lambda: str(identity))

        async def detail(path):
            return ModuleDetail(
                path=path,
                framework_id=identity,
                name="Fixture",
                description="",
                options=[
                    OptionSpec(name="LHOST", required=True),
                    OptionSpec(name="LPORT", kind="port", required=True),
                ],
            )

        async def call(method, args=None):
            return (
                {"formats": ["raw", "python"]}
                if "formats" in method
                else {"modules": ["generic/none"]}
            )

        monkeypatch.setattr(service.modules, "detail", detail)
        monkeypatch.setattr(service.modules.framework, "call", call)
        scope = app.state.workspaces.active_id
        data = PayloadRequest(
            workspace_id=scope,
            framework_id=identity,
            payload="generic/shell_reverse_tcp",
            format="raw",
            lhost="127.0.0.1",
            lport=4444,
            confirmed=True,
        )
        job = await service.generate(data, uuid4())
        for _ in range(100):
            snapshot = app.state.jobs.get(job.id, scope)
            if snapshot.status in {"succeeded", "failed"}:
                break
            await asyncio.sleep(0.01)
        assert snapshot.status == "succeeded", snapshot
        artifact = await app.state.artifacts.get(scope, snapshot.result["artifact_id"])
        assert artifact.read_bytes() == b"fixture-artifact"
        import ssl

        import httpx

        from frontend.api_client import ApiClient, ApiError

        async with ApiClient(
            "https://127.0.0.1:45678",
            ssl.create_default_context(),
            "f" * 64,
            transport=httpx.ASGITransport(app),
        ) as client:
            destination = tmp_path / "saved.bin"
            route = (
                f"/api/v1/artifacts/{snapshot.result['artifact_id']}/download?workspace_id={scope}"
            )
            await client.download(route, str(destination))
            assert destination.read_bytes() == b"fixture-artifact"
            with pytest.raises(ApiError):
                await client.download(route.replace(str(scope), str(uuid4())), str(destination))
            assert destination.read_bytes() == b"fixture-artifact"
        from shared.workspaces import WorkspaceCreate

        other = await app.state.workspaces.create(WorkspaceCreate(name="Other"))
        with pytest.raises(KeyError):
            await app.state.artifacts.get(other.id, snapshot.result["artifact_id"])
        assert any(
            event.data.get("progress") == "Generating fixture"
            for event in app.state.events.recent
            if isinstance(event.data, dict)
        )
        data = data.model_copy(update={"format": "raw --evil"})
        with pytest.raises(ValueError):
            await service.generate(data, uuid4())


@pytest.mark.asyncio
async def test_payload_cancel_waits_for_owned_process_and_keeps_no_artifact(tmp_path, monkeypatch):
    from threading import Event

    from backend.events import EventHub
    from backend.jobs import JobContext
    from backend.services import payload_service

    stopped = tmp_path / "stopped"
    fixture = tmp_path / "wait.py"
    fixture.write_text(
        "import sys,json,pathlib\njson.loads(sys.stdin.readline())\n"
        "print(json.dumps({'type':'progress','message':'Ready'}),flush=True)\n"
        "sys.stdin.read()\npathlib.Path(" + repr(str(stopped)) + ").write_text('reaped')\n"
    )
    monkeypatch.setattr(
        payload_service, "payload_host_argv", lambda: [sys.executable, str(fixture)]
    )
    hub = EventHub()
    context = JobContext(Event(), hub, uuid4(), uuid4())
    task = asyncio.create_task(payload_service.run_generator({}, context))
    for _ in range(100):
        if hub.recent:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert stopped.read_text() == "reaped"
