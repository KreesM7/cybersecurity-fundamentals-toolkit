"""Controlled localhost tool API fixtures, readiness and input guards."""

import asyncio
import json
import ssl
from pathlib import Path
from threading import Event
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import Response

from backend.events import EventHub
from backend.jobs import JobContext
from backend.main import create_app
from backend.services.async_sql import SQLClient
from backend.services.request_gate import RequestGate
from frontend.api_client import MAX_RESPONSE_BYTES, ApiClient, ApiError
from shared.tools import (
    AnomalyOptions,
    DoSOptions,
    EmptyResponse,
    PasswordOptions,
    ToolJob,
    ToolsList,
)

TOKEN = "c" * 64
AUTH = {"Authorization": f"Bearer {TOKEN}"}


async def completed(app, snapshot):
    await app.state.jobs.wait_idle()
    return app.state.jobs.get(
        (
            snapshot["id"]
            if isinstance(snapshot["id"], type(uuid4()))
            else __import__("uuid").UUID(snapshot["id"])
        ),
        app.state.workspaces.active_id,
    )


async def test_real_api_secret_transport_replay_memory_and_clear(tmp_path: Path):
    app = create_app(TOKEN, "tools", tmp_path)
    async with app.router.lifespan_context(app):
        async with ApiClient(
            "https://127.0.0.1:12345",
            ssl.create_default_context(),
            TOKEN,
            transport=httpx.ASGITransport(app=app),
        ) as client:
            rows = await client.request("GET", "/api/v1/tools", ToolsList)
            assert len(rows.root) == 7
            identifier = uuid4()
            options = PasswordOptions(password="qwerty")
            job = await client.request(
                "POST",
                "/api/v1/tools/password-strength/run",
                ToolJob,
                options,
                request_id=identifier,
            )
            await app.state.jobs.wait_idle()
            actual = app.state.jobs.get(job.id, job.workspace_id)
            assert actual.result["common"] and actual.result["score"] <= 1
            assert "qwerty" not in json.dumps(actual.result)
            replay = await client.request(
                "POST",
                "/api/v1/tools/password-strength/run",
                ToolJob,
                options,
                request_id=identifier,
            )
            assert replay.id == job.id
            assert not await app.state.mutations.store.get(job.workspace_id, identifier)
            assert "qwerty" not in repr(app.state.mutations._secrets.records)
            await client.request("DELETE", f"/api/v1/jobs/{job.id}", EmptyResponse)
            assert not app.state.jobs.records
            assert app.state.workspaces._engines[job.workspace_id].references == 0


@pytest.mark.parametrize("target", ["127.0.0.0/16", "::1", "0.0.0.0", "224.0.0.1", "127.0.0.5/24"])
async def test_scanner_invalid_input_rejected_before_job(tmp_path: Path, target: str):
    app = create_app(TOKEN, "guards", tmp_path)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://127.0.0.1", headers=AUTH
        ) as client:
            reply = await client.post(
                "/api/v1/tools/network-scanner/run",
                headers={"X-Request-ID": str(uuid4())},
                json={"kind": "network-scanner", "target": target, "authorized": True},
            )
            assert reply.status_code == 422
            assert not app.state.jobs.records


async def test_upload_detector_parameters_finite_infinity_and_insufficient(tmp_path: Path):
    app = create_app(TOKEN, "uploads", tmp_path)
    csv = (
        b"timestamp,source_ip,bytes,protocol\n0,127.0.0.1,1,TCP\n"
        b"2,127.0.0.1,1,TCP\n4,127.0.0.1,100,UDP\n"
    )
    async with app.router.lifespan_context(app):
        async with ApiClient(
            "https://127.0.0.1:12345",
            ssl.create_default_context(),
            TOKEN,
            transport=httpx.ASGITransport(app=app),
        ) as client:
            job = await client.upload(
                "/api/v1/tools/anomaly-detector/upload",
                ToolJob,
                AnomalyOptions(bin_seconds=2, baseline_bins=2, threshold=0.5),
                csv,
                "../events.csv",
                request_id=uuid4(),
            )
            await app.state.jobs.wait_idle()
            result = (await client.request("GET", f"/api/v1/jobs/{job.id}", ToolJob)).result
            assert result["sufficient"] and result["examined"] == 1
            assert any(
                row["zscore"] is None and row["score_kind"] == "positive_infinity"
                for row in result["anomalies"]
            )
            assert "Infinity" not in json.dumps(result, allow_nan=False)
            job = await client.upload(
                "/api/v1/tools/anomaly-detector/upload",
                ToolJob,
                AnomalyOptions(),
                csv,
                "events.csv",
                request_id=uuid4(),
            )
            await app.state.jobs.wait_idle()
            result = app.state.jobs.get(job.id, job.workspace_id).result
            assert result["status"] == "insufficient_baseline"
            repeated = (
                b"timestamp,source_ip\n" + b"1.1,127.0.0.1\n" * 101 + b"2.1,127.0.0.1\n" * 100
            )
            job = await client.upload(
                "/api/v1/tools/dos-detector/upload",
                ToolJob,
                DoSOptions(),
                repeated,
                "traffic.csv",
                request_id=uuid4(),
            )
            await app.state.jobs.wait_idle()
            result = app.state.jobs.get(job.id, job.workspace_id).result
            assert result["spikes"] == [{"source_ip": "127.0.0.1", "bin_start": 1, "count": 101}]


async def test_api_response_bound_and_actionable_error_without_input_retention():
    app = FastAPI()

    @app.get("/api/v1/large")
    async def large():
        return Response(b"x" * (MAX_RESPONSE_BYTES + 1))

    @app.post("/api/v1/failure")
    async def failure():
        return Response(
            '{"detail":"Confirm permission before scanning."}',
            status_code=422,
            media_type="application/json",
        )

    async with ApiClient(
        "https://127.0.0.1:12345",
        ssl.create_default_context(),
        TOKEN,
        transport=httpx.ASGITransport(app=app),
    ) as client:
        with pytest.raises(ApiError, match="16 MiB"):
            await client.request("GET", "/api/v1/large", ToolsList)
        with pytest.raises(ApiError, match="permission") as error:
            await client.request(
                "POST", "/api/v1/failure", ToolJob, PasswordOptions(password="sensitive-sentinel")
            )
        assert "sensitive-sentinel" not in str(error.value.request.content)


async def test_dns_wait_cancel_does_not_block_executor_shutdown(monkeypatch):
    import socket

    release, entered = Event(), Event()

    def blocked_lookup(*args, **kwargs):
        entered.set()
        release.wait(10)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]

    monkeypatch.setattr(socket, "getaddrinfo", blocked_lookup)
    context = JobContext(Event(), EventHub(), uuid4(), uuid4())
    client = SQLClient(RequestGate(), context, "http://fixture.invalid/")
    task = asyncio.create_task(client.resolve(client.source))
    try:
        while not entered.is_set():
            await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 1)
        # The owned executor worker has returned; only bounded daemon DNS slots remain.
        await asyncio.wait_for(asyncio.get_running_loop().shutdown_default_executor(), 1)
    finally:
        release.set()


async def test_loader_failure_is_isolated(tmp_path: Path, monkeypatch):
    import backend.tools as loader

    original = loader.import_module

    def unavailable(name):
        if name == "backend.tools.password_strength":
            raise ImportError("controlled optional analyzer import failure")
        return original(name)

    monkeypatch.setattr(loader, "import_module", unavailable)
    app = create_app(TOKEN, "isolated", tmp_path)
    async with app.router.lifespan_context(app):
        rows = await app.state.tools.list()
        assert len(rows) == 7
        assert any(row.id == "password-strength" and not row.available for row in rows)
        assert "caesar" in app.state.tools.specs


async def test_router_captures_workspace_before_mutation_reservation(tmp_path: Path, monkeypatch):
    from shared.workspaces import WorkspaceCreate

    app = create_app(TOKEN, "captured-scope", tmp_path)
    async with app.router.lifespan_context(app):
        original_id = app.state.workspaces.active_id
        other = await app.state.workspaces.create(WorkspaceCreate(name="Other"))
        execute = app.state.mutations.execute

        async def switching_reservation(*args, **kwargs):
            await app.state.workspaces.activate(other.id)
            return await execute(*args, **kwargs)

        monkeypatch.setattr(app.state.mutations, "execute", switching_reservation)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://127.0.0.1", headers=AUTH
        ) as client:
            reply = await client.post(
                "/api/v1/tools/caesar/run",
                headers={"X-Request-ID": str(uuid4())},
                json={"kind": "caesar", "text": "scope"},
            )
            assert reply.status_code == 202
            assert reply.json()["workspace_id"] == str(original_id)
            assert app.state.workspaces.active_id == other.id
            await app.state.jobs.wait_idle()


async def test_multipart_larger_than_spool_threshold_never_rolls_to_disk(
    tmp_path: Path, monkeypatch
):
    from backend.routers.tools import RAMMultipart

    parsed = []
    original = RAMMultipart.parse

    async def observe(self):
        form = await original(self)
        parsed.append(form["file"].file._rolled)
        return form

    monkeypatch.setattr(RAMMultipart, "parse", observe)
    app = create_app(TOKEN, "ram-upload", tmp_path)
    content = b"timestamp,source_ip\n1,127.0.0.1\n" + b"\n" * (2 * 1024 * 1024)
    async with app.router.lifespan_context(app):
        async with ApiClient(
            "https://127.0.0.1:12345",
            ssl.create_default_context(),
            TOKEN,
            transport=httpx.ASGITransport(app=app),
        ) as client:
            await client.upload(
                "/api/v1/tools/dos-detector/upload",
                ToolJob,
                DoSOptions(),
                content,
                "traffic.csv",
                request_id=uuid4(),
            )
            await app.state.jobs.wait_idle()
    assert parsed == [False]


async def test_analyzer_import_failure_does_not_prevent_other_tools_starting(
    tmp_path: Path, monkeypatch
):
    import builtins
    import sys

    original = builtins.__import__

    def missing_analysis(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "toolkit.modules" and "caesar" in fromlist:
            raise ImportError("Controlled unavailable Caesar analysis")
        return original(name, globals, locals, fromlist, level)

    monkeypatch.delitem(sys.modules, "backend.tools.caesar", raising=False)
    monkeypatch.setattr(builtins, "__import__", missing_analysis)
    app = create_app(TOKEN, "missing-analysis", tmp_path)
    async with app.router.lifespan_context(app):
        rows = await app.state.tools.list()
        assert len(rows) == 7
        assert any(row.id == "caesar" and not row.available for row in rows)
        assert "dos-detector" in app.state.tools.specs
        assert "password-strength" in app.state.tools.specs
