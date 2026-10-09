"""Foundation behavior: typed boundary, private storage, and responsive Qt clients."""

import asyncio
import os
import ssl
import sys
from ipaddress import IPv4Address
from pathlib import Path
from uuid import UUID, uuid4

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

TOKEN = "a" * 64
API_URL = "https://127.0.0.1:12345"


async def test_health_returns_instance_and_protects_docs(tmp_path: Path) -> None:
    import httpx

    from backend.main import create_app

    app = create_app(TOKEN, "test-instance", tmp_path)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://localhost"
    ) as client:
        response = await client.get("/api/v1/health", headers={"Authorization": f"Bearer {TOKEN}"})
        assert response.json() == {
            "schema_version": 1,
            "version": "2.0.0",
            "instance_id": "test-instance",
            "status": "ready",
        }
        assert (await client.get("/docs")).status_code == 401
        assert (await client.get("/openapi.json")).status_code == 401
    assert app.state.profile == tmp_path


def test_shared_target_validates_ipv4_and_excludes_secrets() -> None:
    from pydantic import ValidationError

    from shared.schemas import ConfigSettings, HealthResponse, TargetCreate, TargetView

    target = TargetCreate(address="192.0.2.8", name="test")
    assert target.address == IPv4Address("192.0.2.8")
    with pytest.raises(ValidationError):
        TargetCreate(address="::1", name="ipv6")
    with pytest.raises(ValidationError):
        TargetCreate(address="192.0.2.8", name="test", unexpected=True)
    with pytest.raises(ValidationError):
        HealthResponse(instance_id="a", schema_version=2)
    viewed = TargetView(id=uuid4(), workspace_id=uuid4(), **target.model_dump())
    assert isinstance(viewed.model_dump(mode="json")["id"], str)
    settings = ConfigSettings(rpc_password="hidden")
    assert "rpc_password" not in settings.model_dump()
    assert "hidden" not in settings.model_dump_json()


async def test_api_client_requires_tls_and_handles_typed_health(tmp_path: Path) -> None:
    import httpx

    from backend.main import create_app
    from frontend.api_client import ApiClient

    context = ssl.create_default_context()
    with pytest.raises(ValueError, match="HTTPS"):
        ApiClient("http://127.0.0.1:12345", context, TOKEN)
    insecure = ssl._create_unverified_context()
    with pytest.raises(ValueError, match="verif"):
        ApiClient(API_URL, insecure, TOKEN)
    transport = httpx.ASGITransport(app=create_app(TOKEN, "known", tmp_path))
    async with ApiClient(API_URL, context, TOKEN, transport=transport) as client:
        assert (await client.health()).instance_id == "known"


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com:12345",
        "https://127.0.0.2:12345",
        "https://localhost:12345",
        "https://127.0.0.1",
        "https://127.0.0.1:0",
        "https://127.0.0.1:65536",
        "https://127.0.0.1:12345/prefix",
        "https://127.0.0.1:12345?query=1",
    ],
)
def test_api_client_rejects_nonloopback_or_ambiguous_base_urls(url: str) -> None:
    from frontend.api_client import ApiClient

    with pytest.raises(ValueError):
        ApiClient(url, ssl.create_default_context(), TOKEN)


@pytest.mark.parametrize("token", ["token", "a" * 63, "A" * 64, "g" * 64])
def test_api_client_rejects_invalid_instance_tokens(token: str) -> None:
    from frontend.api_client import ApiClient

    with pytest.raises(ValueError):
        ApiClient(API_URL, ssl.create_default_context(), token)


async def test_api_mutations_are_sent_once_with_bearer_and_response_validation() -> None:
    import httpx
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from pydantic import ValidationError

    from frontend.api_client import ApiClient
    from shared.schemas import HealthResponse

    app = FastAPI()
    requests: list[tuple[str | None, str | None, str | None]] = []

    @app.post("/api/v1/failure")
    async def failure(request: Request) -> JSONResponse:
        requests.append(
            (
                request.headers.get("Authorization"),
                request.headers.get("X-Request-ID"),
                request.headers.get("X-Secret-Vault-Token"),
            )
        )
        return JSONResponse({"error": "failure"}, status_code=500)

    @app.get("/api/v1/health")
    async def invalid_health() -> dict[str, object]:
        return {"instance_id": "known", "schema_version": 2}

    async with ApiClient(
        API_URL,
        ssl.create_default_context(),
        TOKEN,
        transport=httpx.ASGITransport(app=app),
    ) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.request(
                "POST",
                "/api/v1/failure",
                HealthResponse,
                request_id=UUID("00000000-0000-4000-8000-000000000001"),
                headers={"X-Secret-Vault-Token": "vault"},
            )
        assert requests == [(f"Bearer {TOKEN}", "00000000-0000-4000-8000-000000000001", "vault")]
        with pytest.raises(ValueError, match="Authorization"):
            await client.request(
                "POST",
                "/api/v1/failure",
                HealthResponse,
                headers={"authorization": "Bearer replaced"},
            )
        assert len(requests) == 1
        with pytest.raises(ValidationError):
            await client.health()
        with pytest.raises(ValueError):
            await client.request("GET", "https://example.com/api/v1/health", HealthResponse)


async def test_wss_client_uses_trusted_context_bearer_and_ignores_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from PyQt6.QtWidgets import QApplication
    from websockets.asyncio.server import ServerConnection, serve

    from backend.tls import ensure_tls
    from frontend.viewmodels.base_vm import BaseViewModel
    from frontend.ws_client import WebSocketClient

    material = ensure_tls(tmp_path)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(material.server_cert, material.server_key)
    seen: list[str | None] = []

    async def handler(connection: ServerConnection) -> None:
        assert connection.request is not None
        seen.append(connection.request.headers.get("Authorization"))
        await connection.send("confirmed")

    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    async with serve(handler, "127.0.0.1", 0, ssl=server_context) as server:
        port = server.sockets[0].getsockname()[1]
        client = WebSocketClient(f"https://127.0.0.1:{port}", material.client_context(), TOKEN)
        received = [message async for message in client.messages("/api/v1/events")]
        assert received == ["confirmed"]
        assert seen == [f"Bearer {TOKEN}"]
        with pytest.raises(ValueError):
            async for _ in client.messages("wss://example.com/api/v1/events"):
                raise AssertionError("External stream must not connect")
        application = QApplication.instance() or QApplication([])
        vm = BaseViewModel(f"https://127.0.0.1:{port}", material.client_context(), TOKEN)
        delivered: list[object] = []
        try:
            vm.message_received.connect(delivered.append)
            vm.watch_events("/api/v1/events")
            for _ in range(200):
                application.processEvents()
                if delivered:
                    break
                await asyncio.sleep(0.01)
            assert delivered[0] == "confirmed"
            # A normally closed read-only stream requests resynchronization before retry.
            assert all(message in {"confirmed", '{"topic":"resync"}'} for message in delivered)
        finally:
            vm.close()


@pytest.mark.parametrize("status", [300, 301, 302, 303, 307, 308])
@pytest.mark.parametrize("location", ["wss://example.invalid/api/v1/events", "/api/v1/other"])
async def test_wss_redirects_fail_before_any_second_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int, location: str
) -> None:
    from http import HTTPStatus
    from typing import Any

    from websockets.asyncio.server import ServerConnection, serve
    from websockets.http11 import Request, Response

    from backend.tls import ensure_tls
    from frontend.ws_client import WebSocketClient, WebSocketRedirectError

    material = ensure_tls(tmp_path)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(material.server_cert, material.server_key)
    handshakes: list[str | None] = []

    def redirect(connection: ServerConnection, request: Request) -> Response:
        handshakes.append(request.headers.get("Authorization"))
        response = connection.respond(HTTPStatus(status), "Backend redirect")
        response.headers["Location"] = location
        return response

    async def handler(connection: ServerConnection) -> None:
        raise AssertionError("A redirect must never complete a websocket handshake")

    async with serve(
        handler, "127.0.0.1", 0, ssl=server_context, process_request=redirect
    ) as server:
        port = server.sockets[0].getsockname()[1]
        attempted: list[tuple[object, object]] = []
        loop = asyncio.get_running_loop()
        create_connection = loop.create_connection

        async def guarded_connection(*args: Any, **kwargs: Any) -> Any:
            # Preserve the real local TLS handshake, intercepting only further network attempts.
            host = kwargs.get("host", args[1] if len(args) > 1 else None)
            attempted.append((host, kwargs.get("port", args[2] if len(args) > 2 else None)))
            if len(attempted) > 1:
                raise RuntimeError("Unexpected second connection attempt")
            return await create_connection(*args, **kwargs)

        monkeypatch.setattr(loop, "create_connection", guarded_connection)
        client = WebSocketClient(f"https://127.0.0.1:{port}", material.client_context(), TOKEN)
        with pytest.raises(WebSocketRedirectError) as failure:
            async for _ in client.messages("/api/v1/events"):
                raise AssertionError("Redirect must not produce stream messages")
        assert attempted == [("127.0.0.1", port)]
        assert handshakes == [f"Bearer {TOKEN}"]
        assert "redirect" in str(failure.value).lower()
        assert "instance locator" in str(failure.value).lower()
        assert TOKEN not in str(failure.value) and "example.invalid" not in str(failure.value)


def test_theme_loads_outside_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from frontend.theme import load_theme

    monkeypatch.chdir(tmp_path)
    dark, dark_tokens = load_theme("dark")
    light, light_tokens = load_theme("light")
    assert "QWidget" in dark and "QWidget" in light
    assert dark_tokens.background != light_tokens.background


def test_profile_atomic_write_is_private(tmp_path: Path) -> None:
    from backend.platform_utils import (
        assert_private_path,
        atomic_private_write,
        protect_private_path,
    )

    protect_private_path(tmp_path, directory=True)
    path = tmp_path / "secret"
    atomic_private_write(path, b"first")
    assert_private_path(path)
    atomic_private_write(path, b"second")
    assert path.read_bytes() == b"second"
    assert list(tmp_path.iterdir()) == [path]


def test_profile_write_rejects_symlinks(tmp_path: Path) -> None:
    from backend.platform_utils import atomic_private_write

    path = tmp_path / "secret"
    atomic_private_write(path, b"second")
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(path)
    except OSError:
        pytest.skip("Creating symlinks needs Windows developer mode or privilege")
    with pytest.raises(ValueError, match="symlink"):
        atomic_private_write(linked, b"changed")
    assert path.read_bytes() == b"second"


def test_private_path_assertion_rejects_exposed_file_without_changing_it(tmp_path: Path) -> None:
    from backend.platform_utils import assert_private_path, is_windows

    path = tmp_path / "exposed"
    path.write_bytes(b"existing")
    if not is_windows():
        path.chmod(0o644)
    with pytest.raises(PermissionError):
        assert_private_path(path)
    assert path.read_bytes() == b"existing"


def test_profile_lease_excludes_second_owner_and_can_reacquire(tmp_path: Path) -> None:
    from backend.platform_utils import ProfileInUse, acquire_profile_lease

    first = acquire_profile_lease(tmp_path)
    try:
        with pytest.raises(ProfileInUse):
            acquire_profile_lease(tmp_path)
    finally:
        first.close()
    second = acquire_profile_lease(tmp_path)
    second.close()


def test_platform_fixed_wsl_arguments_and_profile_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from backend.platform_utils import get_config_dir, get_log_dir, wsl_argv

    monkeypatch.setenv("TOOLKIT_PROFILE", str(tmp_path))
    assert get_config_dir() == tmp_path
    assert get_log_dir() == tmp_path / "logs"
    assert wsl_argv(["msfconsole", "-q", "literal;argument"]) == [
        "wsl.exe",
        "--distribution",
        "Toolkit-MSF",
        "--exec",
        "msfconsole",
        "-q",
        "literal;argument",
    ]


async def test_process_output_limit_timeout_and_cancellation() -> None:
    from backend.platform_utils import OutputLimitExceeded, run_process

    result = await run_process([sys.executable, "-c", "print('ok')"])
    assert result.returncode == 0 and result.stdout.strip() == b"ok"
    with pytest.raises(OutputLimitExceeded):
        await run_process([sys.executable, "-c", "print('x'*10000)"], max_output_bytes=32)
    with pytest.raises(TimeoutError):
        await run_process([sys.executable, "-c", "import time;time.sleep(10)"], timeout=0.1)
    task = asyncio.create_task(run_process([sys.executable, "-c", "import time;time.sleep(10)"]))
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def test_qt_worker_keeps_ui_responsive_delivers_on_gui_and_shuts_down(tmp_path: Path) -> None:
    import httpx
    from fastapi import FastAPI
    from PyQt6.QtCore import QThread, QTimer
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QApplication

    from frontend.main_window import MainWindow
    from frontend.viewmodels.base_vm import BaseViewModel

    app = QApplication.instance() or QApplication([])
    assert isinstance(app, QApplication)
    service = FastAPI()

    @service.get("/api/v1/health")
    async def slow_health() -> dict[str, str | int]:
        await asyncio.sleep(0.2)
        return {"schema_version": 1, "version": "2.0.0", "instance_id": "live", "status": "ready"}

    vm = BaseViewModel(
        API_URL,
        ssl.create_default_context(),
        TOKEN,
        transport=httpx.ASGITransport(app=service),
    )
    window = MainWindow(vm)
    received: list[QThread | None] = []
    ticks: list[int] = []
    vm.health_changed.connect(lambda _: received.append(QThread.currentThread()))
    timer = QTimer()
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start(10)
    window.show()
    vm.refresh_health()
    for _ in range(300):
        if received:
            break
        QTest.qWait(10)
    assert received == [app.thread()]
    assert len(ticks) >= 3
    assert "live" in window.health_label.text()
    timer.stop()
    from PyQt6.QtWidgets import QLabel

    first = QLabel("First")
    second = QLabel("Second")
    window.register_view("First", first)
    window.register_view("Second", second)
    window.sidebar.setCurrentRow(window.sidebar.count() - 1)
    assert window.stack.currentWidget() is second
    vm.refresh_health()
    QTest.qWait(30)
    window.close()
    assert not vm.is_running


def test_qt_mutation_creates_one_id_and_delivers_result_on_gui_thread() -> None:
    import httpx
    from fastapi import FastAPI, Request
    from PyQt6.QtCore import QThread
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QApplication

    from frontend.viewmodels.base_vm import BaseViewModel
    from shared.schemas import HealthResponse

    application = QApplication.instance() or QApplication([])
    service = FastAPI()
    mutation_ids: list[str | None] = []

    @service.post("/api/v1/action")
    async def action(request: Request) -> dict[str, str | int]:
        mutation_ids.append(request.headers.get("X-Request-ID"))
        return {"schema_version": 1, "version": "2.0.0", "instance_id": "action", "status": "ready"}

    vm = BaseViewModel(
        API_URL,
        ssl.create_default_context(),
        TOKEN,
        transport=httpx.ASGITransport(app=service),
    )
    completed: list[tuple[object, object, QThread | None]] = []
    try:
        vm.mutation_completed.connect(
            lambda action_id, response: completed.append(
                (action_id, response, QThread.currentThread())
            )
        )
        action_id = vm.run_mutation("POST", "/api/v1/action", HealthResponse)
        for _ in range(300):
            if completed:
                break
            QTest.qWait(10)
        assert isinstance(action_id, UUID)
        assert mutation_ids == [str(action_id)]
        assert completed[0][0] == action_id and completed[0][2] == application.thread()
        assert isinstance(completed[0][1], HealthResponse)
        assert completed[0][1].instance_id == "action"
    finally:
        vm.close()
