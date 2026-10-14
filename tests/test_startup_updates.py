"""Startup waits for release results, remains responsive and never installs updates."""

import asyncio

import httpx
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QLabel

from backend.services.desktop_service import DesktopService
from shared.desktop import StartupUpdateResult, UpdateNotice


async def test_startup_wait_reuses_the_existing_check_and_reports_latest(tmp_path):
    entered, release = asyncio.Event(), asyncio.Event()
    requests = []

    async def response(request):
        requests.append(request)
        entered.set()
        await release.wait()
        return httpx.Response(200, json={"tag_name": "v2.3.0", "draft": False, "prerelease": False})

    service = DesktopService(tmp_path)
    service.settings.check_updates = True
    service._task = asyncio.create_task(service.check(httpx.MockTransport(response)))
    waiting = asyncio.create_task(service.startup_check())
    try:
        await entered.wait()
        await asyncio.sleep(0)
        assert not waiting.done()
        release.set()
        result = await waiting
        assert result.state == "checked"
        assert result.notice.version == "v2.3.0"
        assert len(requests) == 1
        assert service.updater.progress.phase == "idle"
    finally:
        release.set()
        await service.close()


async def test_startup_reports_disabled_and_offline_without_installing(tmp_path):
    service = DesktopService(tmp_path)
    try:
        assert (await service.startup_check()).state == "disabled"
        assert service._task is None
        service.settings.check_updates = True
        service._task = asyncio.create_task(
            service.check(httpx.MockTransport(lambda _: httpx.Response(503)))
        )
        assert (await service.startup_check()).state == "failed"
        assert service.updater.progress.phase == "idle"
    finally:
        await service.close()


def test_launcher_waits_until_check_completes_and_ignores_late_results():
    from frontend.startup import StartupUpdateGate
    from tests.v2.test_module_ui import ViewModelFixture

    app = QApplication.instance() or QApplication([])
    vm = ViewModelFixture()
    launcher = QLabel()
    gate = StartupUpdateGate(vm, launcher)
    results = []
    gate.finished.connect(results.append)
    gate.start()
    assert "Checking for updates" in launcher.text()
    assert not results
    assert vm.calls[-1][1][:2] == ("startup-updates", "/api/v1/updates/startup")
    value = StartupUpdateResult(state="checked", notice=UpdateNotice(version="v2.3.0"))
    vm.state_changed.emit("unrelated", value)
    assert not results
    vm.state_changed.emit("startup-updates", value)
    assert results == [value]
    vm.state_changed.emit("startup-updates", value)
    assert results == [value]
    launcher.deleteLater()
    app.processEvents()


def test_launcher_timeout_and_shutdown_never_reopen_a_closed_app():
    from frontend.startup import StartupUpdateGate
    from tests.v2.test_module_ui import ViewModelFixture

    app = QApplication.instance() or QApplication([])
    vm = ViewModelFixture()
    launcher = QLabel()
    results = []
    gate = StartupUpdateGate(vm, launcher, timeout_ms=20)
    gate.finished.connect(results.append)
    gate.start()
    QTest.qWait(60)
    assert len(results) == 1 and results[0].state == "failed"
    closed = StartupUpdateGate(vm, launcher)
    closed.finished.connect(results.append)
    closed.start()
    closed.cancel()
    vm.state_changed.emit("startup-updates", StartupUpdateResult(state="checked"))
    assert len(results) == 1
    launcher.deleteLater()
    app.processEvents()


async def test_startup_endpoint_is_authenticated_and_opt_out_makes_no_request(tmp_path):
    from backend.main import create_app

    app = create_app("a" * 64, "startup", tmp_path)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://localhost"
        ) as client:
            assert (await client.get("/api/v1/updates/startup")).status_code == 401
            reply = await client.get(
                "/api/v1/updates/startup", headers={"Authorization": "Bearer " + "a" * 64}
            )
            assert reply.status_code == 200
            assert reply.json()["state"] == "disabled"
            assert app.state.desktop._task is None
