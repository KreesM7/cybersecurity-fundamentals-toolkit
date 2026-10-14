"""Manual release checks are explicit and distinguish failures from current versions."""

import httpx
import pytest
from PyQt6.QtWidgets import QApplication

from backend.services.desktop_service import DesktopService
from shared.desktop import DesktopSettings, UpdateNotice, UpdateProgress


@pytest.mark.parametrize("version,expected", [("v2.3.0", "v2.3.0"), ("v1.0.0", "")])
async def test_manual_check_without_startup_opt_in(tmp_path, version, expected):
    service = DesktopService(tmp_path)
    transport = httpx.MockTransport(
        lambda _: httpx.Response(
            200, json={"tag_name": version, "draft": False, "prerelease": False}
        )
    )
    service.settings.dismissed_version = version
    result = await service.check_now(transport)
    assert result.version == expected
    assert service.visible_notice().version == expected
    assert not service.settings.check_updates
    assert service._task is None
    await service.close()


@pytest.mark.parametrize("status", [302, 429, 500, 304])
async def test_failed_manual_checks_never_report_up_to_date(tmp_path, status):
    service = DesktopService(tmp_path)
    with pytest.raises(ValueError, match="Unable to check"):
        await service.check_now(httpx.MockTransport(lambda _: httpx.Response(status)))
    await service.close()


async def test_manual_cached_check(tmp_path):
    service = DesktopService(tmp_path)
    service.etag = '"release"'
    service.notice = UpdateNotice(version="v2.3.0")
    assert (
        await service.check_now(httpx.MockTransport(lambda _: httpx.Response(304)))
    ).version == "v2.3.0"
    await service.close()


def test_manual_check_button_and_update_action(monkeypatch):
    from frontend.views.desktop import DesktopControls
    from tests.v2.test_module_ui import ViewModelFixture

    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("frontend.views.desktop.sys.platform", "win32")
    vm = ViewModelFixture()
    panel = DesktopControls(vm)
    panel.update_state("settings-load", DesktopSettings(dismissed_version="v2.3.0"))
    panel.check_button.click()
    assert not panel.check_button.isEnabled()
    assert vm.calls[-1][1][:2] == ("updates-check", "/api/v1/updates/check")
    panel.update_state("updates-check", UpdateNotice())
    assert panel.check_status.raw_text == "You are up to date"
    assert panel.check_button.isEnabled()
    panel.update_state(
        "updates-check", UpdateNotice(version="v2.3.0", installer_url="https://fixture.invalid")
    )
    assert panel.download_button.text() == "Update to v2.3.0"
    assert not panel.banner.isHidden()
    panel.update_state("updates", panel.notice.model_copy())
    assert not panel.banner.isHidden()
    assert panel.download_button.isEnabled()
    panel.download_button.click()
    assert vm.calls[-1][1][2] == "/api/v1/updates/download"
    assert not panel.install_button.isEnabled()
    panel.error("updates-check", "Offline")
    assert panel.check_status.property("state") == "failed"
    assert panel.check_button.isEnabled()
    panel.update_state("update-progress", UpdateProgress(phase="downloading"))
    assert not panel.check_button.isEnabled()
    panel.deleteLater()
    app.processEvents()


@pytest.mark.parametrize(
    "body", [b"invalid", b"[]", b"x" * 65537], ids=["malformed", "wrong-type", "oversized"]
)
async def test_invalid_manual_response_is_an_error(tmp_path, body):
    service = DesktopService(tmp_path)
    with pytest.raises(ValueError, match="Unable to check"):
        await service.check_now(httpx.MockTransport(lambda _: httpx.Response(200, content=body)))
    await service.close()


async def test_offline_manual_check_is_an_error(tmp_path):
    service = DesktopService(tmp_path)

    def offline(request):
        raise httpx.ConnectError("offline")

    with pytest.raises(ValueError, match="Unable to check"):
        await service.check_now(httpx.MockTransport(offline))
    assert not service.settings.check_updates
    await service.close()


async def test_manual_update_endpoint_is_authenticated(tmp_path, monkeypatch):
    from backend.main import create_app

    app = create_app("a" * 64, "manual-updates", tmp_path)
    async with app.router.lifespan_context(app):
        calls = []

        async def checked():
            calls.append(True)
            return UpdateNotice(version="v2.3.0")

        monkeypatch.setattr(app.state.desktop, "check_now", checked)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://localhost"
        ) as client:
            assert (await client.get("/api/v1/updates/check")).status_code == 401
            assert not calls
            response = await client.get(
                "/api/v1/updates/check", headers={"Authorization": "Bearer " + "a" * 64}
            )
            assert response.status_code == 200
            assert response.json()["version"] == "v2.3.0"
            assert calls == [True]


def test_old_poll_cannot_clear_manual_result(monkeypatch):
    from uuid import uuid4

    from frontend.viewmodels.app_vm import AppViewModel
    from frontend.views.desktop import DesktopControls
    from tests.v2.test_module_ui import ViewModelFixture

    class PollingFixture(ViewModelFixture):
        get = AppViewModel.get
        invalidate = AppViewModel.invalidate

        def __init__(self):
            super().__init__()
            self._closing = False
            self._actions = {}
            self._latest = {}
            self._action_scopes = {}
            self._vault_generations = {}

        def run_get(self, *args):
            return uuid4()

    app = QApplication.instance() or QApplication([])
    vm = PollingFixture()
    panel = DesktopControls(vm)
    try:
        panel.refresh()
        stale_poll = vm._latest["updates"]
        panel.check_updates()
        check = vm._latest["updates-check"]
        panel.refresh()
        assert vm._latest["updates"] != stale_poll
        AppViewModel._result(
            vm, check, UpdateNotice(version="v2.3.0", installer_url="https://fixture.invalid")
        )
        AppViewModel._result(vm, stale_poll, UpdateNotice())
        assert panel.notice.version == "v2.3.0"
        assert not panel.banner.isHidden()
        assert panel.download_button.text() == "Update to v2.3.0"
    finally:
        panel.deleteLater()
        app.processEvents()
