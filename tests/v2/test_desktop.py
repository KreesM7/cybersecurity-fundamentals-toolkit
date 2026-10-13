import json

import httpx
import pytest
from PyQt6.QtWidgets import QApplication

from backend.services.desktop_service import (
    RELEASE_API,
    RELEASE_PAGE,
    DesktopService,
    stable_version,
)
from shared.desktop import DesktopSettings, UpdateNotice


@pytest.mark.parametrize(
    "value", ["2.3.0-beta", "v02.3.0", "9999999.1.0", "2.0", "file:///etc/passwd"]
)
def test_stable_versions_only(value):
    assert stable_version(value) is None


async def test_update_bounds_etag_persistence_dismiss_and_quiet_failures(tmp_path):
    service = DesktopService(tmp_path)
    await service.start()
    assert service._task is None
    service.settings.check_updates = True
    requests = []

    def fixture(request):
        requests.append(request)
        assert str(request.url) == RELEASE_API
        assert "authorization" not in request.headers
        return httpx.Response(
            200,
            headers={"ETag": '"fixture"'},
            json={
                "tag_name": "v2.3.0",
                "draft": False,
                "prerelease": False,
                "html_url": "https://untrusted.invalid/",
            },
        )

    await service.check(httpx.MockTransport(fixture))
    assert service.visible_notice().url == RELEASE_PAGE + "v2.3.0"
    await service.check(httpx.MockTransport(fixture))
    assert requests[-1].headers["If-None-Match"] == '"fixture"'
    service.settings.dismissed_version = "v2.3.0"
    assert not service.visible_notice().version
    await service.update(
        service.settings.model_copy(update={"check_updates": False, "theme": "light"})
    )
    restored = DesktopService(tmp_path)
    await restored.start()
    assert restored.settings.theme == "light" and restored.etag == '"fixture"'
    assert restored._task is None
    restored.settings.check_updates = True
    for status in (304, 404, 429, 302, 500):
        await restored.check(
            httpx.MockTransport(
                lambda _: httpx.Response(status, headers={"Location": "http://127.0.0.1"})
            )
        )
        assert restored.notice.version == "v2.3.0"
    for result in (
        {"tag_name": "3.0.0-beta", "draft": False, "prerelease": False},
        ["wrong"],
        {"body": "a" * 65537},
    ):
        await restored.check(httpx.MockTransport(lambda _: httpx.Response(200, json=result)))
        assert restored.notice.version == "v2.3.0"

    def offline(request):
        raise httpx.ConnectError("offline")

    await restored.check(httpx.MockTransport(offline))
    await service.close()
    await restored.close()


def test_desktop_preferences_onboarding_and_banner():
    from frontend.views.desktop import DesktopControls
    from tests.v2.test_module_ui import ViewModelFixture

    app = QApplication.instance() or QApplication([])
    vm = ViewModelFixture()
    panel = DesktopControls(vm)
    panel.update_state("settings-load", DesktopSettings())
    panel.theme.setCurrentText("light")
    assert panel.settings.theme == "light"
    panel.finish_onboarding()
    assert panel.settings.onboarding_complete
    panel.update_state("updates", UpdateNotice(version="v2.3.0", url=RELEASE_PAGE + "v2.3.0"))
    assert not panel.banner.isHidden()
    panel.dismiss_update()
    assert panel.banner.isHidden()
    panel.save()
    assert vm.calls[-1][1][0] == "settings-save"
    panel.settings_panel.deleteLater()
    panel.deleteLater()
    app.processEvents()


async def test_settings_api_and_dashboard(tmp_path):
    from uuid import uuid4

    from backend.main import create_app

    app = create_app("a" * 64, "desktop", tmp_path)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app),
            base_url="https://localhost",
            headers={"Authorization": "Bearer " + "a" * 64},
        ) as client:
            data = DesktopSettings(theme="system").model_dump()
            headers = {"X-Request-ID": str(uuid4())}
            assert (
                await client.put("/api/v1/settings", json=data, headers=headers)
            ).status_code == 200
            assert (await client.get("/api/v1/settings")).json()["theme"] == "system"
            response = await client.get(
                "/api/v1/dashboard", params={"workspace_id": str(app.state.workspaces.active_id)}
            )
            assert response.status_code == 200 and response.json()["targets"] == 0
            assert (await client.get("/api/v1/updates")).json() == UpdateNotice().model_dump()
    assert json.loads((tmp_path / "desktop.json").read_text())["settings"]["theme"] == "system"


def test_closed_viewmodel_drops_queued_callbacks():
    import ssl
    from uuid import uuid4

    from frontend.viewmodels.app_vm import AppViewModel

    viewmodel = AppViewModel("https://127.0.0.1:1", ssl.create_default_context(), "a" * 64)
    received = []
    viewmodel.state_changed.connect(lambda *args: received.append(args))
    identifier = uuid4()
    viewmodel._actions[identifier] = "settings-load"
    viewmodel._action_scopes[identifier] = None
    viewmodel.close()
    viewmodel._result(identifier, DesktopSettings())
    viewmodel._action_failed(identifier, "closed")
    viewmodel._event(json.dumps({"topic": "resync"}))
    assert received == []
