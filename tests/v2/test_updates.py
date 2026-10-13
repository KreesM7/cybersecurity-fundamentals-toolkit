"""Controlled assets: no test executes a downloaded installer or contacts a target."""

import asyncio
import hashlib
import json
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import httpx
import pytest

from backend.events import EventHub
from backend.platform_utils import atomic_private_write
from backend.services import update_service as updates
from backend.services.desktop_service import DesktopService
from shared.desktop import UpdateProgress

VERSION = "v2.2.0"
PAYLOAD = b"fake installer fixture"
VERIFIER = b"fake verifier fixture"


def release():
    name = updates.installer_name(VERSION)
    sizes = {
        name: len(PAYLOAD),
        "SHA256SUMS": 200,
        name + ".sigstore.json": 100,
        "SHA256SUMS.sigstore.json": 100,
    }
    return {
        "tag_name": VERSION,
        "draft": False,
        "prerelease": False,
        "assets": [
            {
                "name": key,
                "size": size,
                "browser_download_url": updates.DOWNLOAD + VERSION + "/" + key,
            }
            for key, size in sizes.items()
        ],
    }


def notice():
    return updates.release_notice(VERSION, release())


@pytest.fixture
def verifier(monkeypatch):
    monkeypatch.setattr(updates, "COSIGN_SIZE", len(VERIFIER))
    monkeypatch.setattr(updates, "COSIGN_SHA256", hashlib.sha256(VERIFIER).hexdigest())
    run = Mock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr(updates.subprocess, "run", run)
    monkeypatch.setattr(updates, "install_directory", lambda: None)
    # Only the platform gate changes; do not patch global sys.platform on Linux.
    monkeypatch.setattr(updates, "sys", SimpleNamespace(platform="win32"))
    return run


def transport(payload=PAYLOAD, manifest=None):
    name = updates.installer_name(VERSION)
    manifest = manifest or (hashlib.sha256(PAYLOAD).hexdigest() + "  " + name + "\n").encode()

    def respond(request):
        assert request.headers.get("authorization") is None
        if str(request.url) == updates.COSIGN_URL:
            return httpx.Response(200, content=VERIFIER)
        if request.url.path.endswith("SHA256SUMS"):
            return httpx.Response(200, content=manifest)
        if request.url.path.endswith(".sigstore.json"):
            return httpx.Response(200, content=b"signature fixture")
        return httpx.Response(200, content=payload)

    return httpx.MockTransport(respond)


async def service(tmp_path):
    value = updates.UpdateService(tmp_path, EventHub())
    await value.start()
    value.transport = transport()
    return value


async def test_release_check_captures_only_exact_assets(tmp_path):
    value = DesktopService(tmp_path)
    value.settings.check_updates = True
    await value.check(httpx.MockTransport(lambda _: httpx.Response(200, json=release())))
    assert value.notice == notice()
    assert value.notice.installer_size == len(PAYLOAD)
    for changed in ("https://evil.invalid/file.exe", "http://github.com/file", "file:///C:/x"):
        data = release()
        data["assets"][0]["browser_download_url"] = changed
        assert not updates.release_notice(VERSION, data).installer_url
    for data in ({"assets": {}}, {"assets": [None]}, {"assets": release()["assets"] * 2}):
        assert not updates.release_notice(VERSION, data).installer_url
    data = release()
    data["assets"][0]["size"] = updates.MAX_INSTALLER + 1
    assert not updates.release_notice(VERSION, data).installer_url
    await value.close()


async def test_happy_download_does_not_execute_and_apply_rechecks(tmp_path, verifier, monkeypatch):
    value = await service(tmp_path)
    initial = await value.download_update(notice())
    assert initial.phase == "downloading"
    await value.task
    assert value.progress.phase == "verified"
    assert value.progress.checksum_verified and value.progress.signature_verified
    assert not value.pending
    assert len(verifier.call_args_list) == 2
    for call in verifier.call_args_list:
        assert call.args[0][1] == "verify-blob"
        assert "--certificate-oidc-issuer" in call.args[0]
        assert "--insecure-ignore-tlog" not in call.args[0]
    assert any(row.topic == "update-progress" for row in value.hub.recent)
    monkeypatch.setattr(updates, "install_directory", lambda: tmp_path / "installed")
    assert (await value.apply_update(VERSION)).phase == "preparing"
    await value.task
    assert value.pending and value.progress.phase == "prepared"
    assert verifier.call_count == 4
    await value.close()


@pytest.mark.parametrize(
    "failure",
    ["checksum", "signature", "manifest-signature", "verifier", "short", "oversize", "network"],
)
async def test_failed_download_deleted_no_install(tmp_path, verifier, monkeypatch, failure):
    value = await service(tmp_path)
    if failure == "checksum":
        value.transport = transport(payload=b"X" * len(PAYLOAD))
    elif failure in {"signature", "manifest-signature"}:
        verifier.side_effect = (
            [SimpleNamespace(returncode=0), SimpleNamespace(returncode=1)]
            if failure == "signature"
            else [SimpleNamespace(returncode=1)]
        )
    elif failure == "verifier":
        monkeypatch.setattr(updates, "COSIGN_SHA256", "0" * 64)
    elif failure == "short":
        value.transport = transport(payload=b"x")
    elif failure == "oversize":
        value.transport = transport(payload=b"x" * (len(PAYLOAD) + 1))
    elif failure == "network":
        value.transport = httpx.MockTransport(lambda _: httpx.Response(503))
    await value.download_update(notice())
    await value.task
    assert value.progress.phase == "failed"
    assert not value.progress.signature_verified and not value.progress.checksum_verified
    assert not (value.directory / "installer.exe").exists()
    monkeypatch.setattr(updates, "install_directory", lambda: tmp_path)
    with pytest.raises(updates.UpdateError):
        await value.apply_update(VERSION)
    assert not value.pending
    await value.close()


async def test_modified_download_rejected_at_apply(tmp_path, verifier, monkeypatch):
    value = await service(tmp_path)
    await value.download_update(notice())
    await value.task
    atomic_private_write(value.directory / "installer.exe", b"tampered")
    monkeypatch.setattr(updates, "install_directory", lambda: tmp_path)
    await value.apply_update(VERSION)
    await value.task
    assert value.progress.phase == "failed" and not value.pending
    assert verifier.call_count == 2  # second checksum fails before any signature process


async def test_new_launch_discards_cached_trust(tmp_path, verifier):
    value = await service(tmp_path)
    await value.download_update(notice())
    await value.task
    replacement = await service(tmp_path)
    assert replacement.progress.phase == "idle"
    assert not replacement.progress.signature_verified
    assert not (replacement.directory / "installer.exe").exists()


@pytest.mark.parametrize(
    "location",
    [
        "http://release-assets.githubusercontent.com/a",
        "https://evil.invalid/a",
        "https://user:pw@release-assets.githubusercontent.com/a",
        "https://release-assets.githubusercontent.com:99/a",
        "/relative",
    ],
)
async def test_redirect_restrictions(tmp_path, verifier, location):
    value = await service(tmp_path)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(302, headers={"location": location}))
    ) as client:
        with pytest.raises(updates.UpdateError, match="redirect"):
            await value._fetch(client, updates.COSIGN_URL, value.directory / "part", 10)
    assert not (value.directory / "part").exists()


async def test_allowed_asset_redirect_and_limits(tmp_path, verifier):
    value = await service(tmp_path)
    calls = []

    def respond(request):
        calls.append(str(request.url))
        if len(calls) == 1:
            return httpx.Response(
                302, headers={"Location": "https://release-assets.githubusercontent.com/a"}
            )
        return httpx.Response(200, content=b"ok")

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        await value._fetch(client, updates.COSIGN_URL, value.directory / "part", 10)
    assert (value.directory / "part").read_bytes() == b"ok" and len(calls) == 2
    for response in (
        httpx.Response(200, headers={"Content-Length": "999"}),
        httpx.Response(206),
        httpx.Response(200, content=b""),
    ):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: response)) as client:
            with pytest.raises(updates.UpdateError):
                await value._fetch(client, updates.COSIGN_URL, value.directory / "part", 10)


async def test_cancel_download_cleans_partial_and_duplicate_rejected(tmp_path, verifier):
    value = await service(tmp_path)
    entered = asyncio.Event()

    async def stalled(request):
        entered.set()
        await asyncio.Event().wait()

    value.transport = httpx.MockTransport(stalled)
    await value.download_update(notice())
    await entered.wait()
    with pytest.raises(updates.UpdateError, match="already"):
        await value.download_update(notice())
    await value.close()
    assert value.task.done() and not (value.directory / "installer.exe").exists()


async def test_handoff_requires_both_checks_and_correct_flags(tmp_path, verifier, monkeypatch):
    from backend import update_handoff as handoff

    value = await service(tmp_path)
    target = tmp_path / "installed path"
    monkeypatch.setattr(updates, "install_directory", lambda: target)
    monkeypatch.setattr(handoff, "install_directory", lambda: target)
    launch = Mock()
    monkeypatch.setattr(handoff.subprocess, "Popen", launch)
    with pytest.raises(updates.UpdateError):
        handoff.launch_pending_update(value)
    launch.assert_not_called()
    await value.download_update(notice())
    await value.task
    with pytest.raises(updates.UpdateError):
        handoff.launch_pending_update(value)
    await value.apply_update(VERSION)
    await value.task
    value.progress.signature_verified = False
    with pytest.raises(updates.UpdateError):
        handoff.launch_pending_update(value)
    launch.assert_not_called()
    value.progress.signature_verified = True
    handoff.launch_pending_update(value)
    assert launch.call_count == 1 and not value.pending
    command = handoff.silent_install_command(value.directory / "installer.exe", target)
    assert command[1:4] == ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]
    assert command[-1] == "/DIR=" + str(target)
    plan = json.loads((value.directory / "apply.json").read_text())
    assert plan["directory"] == str(target)
    assert plan["application"] == str(target / updates.EXE)
    assert not json.loads((value.directory / "updated.json").read_text())["complete"]
    assert handoff.consume_update_message(tmp_path, "2.0.0").startswith("Update did not complete")
    atomic_private_write(
        value.directory / "updated.json",
        json.dumps({"version": VERSION, "complete": True}).encode(),
    )
    assert handoff.consume_update_message(tmp_path, "2.2.0") == "Updated to v2.2.0"
    assert handoff.consume_update_message(tmp_path, "2.2.0") == ""


@pytest.mark.parametrize("error", [subprocess.TimeoutExpired("cosign", 60), OSError("unavailable")])
def test_verifier_failure_is_closed(tmp_path, verifier, error):
    for name, data in (("cosign.exe", VERIFIER), ("installer", PAYLOAD), ("bundle", b"bundle")):
        atomic_private_write(tmp_path / name, data)
    verifier.side_effect = error
    with pytest.raises(updates.UpdateError):
        updates.verify_signature(
            tmp_path / "cosign.exe", tmp_path / "installer", tmp_path / "bundle", VERSION
        )


def test_verifier_rejects_override_and_wrong_identity(monkeypatch):
    import re

    monkeypatch.setenv("COSIGN_REPOSITORY", "attacker")
    monkeypatch.setenv("HTTPS_PROXY", "https://evil.invalid")
    env = updates.verifier_environment()
    assert "COSIGN_REPOSITORY" not in env and "HTTPS_PROXY" not in env
    pattern = updates.identity_pattern(VERSION)
    assert re.fullmatch(pattern, updates.WORKFLOW + "refs/heads/main")
    assert re.fullmatch(pattern, updates.WORKFLOW + "refs/tags/" + VERSION)
    assert not re.fullmatch(pattern, updates.WORKFLOW + "refs/heads/evil")
    assert not re.fullmatch(pattern, updates.WORKFLOW + "refs/tags/v9.0.0")


async def test_update_endpoints_auth_idempotency_and_no_execution(tmp_path, verifier, monkeypatch):
    from backend.main import create_app

    app = create_app("a" * 64, "updates", tmp_path)
    async with app.router.lifespan_context(app):
        desktop = app.state.desktop
        desktop.notice = notice()
        desktop.settings.check_updates = True
        desktop.updater.transport = transport()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://localhost"
        ) as client:
            assert (
                await client.post("/api/v1/updates/download", json={"version": VERSION})
            ).status_code == 401
            client.headers["Authorization"] = "Bearer " + "a" * 64
            assert (
                await client.post("/api/v1/updates/download", json={"version": VERSION})
            ).status_code == 422
            headers = {"X-Request-ID": str(uuid4())}
            first = await client.post(
                "/api/v1/updates/download", json={"version": VERSION}, headers=headers
            )
            assert first.status_code == 202
            await desktop.updater.task
            again = await client.post(
                "/api/v1/updates/download", json={"version": VERSION}, headers=headers
            )
            assert first.json() == again.json()
            conflict = await client.post(
                "/api/v1/updates/download", json={"version": "v3.0.0"}, headers=headers
            )
            assert conflict.status_code == 409
            assert (await client.get("/api/v1/updates/progress")).json()["phase"] == "verified"
            assert not desktop.updater.pending
            monkeypatch.setattr(updates, "install_directory", lambda: tmp_path)
            response = await client.post(
                "/api/v1/updates/apply",
                json={"version": VERSION},
                headers={"X-Request-ID": str(uuid4())},
            )
            assert response.status_code == 202
            await desktop.updater.task
            assert desktop.updater.pending


def test_settings_download_verify_failure_and_explicit_install():
    from PyQt6.QtWidgets import QApplication

    from frontend.views.desktop import DesktopControls
    from tests.v2.test_module_ui import ViewModelFixture

    application = QApplication.instance() or QApplication([])
    vm = ViewModelFixture()
    panel = DesktopControls(vm)
    panel.notice = notice()
    panel.render_update()
    assert not panel.install_button.isEnabled()
    clicks = []
    panel.install_requested.connect(lambda: clicks.append(True))
    panel.update_state(
        "update-progress",
        UpdateProgress(
            version=VERSION,
            phase="verified",
            checksum_verified=True,
            signature_verified=True,
            can_apply=True,
        ),
    )
    assert panel.install_button.isEnabled() and not clicks
    panel.install_button.click()
    assert clicks == [True]
    panel.update_state(
        "update-progress",
        UpdateProgress(version=VERSION, phase="failed", message="Checksum mismatch"),
    )
    assert panel.verification.property("state") == "failed"
    assert not panel.install_button.isEnabled()
    assert panel.download_button.text() == "Retry download"
    panel.settings_panel.deleteLater()
    panel.deleteLater()
    application.processEvents()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows installer handoff")
@pytest.mark.parametrize("failure", [None, "checksum", "signature"])
def test_real_windows_helper_silent_arguments_and_relaunch(tmp_path, failure):
    """Real Windows processes, harmless C# stubs; never executes a release installer."""
    import os
    import shutil
    from pathlib import Path

    from backend import update_handoff

    compiler = Path(os.environ["SystemRoot"]) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
    if not compiler.exists():
        pytest.skip("Windows .NET Framework compiler unavailable")
    source = tmp_path / "Stub.cs"
    source.write_text("""using System;
using System.IO;
class Stub {
  static int Main(string[] args) {
    string file = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
    string dir = Path.GetDirectoryName(file);
    if (args.Length > 0 && args[0] == "verify-blob") {
      return File.Exists(Path.Combine(dir, "reject")) ? 1 : 0;
    }
    File.WriteAllLines(file + ".args", args);
    return 0;
  }
}""")
    binary = tmp_path / "stub.exe"
    subprocess.run(
        [str(compiler), "/nologo", "/target:exe", "/out:" + str(binary), str(source)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    for name in ("cosign.exe", "installer.exe", "application.exe"):
        shutil.copyfile(binary, tmp_path / name)
    (tmp_path / "sums").write_text("fixture")
    (tmp_path / "bundle").write_text("fixture")
    if failure == "signature":
        (tmp_path / "reject").touch()
    target = tmp_path / "installed space café"
    target.mkdir()
    profile = tmp_path / "profile with space"
    profile.mkdir()
    plan = {
        "parent": 2147483647,
        "version": VERSION,
        "installer": str(tmp_path / "installer.exe"),
        "verifier": str(tmp_path / "cosign.exe"),
        "checksums": str(tmp_path / "sums"),
        "signature": str(tmp_path / "bundle"),
        "checksums_signature": str(tmp_path / "bundle"),
        "verifier_hash": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "installer_hash": (
            "0" * 64 if failure == "checksum" else hashlib.sha256(binary.read_bytes()).hexdigest()
        ),
        "manifest_hash": hashlib.sha256(b"fixture").hexdigest(),
        "identity": updates.identity_pattern(VERSION),
        "directory": str(target),
        "application": str(tmp_path / "application.exe"),
        "profile": str(profile),
        "flag": str(tmp_path / "updated.json"),
    }
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan, ensure_ascii=False), "utf-8")
    script = Path(update_handoff.__file__).parent / "resources/apply-update.ps1"
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-Plan",
            str(path),
        ],
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    marker = json.loads((tmp_path / "updated.json").read_text("utf-8-sig"))
    assert marker["complete"] is (failure is None), result.stdout.decode(errors="replace")
    installed = tmp_path / "installer.exe.args"
    if failure is None:
        assert (
            installed.read_text(encoding="utf-8-sig").splitlines()
            == update_handoff.silent_install_command(tmp_path / "installer.exe", target)[1:]
        )
    else:
        assert not installed.exists()
    import time

    for _ in range(100):
        if (tmp_path / "application.exe.args").exists():
            break
        time.sleep(0.05)
    assert (tmp_path / "application.exe.args").read_text(encoding="utf-8-sig").splitlines() == [
        "--profile",
        str(profile),
    ]
    assert not path.exists()


@pytest.mark.parametrize("allow", [True, False])
def test_window_install_requires_click_and_shutdown_confirmation(monkeypatch, allow):
    from PyQt6.QtWidgets import QApplication

    from frontend.main_window import MainWindow
    from shared.framework import ShutdownCheck
    from tests.v2.presentation_fixture import PresentationModel

    app = QApplication.instance() or QApplication([])
    vm = PresentationModel()
    window = MainWindow(vm)
    window.show()
    panel = window.desktop_controls
    panel.notice = notice()
    ready = UpdateProgress(
        version=VERSION,
        phase="verified",
        checksum_verified=True,
        signature_verified=True,
        can_apply=True,
    )
    vm.state_changed.emit("update-progress", ready)
    assert not window.update_exit and not window._installing
    monkeypatch.setattr(window, "_confirm_shutdown", lambda: allow)
    panel.install_button.click()
    assert window._installing
    vm.state_changed.emit("shutdown-check", ShutdownCheck(confirmation_required=True))
    calls = [call for call in vm.calls if call[0] and call[0][0] == "update-apply"]
    assert bool(calls) is allow
    vm.state_changed.emit("update-progress", ready.model_copy(update={"phase": "prepared"}))
    assert window.update_exit is allow
    if not allow:
        window._closing = True
        window.close()
    app.processEvents()


async def test_cancel_waits_for_owned_verifier(tmp_path, verifier, monkeypatch):
    import threading

    value = await service(tmp_path)
    entered, release_gate = threading.Event(), threading.Event()

    def slow():
        entered.set()
        release_gate.wait(5)

    monkeypatch.setattr(value, "verify", slow)
    task = asyncio.create_task(value._verify_owned())
    await asyncio.to_thread(entered.wait, 5)
    task.cancel()
    await asyncio.sleep(0.02)
    assert not task.done()
    release_gate.set()
    with pytest.raises(asyncio.CancelledError):
        await task


def test_native_apply_only_in_installed_windows_build(tmp_path, monkeypatch):
    monkeypatch.setattr(
        updates,
        "sys",
        SimpleNamespace(platform="linux", frozen=True, executable=str(tmp_path / updates.EXE)),
    )
    assert updates.install_directory() is None
    updates.sys.platform = "win32"
    updates.sys.frozen = False
    assert updates.install_directory() is None
    updates.sys.frozen = True
    assert updates.install_directory() is None
    (tmp_path / "unins000.exe").touch()
    assert updates.install_directory() == tmp_path
