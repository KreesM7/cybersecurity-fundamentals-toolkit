"""Real local PTYs; no security-tool target, capture or network is touched."""

import sys
import time

import pytest

from toolkit.secdesk.terminal import NativeTerminal


def wait_output(terminal, needle):
    chunks = []
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        chunks.append(terminal.read())
        if needle in "".join(chunks):
            return "".join(chunks)
        time.sleep(0.02)
    pytest.fail("Real PTY output did not arrive")


def test_native_terminal_normal_exit_resize_and_input(tmp_path):
    terminal = NativeTerminal(
        [sys.executable, "-u", "-c", "print('ready'); print(input())"], tmp_path
    )
    try:
        wait_output(terminal, "ready")
        terminal.resize(32, 100)
        terminal.write("fixture-line\r")
        wait_output(terminal, "fixture-line")
    finally:
        terminal.close()
    assert not terminal.alive()


def test_native_terminal_killed_mid_command_and_repeated_cleanup(tmp_path):
    terminal = NativeTerminal(
        [sys.executable, "-u", "-c", "import time; print('ready'); time.sleep(60)"], tmp_path
    )
    wait_output(terminal, "ready")
    terminal.close()
    terminal.close()
    assert not terminal.alive()


def test_native_terminal_rejects_unbounded_dimensions_and_input(tmp_path):
    with pytest.raises(ValueError):
        NativeTerminal([], tmp_path)
    terminal = NativeTerminal([sys.executable, "-u", "-c", "import time; time.sleep(60)"], tmp_path)
    try:
        with pytest.raises(ValueError):
            terminal.resize(0, 100)
        with pytest.raises(ValueError):
            terminal.write("x" * 4097)
    finally:
        terminal.close()


async def test_native_service_authorization_ownership_audit_and_shutdown(tmp_path, monkeypatch):
    import asyncio
    from uuid import uuid4

    from pydantic import SecretStr

    from backend.events import EventHub
    from backend.services.secdesk_service import SecDeskService
    from backend.services.workspace_service import WorkspaceService
    from shared.secdesk import NativeHandle, NativeInput, NativeLaunch, NativeResize

    with pytest.raises(ValueError):
        NativeLaunch(workspace_id=uuid4(), tool_id="tcpdump", mode="terminal", authorized=False)
    workspaces = WorkspaceService(tmp_path)
    await workspaces.start()
    service = SecDeskService(workspaces, EventHub())
    import shutil

    original_which = shutil.which
    monkeypatch.setattr(
        "toolkit.secdesk.registry.shutil.which",
        lambda name: original_which(name) if name == "sh" else sys.executable,
    )
    data = NativeLaunch(
        workspace_id=workspaces.active_id, tool_id="tcpdump", mode="terminal", authorized=True
    )
    try:
        launched = await service.open(data)
        handle = NativeHandle(id=launched.id, workspace_id=launched.workspace_id)
        await service.resize(NativeResize(**handle.model_dump(), rows=30, columns=90))
        await service.input(
            NativeInput(**handle.model_dump(), text=SecretStr("echo fixture-native\r"))
        )
        for _ in range(50):
            if "fixture-native" in service.snapshot(handle).screen:
                break
            await asyncio.sleep(0.1)
        else:
            pytest.fail("Real owned terminal output missing")
        with pytest.raises(ValueError):
            service.snapshot(NativeHandle(id=launched.id, workspace_id=uuid4()))
        assert (await service.audit(launched.workspace_id))[0].authorized
        assert "fixture-native" not in str(await service.audit(launched.workspace_id))
        await service.stop(handle)
        assert service.snapshot(handle).status == "closed"
        assert service.owned[launched.id].released
    finally:
        await service.close()
        await workspaces.close()


def test_missing_native_component_is_actionable_and_starts_nothing(tmp_path, monkeypatch):
    import importlib

    original = importlib.import_module

    def missing(name, package=None):
        if name == "psutil":
            raise ImportError("fixture missing")
        return original(name, package)

    monkeypatch.setattr(importlib, "import_module", missing)
    with pytest.raises(ValueError, match="runtime missing"):
        NativeTerminal([sys.executable], tmp_path)


@pytest.mark.parametrize("parent_exits", [False, True])
def test_owned_gui_cleans_descendants_after_launcher_exit(tmp_path, parent_exits):
    import psutil

    from toolkit.secdesk.gui_process import NativeGUI

    child_file = tmp_path / "child.pid"
    script = (
        "import subprocess,sys,time,pathlib; "
        "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
        f"pathlib.Path({str(child_file)!r}).write_text(str(p.pid)); "
        + ("" if parent_exits else "time.sleep(60)")
    )
    process = NativeGUI([sys.executable, "-c", script], tmp_path)
    child = None
    try:
        deadline = time.monotonic() + 5
        while not child_file.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert child_file.exists()
        child = psutil.Process(int(child_file.read_text()))
        if parent_exits:
            while process._process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            assert process._process.poll() is not None
            assert process.alive()
        process.close()
        process.close()
        try:
            child.wait(timeout=2)
        except psutil.TimeoutExpired:
            assert child.status() == psutil.STATUS_ZOMBIE
    finally:
        process.close()
        if child is not None:
            try:
                child.wait(timeout=0.1)
            except psutil.TimeoutExpired:
                child.kill()


async def test_immediate_stop_cleans_monitor_cancelled_before_start(tmp_path, monkeypatch):
    import shutil

    from backend.events import EventHub
    from backend.services.secdesk_service import SecDeskService
    from backend.services.workspace_service import WorkspaceService
    from shared.secdesk import NativeLaunch

    original = shutil.which
    monkeypatch.setattr(
        "toolkit.secdesk.registry.shutil.which",
        lambda name: original(name) if name == "sh" else sys.executable,
    )
    workspaces = WorkspaceService(tmp_path)
    await workspaces.start()
    service = SecDeskService(workspaces, EventHub())
    try:
        row = await service.open(
            NativeLaunch(
                workspace_id=workspaces.active_id,
                tool_id="tcpdump",
                mode="terminal",
                authorized=True,
            )
        )
        await service.stop(row)
        assert service.owned[row.id].released
        assert not service.owned[row.id].terminal.alive()
        assert service.snapshot(row).status == "closed"
    finally:
        await service.close()
        await workspaces.close()
