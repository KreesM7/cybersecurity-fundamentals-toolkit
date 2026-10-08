"""Seven-tool boundaries and in-memory submission contracts."""

import asyncio
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from backend.events import EventHub
from backend.jobs import JobManager
from backend.services.tool_service import ToolService
from backend.services.workspace_service import WorkspaceService
from shared.tools import CaesarOptions, PasswordOptions, ScannerOptions
from toolkit.traffic import read_traffic_bytes


def test_password_transport_is_explicit_and_repr_hides_secret():
    options = PasswordOptions(password="practice-secret")
    assert "practice-secret" not in repr(options)
    assert options.model_dump(mode="json")["password"] == "**********"
    assert options.transport_dump()["password"] == "practice-secret"
    with pytest.raises(ValidationError):
        PasswordOptions(password="x" * 73)


def test_ram_csv_reports_malformed_and_out_of_order():
    data = read_traffic_bytes(
        b"timestamp,source_ip,bytes,protocol\n2,127.0.0.1,2,TCP\n1,127.0.0.1,1,TCP\nbad,127.0.0.1,1,TCP\n",
        "events.csv",
        require_volume=True,
    )
    assert len(data.events) == 2 and data.skipped == 1 and not data.complete
    assert any("order" in warning for warning in data.warnings)
    with pytest.raises(ValueError, match="UTF-8"):
        read_traffic_bytes(b"\xff", "events.csv")


async def test_submission_results_and_workspace_lease(tmp_path: Path):
    workspaces = WorkspaceService(tmp_path)
    await workspaces.start()
    jobs = JobManager(EventHub())
    tools = ToolService(workspaces, jobs)
    try:
        result = await tools.submit("caesar", CaesarOptions(text="Az! é", shift=1))
        assert workspaces._engines[result.workspace_id].references == 1
        await jobs.wait_idle()
        snapshot = jobs.get(result.id, result.workspace_id)
        assert snapshot.result["text"] == "Ba! é"
        assert len(snapshot.result["candidates"]) == 25
        assert workspaces._engines[result.workspace_id].references == 0
        assert "PySide6" not in sys.modules and "scapy" not in sys.modules
    finally:
        await jobs.close()
        await tools.close()
        await workspaces.close()


async def test_unowned_scanner_never_creates_job(tmp_path: Path):
    workspaces = WorkspaceService(tmp_path)
    await workspaces.start()
    jobs = JobManager(EventHub())
    tools = ToolService(workspaces, jobs)
    try:
        with pytest.raises(ValueError, match="permission"):
            await tools.submit("network-scanner", ScannerOptions(target="127.0.0.1"))
        assert not jobs.records
        assert workspaces._engines[workspaces.active_id].references == 0
    finally:
        await jobs.close()
        await tools.close()
        await workspaces.close()


async def test_queued_cancel_and_active_clear_release_actual_tool_leases(
    tmp_path: Path, monkeypatch
):
    from threading import Event

    from toolkit.modules import caesar

    entered, release = Event(), Event()
    original = caesar.transform

    def gated(*args, **kwargs):
        entered.set()
        release.wait(3)
        return original(*args, **kwargs)

    monkeypatch.setattr(caesar, "transform", gated)
    workspaces = WorkspaceService(tmp_path)
    await workspaces.start()
    jobs = JobManager(EventHub())
    tools = ToolService(workspaces, jobs)
    try:
        snapshots = [
            await tools.submit("caesar", CaesarOptions(text=str(index))) for index in range(3)
        ]
        while not entered.is_set():
            await asyncio.sleep(0.01)
        assert workspaces._engines[workspaces.active_id].references == 3
        await jobs.cancel(snapshots[2].id, snapshots[2].workspace_id)
        assert workspaces._engines[workspaces.active_id].references == 2
        clearing = asyncio.create_task(jobs.clear(snapshots[0].id, snapshots[0].workspace_id))
        await asyncio.sleep(0.05)
        assert not clearing.done()
        assert workspaces._engines[workspaces.active_id].references == 2
        release.set()
        await clearing
        await jobs.close()
        assert snapshots[0].id not in jobs.records
        assert workspaces._engines[workspaces.active_id].references == 0
    finally:
        release.set()
        await jobs.close()
        await tools.close()
        await workspaces.close()
