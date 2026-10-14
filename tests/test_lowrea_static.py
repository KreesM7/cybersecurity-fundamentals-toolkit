"""Generated native headers and real decoder output; no target code is executed."""

import hashlib
import struct

import pytest

from shared.lowrea import LowreaOptions


def pe_fixture():
    data = bytearray(1536)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 128)
    data[128:132] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 132, 0x8664, 2, 0, 0, 0, 240, 0x22)
    struct.pack_into("<H", data, 152, 0x20B)
    struct.pack_into("<I", data, 168, 0x1000)
    struct.pack_into("<Q", data, 176, 0x140000000)
    struct.pack_into("<II", data, 184, 0x1000, 0x200)
    struct.pack_into("<II", data, 208, 0x3000, 0x200)
    struct.pack_into("<H", data, 220, 3)
    struct.pack_into("<I", data, 260, 16)
    for table, name, size, rva, raw, flags in (
        (392, b".text", 8, 0x1000, 512, 0x60000020),
        (432, b".rdata", 16, 0x2000, 1024, 0x40000040),
    ):
        data[table : table + len(name)] = name
        struct.pack_into("<IIII", data, table + 8, size, rva, 512, raw)
        struct.pack_into("<I", data, table + 36, flags)
    data[512:520] = bytes.fromhex("488d0df90f0000c3")
    data[1024:1036] = b"LowREA demo\x00"
    return bytes(data)


def test_pe_entry_and_real_rip_reference():
    from toolkit.lowrea.static import inspect_bytes

    data = pe_fixture()
    record = inspect_bytes(data, LowreaOptions(), "fixture.exe").record()
    assert record["subject_sha256"] == hashlib.sha256(data).hexdigest()
    facts = record["normalized_result"]
    assert facts["headers"]["architecture"] == "x86-64"
    assert facts["window"]["offset"] == 512
    assert [row["mnemonic"] for row in facts["instructions"]] == ["lea", "ret"]
    assert facts["references"][0]["file_offset"] == 1024
    assert facts["references"][0]["possible_string"] == "LowREA demo"
    assert facts["unknowns"]


def test_explicit_window_stops_at_virtual_mapping_boundary():
    from toolkit.lowrea.static import inspect_bytes

    facts = inspect_bytes(
        pe_fixture(), LowreaOptions(offset=512, length=16), "fixture.exe"
    ).record()["normalized_result"]
    assert facts["decoder"]["bytes_decoded"] == 8
    assert all(row["file_offset"] < 520 for row in facts["instructions"])
    assert facts["window"]["length"] == 16
    assert any("boundary" in note for note in facts["unknowns"])


@pytest.mark.parametrize("prefix", ["64", "65"])
def test_segment_relative_reference_is_not_a_physical_string(prefix):
    from toolkit.lowrea.static import inspect_bytes

    data = bytearray(pe_fixture())
    struct.pack_into("<I", data, 400, 9)
    data[512:521] = bytes.fromhex(prefix + "488b05f80f0000c3")
    facts = inspect_bytes(bytes(data), LowreaOptions(), "fixture.exe").record()["normalized_result"]
    reference = facts["references"][0]
    assert reference["segment_base_unknown"]
    assert reference["file_offset"] is None
    assert reference["possible_string"] is None


def test_elf_file_size_cannot_exceed_memory_size():
    from toolkit.lowrea.static import inspect_bytes

    data = bytearray(136)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 2, 62, 1)
    struct.pack_into("<QQQ", data, 24, 0x400080, 64, 0)
    struct.pack_into("<HHH", data, 52, 64, 56, 1)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0x400000, 136, 8, 0x1000)
    facts = inspect_bytes(bytes(data), LowreaOptions(), "broken.elf").record()["normalized_result"]
    assert not facts["regions"]
    assert not facts["instructions"]
    assert any("memory size" in note for note in facts["unknowns"])


def test_gui_inspect_waits_for_workspace():
    from PyQt6.QtWidgets import QApplication

    from frontend.views.lowrea import LowreaPanel
    from tests.test_tool_terminals import ToolFixture

    app = QApplication.instance() or QApplication([])
    vm = ToolFixture()
    vm.workspace_id = None
    panel = LowreaPanel(vm)
    panel.file_path.setText("fixture.exe")
    panel.update_buttons()
    panel.inspect()
    assert not panel.inspect_button.isEnabled()
    assert not vm.calls
    panel.deleteLater()
    app.processEvents()


@pytest.mark.parametrize(
    "architecture,code,mnemonic",
    [
        ("x86-64", "b82a000000c3", "mov"),
        ("arm64", "200080d2c0035fd6", "mov"),
    ],
)
def test_declared_raw_architecture_uses_real_decoder(architecture, code, mnemonic):
    from toolkit.lowrea.static import inspect_bytes

    result = inspect_bytes(bytes.fromhex(code), LowreaOptions(architecture=architecture), "raw.bin")
    facts = result.record()["normalized_result"]
    assert facts["headers"]["architecture"] == "unknown"
    assert facts["instructions"][0]["mnemonic"] == mnemonic
    assert facts["instructions"][-1]["mnemonic"] == "ret"


@pytest.mark.parametrize("data", [b"", b"MZ", b"\x7fELF", pe_fixture()[:400], b"text only"])
def test_malformed_headers_preserve_identity_and_unknowns(data):
    from toolkit.lowrea.static import inspect_bytes

    evidence = inspect_bytes(data, LowreaOptions(), "renamed.dll")
    assert evidence.record()["subject_sha256"] == hashlib.sha256(data).hexdigest()
    assert evidence.record()["normalized_result"]["unknowns"]


def test_changed_artifact_and_cancel_are_reported():
    from threading import Event

    from toolkit.lowrea.static import inspect_bytes
    from toolkit.task_context import CancelledError, TaskContext

    with pytest.raises(ValueError, match="Artifact changed"):
        inspect_bytes(b"new", LowreaOptions(expected_sha256="a" * 64), "raw.bin")
    with pytest.raises(ValueError, match="offset"):
        inspect_bytes(b"abc", LowreaOptions(offset=4), "raw.bin")
    event = Event()
    event.set()
    with pytest.raises(CancelledError):
        inspect_bytes(b"abc", LowreaOptions(), "raw.bin", TaskContext(event))


@pytest.mark.parametrize("bits,endian", [(32, "little"), (64, "little"), (64, "big")])
def test_elf_load_segment_and_byte_order(bits, endian):
    from toolkit.lowrea.static import inspect_bytes

    prefix = "<" if endian == "little" else ">"
    data = bytearray(136)
    data[:7] = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1 if endian == "little" else 2, 1])
    struct.pack_into(prefix + "HHI", data, 16, 2, 62 if bits == 64 else 3, 1)
    if bits == 64:
        struct.pack_into(prefix + "QQQ", data, 24, 0x400080, 64, 0)
        struct.pack_into(prefix + "HHH", data, 52, 64, 56, 1)
        struct.pack_into(
            prefix + "IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0x400000, 136, 136, 0x1000
        )
    else:
        struct.pack_into(prefix + "III", data, 24, 0x400080, 52, 0)
        struct.pack_into(prefix + "HHH", data, 40, 52, 32, 1)
        struct.pack_into(
            prefix + "IIIIIIII", data, 52, 1, 0, 0x400000, 0x400000, 136, 136, 5, 0x1000
        )
    data[128:134] = bytes.fromhex("b82a000000c3")
    facts = inspect_bytes(bytes(data), LowreaOptions(), "renamed.txt").record()["normalized_result"]
    assert facts["headers"]["format"] == "ELF"
    assert facts["headers"]["endian"] == endian
    assert facts["window"]["offset"] == 128
    if endian == "little":
        assert facts["instructions"][0]["mnemonic"] == "mov"


async def test_lowrea_upload_auth_mutation_identity_and_workspace_scope(tmp_path):
    import json
    from uuid import uuid4

    import httpx

    from backend.main import create_app
    from shared.workspaces import WorkspaceCreate

    app = create_app("a" * 64, "lowrea", tmp_path)
    async with app.router.lifespan_context(app):
        scope = app.state.workspaces.active_id
        options = LowreaOptions(workspace_id=scope).model_dump_json()
        files = {"file": ("fixture.exe", pe_fixture(), "application/octet-stream")}
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://localhost"
        ) as client:
            assert (
                await client.post("/api/v1/lowrea/inspect", data={"options": options}, files=files)
            ).status_code == 401
            headers = {"Authorization": "Bearer " + "a" * 64, "X-Request-ID": str(uuid4())}
            response = await client.post(
                "/api/v1/lowrea/inspect", headers=headers, data={"options": options}, files=files
            )
            assert response.status_code == 202, response.text
            identifier = response.json()["id"]
            await app.state.jobs.wait_idle()
            result = await client.get(f"/api/v1/jobs/{identifier}", headers=headers)
            assert result.json()["status"] == "succeeded"
            assert (
                result.json()["result"]["subject_sha256"]
                == hashlib.sha256(pe_fixture()).hexdigest()
            )
            repeated = await client.post(
                "/api/v1/lowrea/inspect", headers=headers, data={"options": options}, files=files
            )
            assert repeated.json()["id"] == identifier
            conflict = await client.post(
                "/api/v1/lowrea/inspect",
                headers=headers,
                data={"options": options},
                files={"file": ("fixture.exe", b"different")},
            )
            assert conflict.status_code == 409
            other = await app.state.workspaces.create(WorkspaceCreate(name="Other"))
            denied = await client.get(
                f"/api/v1/jobs/{identifier}",
                headers=headers,
                params={"workspace_id": str(other.id)},
            )
            assert denied.status_code == 404
            assert json.loads(options)["workspace_id"] == str(scope)


def test_lowrea_gui_click_paging_and_workspace_reset():
    from PyQt6.QtWidgets import QApplication

    from frontend.views.lowrea import LowreaPanel
    from tests.test_tool_terminals import ToolFixture
    from toolkit.lowrea.static import inspect_bytes

    app = QApplication.instance() or QApplication([])
    vm = ToolFixture()
    panel = LowreaPanel(vm)
    try:
        panel.file_path.setText("fixture.exe")
        panel.update_buttons()
        panel.inspect_button.click()
        assert vm.calls[-1][0] == "inspect_lowrea"
        assert vm.calls[-1][1][0].expected_sha256 is None
        panel.busy = False
        panel.show_evidence(inspect_bytes(pe_fixture(), LowreaOptions(), "fixture.exe"))
        assert panel.instructions.topLevelItemCount() == 2
        assert "00000200" in panel.hex_output.toPlainText()
        panel.next_button.click()
        assert vm.calls[-1][1][0].offset == 768
        assert vm.calls[-1][1][0].expected_sha256 == hashlib.sha256(pe_fixture()).hexdigest()
        panel.update_state("workspace", None)
        assert panel.evidence is None
        assert not panel.file_path.text()
        assert not panel.export_button.isEnabled()
    finally:
        panel.deleteLater()
        app.processEvents()


async def test_real_mcp_stdio_and_cli_produce_equal_evidence(tmp_path):
    import json
    import subprocess
    import sys
    from pathlib import Path

    from mcp.client import Client
    from mcp.client.stdio import StdioServerParameters

    path = tmp_path / "fixture.exe"
    path.write_bytes(pe_fixture())
    root = Path(__file__).resolve().parent.parent
    cli = subprocess.run(
        [sys.executable, "-m", "toolkit", "lowrea", "inspect", str(path)],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    assert cli.returncode == 0, cli.stderr
    expected = json.loads(cli.stdout)["evidence"]
    parameters = StdioServerParameters(
        command=sys.executable, args=["-m", "toolkit", "lowrea", "serve"], cwd=str(root)
    )
    async with Client(parameters, read_timeout_seconds=20) as client:
        listed = await client.list_tools()
        assert any(
            tool.name == "inspect_static" and tool.annotations.read_only_hint
            for tool in listed.tools
        )
        response = await client.call_tool("inspect_static", {"path": str(path)})
        assert not response.is_error
        assert response.structured_content["evidence"] == expected
        denied = await client.call_tool("inspect_static", {"path": str(tmp_path / "absent")})
        assert denied.is_error
        assert denied.structured_content["error"]["code"] == "artifact_unreadable_or_invalid"


def test_real_https_lowrea_gui_inspection_and_clear(tmp_path):
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QApplication

    from frontend.runtime import BackendThread
    from frontend.viewmodels.app_vm import AppViewModel
    from frontend.views.lowrea import LowreaPanel

    app = QApplication.instance() or QApplication([])
    backend = BackendThread(tmp_path / "profile")
    received, failures = [], []
    backend.ready.connect(lambda locator, tls, owned: received.append((locator, tls)))
    backend.failed.connect(failures.append)
    backend.start()
    vm = panel = None

    def wait(predicate):
        for _ in range(1500):
            if predicate():
                return
            QTest.qWait(10)
        pytest.fail("LowREA HTTPS job did not finish")

    try:
        wait(lambda: received or failures)
        assert not failures
        locator, tls = received[0]
        vm = AppViewModel(
            f"https://127.0.0.1:{locator.port}",
            tls.client_context(),
            locator.token.get_secret_value(),
        )
        vm.refresh_workspaces()
        wait(lambda: vm.workspace_id is not None)
        panel = LowreaPanel(vm)
        path = tmp_path / "real-fixture.exe"
        path.write_bytes(pe_fixture())
        panel.file_path.setText(str(path))
        panel.update_buttons()
        panel.inspect_button.click()
        wait(lambda: panel.evidence is not None or not panel.busy)
        assert panel.evidence is not None, panel.status.text()
        assert panel.instructions.topLevelItemCount() == 2
        assert panel.status.property("state") == "done"
        assert not panel.busy
        panel.clear_button.click()
        assert panel.evidence is None
        assert not panel.export_button.isEnabled()
    finally:
        if vm is not None:
            vm.close()
        backend.stop()
        assert backend.wait(15000)
        if panel is not None:
            panel.deleteLater()
        app.processEvents()


def test_missing_decoder_preserves_identity(monkeypatch):
    from toolkit.lowrea import static

    original = static.importlib.import_module

    def missing(name):
        if name == "capstone":
            raise ImportError("Native decoder unavailable")
        return original(name)

    monkeypatch.setattr(static.importlib, "import_module", missing)
    evidence = static.inspect_bytes(pe_fixture(), LowreaOptions(), "fixture.exe").record()
    assert evidence["provider"]["id"] == "builtin-static"
    assert evidence["subject_sha256"] == hashlib.sha256(pe_fixture()).hexdigest()
    assert not evidence["normalized_result"]["instructions"]
    assert any("unavailable" in note for note in evidence["limitations"])


async def test_mcp_public_server_calls_validate_files_and_preserve_evidence(tmp_path):
    from toolkit.lowrea.domain import Evidence
    from toolkit.lowrea.mcp_server import create_server

    path = tmp_path / "fixture.exe"
    path.write_bytes(pe_fixture())
    server = create_server()
    reply = await server.call_tool("inspect_static", {"path": str(path)})
    assert not reply.is_error
    evidence = Evidence.from_record(reply.structured_content["evidence"])
    assert evidence.record()["subject_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    for arguments in (
        {"path": str(tmp_path)},
        {"path": str(tmp_path / "absent")},
        {"path": str(path), "expected_sha256": "a" * 64},
    ):
        error = await server.call_tool("inspect_static", arguments)
        assert error.is_error
        assert error.structured_content["error"]["code"] == "artifact_unreadable_or_invalid"


async def test_mcp_cancellation_waits_for_owned_worker(tmp_path, monkeypatch):
    import asyncio
    from threading import Event

    from toolkit.lowrea import mcp_server
    from toolkit.task_context import CancelledError

    entered, cancelled, release = Event(), Event(), Event()

    def owned_read(path, options, task):
        entered.set()
        while True:
            try:
                task.check()
            except CancelledError:
                cancelled.set()
                assert release.wait(5), "Worker cleanup was never released"
                raise
            release.wait(0.005)

    monkeypatch.setattr(mcp_server, "inspect_path", owned_read)
    server = mcp_server.create_server()
    request = asyncio.create_task(
        server.call_tool("inspect_static", {"path": str(tmp_path / "fixture")})
    )
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        request.cancel()
        assert await asyncio.to_thread(cancelled.wait, 5)
        await asyncio.sleep(0.02)
        assert not request.done(), "Cancellation abandoned the owned worker"
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await request


def test_capture_limits_and_read_failure_close_descriptor(tmp_path, monkeypatch):
    import os

    from toolkit.lowrea import files

    path = tmp_path / "oversized.bin"
    with path.open("wb") as stream:
        stream.truncate(files.MAX_INSPECTION_BYTES + 1)
    with pytest.raises(ValueError, match="25 MiB"):
        files.inspect_path(path, LowreaOptions())
    path.write_bytes(b"ordinary artifact")
    captured = []
    original_open = os.open

    def track_open(*args, **kwargs):
        descriptor = original_open(*args, **kwargs)
        captured.append(descriptor)
        return descriptor

    def fail_stream(*args, **kwargs):
        raise OSError("fixture stream failure")

    monkeypatch.setattr(files.os, "open", track_open)
    monkeypatch.setattr(files.os, "fdopen", fail_stream)
    with pytest.raises(OSError, match="stream failure"):
        files.inspect_path(path, LowreaOptions())
    with pytest.raises(OSError):
        os.fstat(captured[-1])
