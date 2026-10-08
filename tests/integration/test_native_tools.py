"""Real native prerequisites against owned local fixtures; no public targets."""

import asyncio
from threading import Event
from uuid import uuid4

import pytest

from backend.events import EventHub
from backend.jobs import JobContext
from backend.platform_utils import find_nmap_binary
from backend.services.async_scanner import scan
from shared.tools import ScannerOptions
from toolkit.modules.file_type import identify_bytes, readiness
from toolkit.task_context import TaskContext


@pytest.mark.integration
async def test_native_connect_scan_finds_owned_loopback_listener() -> None:
    pytest.importorskip("nmap")
    if find_nmap_binary() is None:
        pytest.skip("Native Nmap is not installed; setup readiness is tested separately.")

    async def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()
        await writer.wait_closed()

    server = None
    for port in (8080, 8443, 5900):
        try:
            server = await asyncio.start_server(accept, "127.0.0.1", port)
            break
        except OSError:
            continue
    if server is None:
        pytest.skip("The three local fixture ports are in use.")
    hub = EventHub()
    context = JobContext(Event(), hub, uuid4(), uuid4())
    try:
        async with server:
            result = await scan(ScannerOptions(target="127.0.0.1/32", authorized=True), context)
            assert isinstance(result, list) and len(result) == 1
            assert result[0]["ip"] == "127.0.0.1"
            assert result[0]["status"] == "Responded"
            assert any(value.startswith(f"{port}/tcp") for value in result[0]["open_ports"])
    finally:
        await hub.close()


@pytest.mark.integration
async def test_native_magic_identifies_renamed_upload_in_its_worker() -> None:
    reason = readiness()
    if reason:
        pytest.skip(reason)
    hub = EventHub()
    context = JobContext(Event(), hub, uuid4(), uuid4())
    # The signature lies about its suffix; bytes after the sample must not be read by libmagic.
    content = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n" + b" " * (2 * 1024 * 1024)
    try:
        report = await context.run_sync(
            lambda: identify_bytes(content, "renamed.png", TaskContext(context.cancel_event))
        )
        assert report.mime == "application/pdf"
        assert "PDF" in report.description
        assert report.extension_status == "Mismatch"
        assert report.sample_bytes == 1024 * 1024
    finally:
        await hub.close()
