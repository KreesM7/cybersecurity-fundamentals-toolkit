"""Wire contract and real independently installed capture subprocess tests."""

import asyncio
import json
import os
import struct
import sys
from threading import Event
from uuid import uuid4

import pytest

from backend.events import EventHub
from backend.jobs import JobContext


@pytest.fixture(autouse=True)
def independent_ci_worker(monkeypatch):
    """CI uses a separate native interpreter; real Windows WSL tests use the default host."""
    executable = os.environ.get("TOOLKIT_TEST_WORKER")
    if executable:
        from backend.services import traffic_worker

        monkeypatch.setattr(traffic_worker, "is_windows", lambda: False)

        def argv(arguments):
            # Native Windows CI tests stdio framing and owned-process termination.
            # Unix control sockets belong to the production Linux/WSL host and
            # are exercised by Linux CI and the separate Windows WSL lab tests.
            if sys.platform == "win32" and arguments[:1] == ["--control-token"]:
                arguments = arguments[2:]
            return [executable, "-m", "toolkit_scapy_worker", *arguments]

        monkeypatch.setattr(
            traffic_worker,
            "capture_worker_argv",
            argv,
        )


def packet(protocol=6, ipv6=False):
    ethernet = b"\0" * 12 + (b"\x86\xdd" if ipv6 else b"\x08\x00")
    if ipv6:
        return (
            ethernet
            + struct.pack("!IHBB", 6 << 28, 8, protocol, 64)
            + bytes.fromhex("20010db8000000000000000000000001" "20010db8000000000000000000000002")
            + b"\0" * 8
        )
    return (
        ethernet
        + struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            28,
            0,
            0,
            64,
            protocol,
            0,
            b"\xc0\xa8\x01\x0a",
            b"\xc0\xa8\x01\x0b",
        )
        + b"\0" * 8
    )


def pcap(records=None, endian="<", nano=False):
    records = records or [(2, packet()), (1, packet(17))]
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    result = [struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1)]
    for seconds, payload in records:
        result.append(
            struct.pack(
                endian + "IIII",
                seconds,
                125000000 if nano else 125000,
                len(payload),
                len(payload) + 4,
            )
            + payload
        )
    return b"".join(result)


def block(kind, body, endian="<"):
    body += b"\0" * (-len(body) % 4)
    size = len(body) + 12
    return struct.pack(endian + "II", kind, size) + body + struct.pack(endian + "I", size)


def pcapng(endian="<"):
    section = block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535), endian)
    payload = packet(1)
    record = block(
        6, struct.pack(endian + "IIIII", 0, 0, 2125000, len(payload), 60) + payload, endian
    )
    return section + interface + record


def context():
    return JobContext(Event(), EventHub(), uuid4(), uuid4())


def test_strict_wire_retains_prior_packet_and_sanitizes_error():
    from shared.capture import CaptureProtocol

    parser = CaptureProtocol()
    for row in [
        {"v": 1, "type": "meta", "unit": "packets"},
        {
            "v": 1,
            "type": "packet",
            "index": 1,
            "timestamp": 2.125,
            "source_ip": "192.168.1.10",
            "bytes": 60,
            "protocol": "TCP",
        },
        {
            "v": 1,
            "type": "error",
            "code": "MALFORMED_CAPTURE",
            "message": "secret payload",
            "index": 2,
            "fatal": True,
        },
        {
            "v": 1,
            "type": "end",
            "emitted": 1,
            "ignored_non_ip": 0,
            "malformed": 1,
            "complete": False,
        },
    ]:
        parser.feed(json.dumps(row).encode() + b"\n")
    data = parser.finish(2)
    assert len(data.events) == 1 and not data.complete
    assert "secret" not in str(data.warnings)


@pytest.mark.parametrize("mutation", ["version", "count", "exit", "eof", "line", "order"])
def test_wire_corruption_never_succeeds(mutation):
    from shared.capture import CaptureProtocol

    parser = CaptureProtocol()
    meta = {"v": 2 if mutation == "version" else 1, "type": "meta", "unit": "packets"}
    rows = [
        meta,
        {
            "v": 1,
            "type": "end",
            "emitted": 1 if mutation == "count" else 0,
            "ignored_non_ip": 0,
            "malformed": 0,
            "complete": True,
        },
    ]
    if mutation == "eof":
        rows.pop()
    if mutation == "order":
        rows.reverse()
    try:
        for row in rows:
            parser.feed(json.dumps(row).encode() + b"\n")
        if mutation == "line":
            parser.feed(b"x" * 65537 + b"\n")
    except ValueError:
        pass
    assert not parser.finish(1 if mutation == "exit" else 0).complete


@pytest.mark.integration
@pytest.mark.parametrize("content", [pcap(), pcap(endian=">", nano=True), pcapng(), pcapng(">")])
async def test_independent_capture_worker(content):
    from backend.services.traffic_worker import read_capture

    data = await read_capture(content, context())
    assert data.complete and data.events and data.unit == "packets"
    assert data.events[0].source_ip == "192.168.1.10"
    assert "scapy" not in sys.modules


@pytest.mark.integration
async def test_truncated_second_record_preserves_first():
    from backend.services.traffic_worker import read_capture

    data = await read_capture(pcap()[:-3], context())
    assert len(data.events) == 1 and not data.complete


@pytest.mark.integration
@pytest.mark.parametrize(
    "content,filename,complete",
    [
        (pcap(), "fixture.pcap", True),
        (pcapng(), "fixture.pcapng", True),
        (pcap()[:-3], "truncated.pcap", False),
    ],
    ids=["pcap", "pcapng", "partial"],
)
async def test_capture_tool_both_detectors_and_cancellation(content, filename, complete):
    from backend.services.tool_service import ToolService
    from backend.services.traffic_worker import read_capture
    from shared.tools import AnomalyOptions, DoSOptions

    service = object.__new__(ToolService)
    for options in (DoSOptions(), AnomalyOptions()):
        result = await service.analyze(options.kind, options, content, filename, context())
        assert result["complete"] is complete
        assert result["events"] == (2 if filename == "fixture.pcap" else 1)
    cancelled = context()
    cancelled.cancel_event.set()
    with pytest.raises(asyncio.CancelledError):
        await read_capture(pcap(), cancelled)


@pytest.mark.integration
async def test_real_running_worker_cancellation_and_deadline():
    from backend.services.traffic_worker import read_capture

    content = pcap([(2, packet())] * 100000)
    task = asyncio.create_task(read_capture(content, context()))
    await asyncio.sleep(0.25)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 15)
    with pytest.raises(ValueError, match="incomplete"):
        await read_capture(content, context(), timeout=0.05)


@pytest.mark.integration
async def test_worker_non_ip_gaps_protocols_and_impossible_lengths():
    from backend.services.traffic_worker import read_capture

    content = pcap(
        [(5, packet()), (4, b"\0" * 14), (3, packet(1)), (2, packet(17)), (1, packet(58, True))]
    )
    data = await read_capture(content, context())
    assert data.complete and len(data.events) == 4
    assert [row.protocol for row in data.events] == ["IP-58", "UDP", "ICMP", "TCP"]
    assert data.events[0].source_ip == "2001:db8::1"
    corrupted = pcap([(2, packet())]) + struct.pack("<IIII", 3, 0, 0xFFFFFFFF, 0xFFFFFFFF)
    data = await read_capture(corrupted, context())
    assert len(data.events) == 1 and not data.complete


async def test_missing_worker_keeps_text_tools_ready(monkeypatch):
    from backend.services import traffic_worker
    from backend.services.tool_service import ToolService

    def missing(_args):
        raise ValueError("worker absent")

    monkeypatch.setattr(traffic_worker, "capture_worker_argv", missing)
    assert "CSV/log ready" in await traffic_worker.readiness()
    service = ToolService(None, None)
    rows = await service.list()
    assert all(row.available for row in rows if row.id in {"dos-detector", "anomaly-detector"})


def test_main_packaging_excludes_worker_and_scapy():
    import importlib.util
    import tomllib
    from pathlib import Path

    from setuptools import find_packages

    root = Path(__file__).resolve().parents[2]
    config = tomllib.loads((root / "pyproject.toml").read_text())
    includes = config["tool"]["setuptools"]["packages"]["find"]["include"]
    inventory = find_packages(root, include=includes)
    assert not any("worker" in name or "scapy" in name for name in inventory)
    assert not any(
        "scapy" in requirement.lower() for requirement in config["project"]["dependencies"]
    )
    assert "scapy" not in sys.modules
    if sys.platform.startswith("linux"):
        assert importlib.util.find_spec("scapy") is None


@pytest.mark.integration
async def test_pcapng_interfaces_resolution_sections_and_bad_block():
    from backend.services.traffic_worker import read_capture

    def section(endian):
        return block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)

    def interface(endian, resolution):
        options = struct.pack(endian + "HH", 9, 1) + bytes([resolution]) + b"\0" * 3
        options += struct.pack(endian + "HHqHH", 14, 8, 3, 0, 0)
        return block(1, struct.pack(endian + "HHI", 1, 0, 65535) + options, endian)

    def event(endian, index, ticks):
        payload = packet(17)
        return block(
            6, struct.pack(endian + "IIIII", index, 0, ticks, len(payload), 60) + payload, endian
        )

    content = (
        section("<")
        + interface("<", 9)
        + interface("<", 0x8A)
        + event("<", 1, 1024)
        + event("<", 0, 125000000)
        + section(">")
        + interface(">", 6)
        + event(">", 0, 1000000)
    )
    data = await read_capture(content, context())
    assert data.complete and [event.timestamp for event in data.events] == [3.125, 4.0, 4.0]
    for trailing in (
        struct.pack(">II", 6, 0xFFFFFFFC) + b"\0" * 4,
        event(">", 10, 1000000),
        event(">", 0, 1000000)[:-1],
    ):
        data = await read_capture(content + trailing, context())
        assert len(data.events) == 3 and not data.complete


@pytest.mark.parametrize(
    "tail", [b"x" * 65537 + b"\n", b'{"v":1', b""], ids=["overlong", "truncated", "eof"]
)
async def test_real_bad_worker_stream_retains_prior_records(tmp_path, monkeypatch, tail):
    from backend.services import traffic_worker

    rows = [
        {"v": 1, "type": "meta", "unit": "packets"},
        {
            "v": 1,
            "type": "packet",
            "index": 1,
            "timestamp": 1.0,
            "source_ip": "192.168.1.10",
            "bytes": 60,
            "protocol": "TCP",
        },
    ]
    wire = b"".join(json.dumps(row).encode() + b"\n" for row in rows) + tail
    script = tmp_path / "fake_worker.py"
    script.write_text(
        "import sys\nsys.stdin.buffer.read()\nsys.stdout.buffer.write(" + repr(wire) + ")\n"
    )
    monkeypatch.setattr(
        traffic_worker, "capture_worker_argv", lambda _: [sys.executable, str(script)]
    )
    monkeypatch.setattr(traffic_worker, "is_windows", lambda: False)
    data = await traffic_worker.read_capture(b"fixture", context())
    assert len(data.events) == 1 and not data.complete


async def test_input_byte_limit_before_spawn():
    from backend.services.traffic_worker import read_capture

    with pytest.raises(ValueError, match="25 MiB"):
        await read_capture(b"\0" * (25 * 1024 * 1024 + 1), context())


async def test_cancellation_during_spawn_reaps_owned_process(tmp_path, monkeypatch):
    from backend.services import traffic_worker

    script = tmp_path / "waiting_worker.py"
    script.write_text("import sys,time\nsys.stdin.buffer.read()\ntime.sleep(10)\n")
    monkeypatch.setattr(
        traffic_worker, "capture_worker_argv", lambda _: [sys.executable, str(script)]
    )
    monkeypatch.setattr(traffic_worker, "is_windows", lambda: False)
    original = asyncio.create_subprocess_exec
    owned = []
    spawned = asyncio.Event()

    async def delayed(*args, **kwargs):
        child = await original(*args, **kwargs)
        owned.append(child)
        spawned.set()
        await asyncio.sleep(0.1)
        return child

    monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed)
    task = asyncio.create_task(traffic_worker.read_capture(b"fixture", context()))
    await spawned.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5)
    assert owned[0].returncode is not None
