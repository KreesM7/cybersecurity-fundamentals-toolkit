"""Raw binary framing fixtures; deliberately independent of the desktop package."""

import io
import json
import os
import struct
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

import pytest

PYTHON = "/opt/toolkit-scapy/bin/python"


def command(*args):
    argv = [PYTHON, *args]
    return (
        ["wsl.exe", "--distribution", "Toolkit-MSF", "--exec", *argv]
        if sys.platform == "win32"
        else argv
    )


def decode(source, output, max_records=250000):
    script = (
        "import io,sys; from toolkit_scapy_worker.capture import decode; "
        f"sys.exit(decode(io.BytesIO(sys.stdin.buffer.read()), sys.stdout, {max_records}))"
    )
    reply = subprocess.run(
        command("-c", script), input=source.read(), capture_output=True, timeout=10
    )
    output.write(reply.stdout.decode())
    assert not reply.stderr
    return reply.returncode


def capture(truncated=False, huge=False):
    payload = (
        b"\0" * 12
        + b"\x08\x00"
        + struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, 17, 0, b"\xc0\xa8\x01\x0a", b"\xc0\xa8\x01\x0b"
        )
        + b"\0" * 8
    )
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    data += struct.pack("<IIII", 2, 125000, len(payload), 60) + payload
    if huge:
        data += struct.pack("<IIII", 3, 0, 0xFFFFFFFF, 0xFFFFFFFF)
    elif truncated:
        data += b"\0" * 3
    return data


@pytest.mark.parametrize("truncated,huge", [(False, False), (True, False), (False, True)])
def test_stream_preserves_valid_record(truncated, huge):
    output = io.StringIO()
    status = decode(io.BytesIO(capture(truncated, huge)), output)
    rows = [json.loads(line) for line in output.getvalue().splitlines()]
    assert rows[0] == {"v": 1, "type": "meta", "unit": "packets"}
    assert rows[1]["source_ip"] == "192.168.1.10"
    assert rows[1]["bytes"] == 60
    assert rows[-1]["type"] == "end" and rows[-1]["emitted"] == 1
    assert rows[-1]["complete"] == (not truncated and not huge)
    assert status == (2 if truncated or huge else 0)


def test_total_records_limit_blocks_non_ip_bypass():
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    data += (struct.pack("<IIII", 1, 0, 14, 14) + b"\0" * 14) * 3
    output = io.StringIO()
    assert decode(io.BytesIO(data), output, max_records=2) == 2
    rows = [json.loads(line) for line in output.getvalue().splitlines()]
    assert rows[-1]["ignored_non_ip"] == 2 and rows[-2]["code"] == "INPUT_LIMIT"


def test_truncated_ip_header_is_invalid_not_non_ip():
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    payload = b"\0" * 12 + b"\x08\x00" + b"\x45\0"
    data += struct.pack("<IIII", 1, 0, len(payload), 60) + payload
    output = io.StringIO()
    assert decode(io.BytesIO(data), output) == 2
    rows = [json.loads(line) for line in output.getvalue().splitlines()]
    assert rows[1]["code"] == "INVALID_PACKET"
    assert rows[-1]["ignored_non_ip"] == 0 and rows[-1]["malformed"] == 1


def test_non_ip_record_gaps_and_event_ceiling():
    original = capture()
    packet_record = original[24:]
    non_ip = struct.pack("<IIII", 1, 0, 14, 14) + b"\0" * 14
    output = io.StringIO()
    assert (
        decode(io.BytesIO(original[:24] + non_ip + packet_record + packet_record), output, 2) == 2
    )
    rows = [json.loads(line) for line in output.getvalue().splitlines()]
    assert rows[1]["type"] == "packet" and rows[1]["index"] == 2
    assert rows[-1]["ignored_non_ip"] == 1 and rows[-1]["emitted"] == 1


def test_independent_cli_stdin_path_equivalence(tmp_path):
    if sys.platform == "win32":
        pytest.skip("Literal Linux path and temporary mode inspection run in dedicated Linux tests")
    path = tmp_path / "fixture.pcap"
    path.write_bytes(capture())
    upload = subprocess.run(
        command("-m", "toolkit_scapy_worker"), input=capture(), capture_output=True
    )
    literal = subprocess.run(command("-m", "toolkit_scapy_worker", str(path)), capture_output=True)
    assert upload.returncode == literal.returncode == 0
    assert upload.stdout == literal.stdout and not upload.stderr and not literal.stderr


def test_missing_scapy_produces_readable_safe_wire():
    reply = subprocess.run(
        command(
            "-S",
            "-c",
            "import runpy,sys; sys.path.insert(0,"
            "'/opt/toolkit-scapy/lib/python3.12/site-packages'); "
            "sys.meta_path.insert(0,type('Block',(),{'find_spec':lambda s,n,*a:"
            "(_ for _ in ()).throw(ImportError()) if n.startswith('scapy') else None})()); "
            "runpy.run_module('toolkit_scapy_worker',run_name='__main__')",
        ),
        input=capture(),
        capture_output=True,
    )
    rows = [json.loads(line) for line in reply.stdout.splitlines()]
    assert reply.returncode == 1 and rows[1]["code"] == "MISSING_DEPENDENCY"
    assert not reply.stderr and rows[-1]["complete"] is False


def test_control_cancellation_cleans_private_spool(tmp_path):
    if sys.platform == "win32":
        pytest.skip("Mode and Linux-owned process inspection run in dedicated Linux tests")
    token = uuid4().hex
    environment = dict(os.environ, TMPDIR=str(tmp_path))
    process = subprocess.Popen(
        command("-m", "toolkit_scapy_worker", "--control-token", token),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            paths = list(tmp_path.glob("toolkit-scapy-*/input"))
            if paths:
                break
            time.sleep(0.02)
        assert paths
        assert paths[0].stat().st_mode & 0o777 == 0o600
        assert paths[0].parent.stat().st_mode & 0o777 == 0o700
        cancel = subprocess.run(
            command("-m", "toolkit_scapy_worker", "--cancel-token", token),
            capture_output=True,
            timeout=7,
        )
        assert cancel.returncode == 0
        assert process.wait(timeout=5) == 130
        assert not list(tmp_path.iterdir())
        assert not Path(f"/tmp/toolkit-scapy-{token}.sock").exists()
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream:
                stream.close()
