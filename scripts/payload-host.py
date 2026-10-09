"""Independent bounded msfvenom supervisor. One JSON input line; EOF cancels ownership."""

from __future__ import annotations

import base64
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import threading
import time
from ipaddress import ip_address


def emit(value: object) -> None:
    print(json.dumps(value, ensure_ascii=True), flush=True)


def arguments(data: dict[str, object]) -> list[str]:
    if set(data) != {"payload", "format", "encoder", "iterations", "lhost", "lport"}:
        raise ValueError("Invalid generation fields")
    for field in ("payload", "encoder"):
        value = data[field]
        if (
            not isinstance(value, str)
            or len(value) > 190
            or (value and not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", value))
        ):
            raise ValueError("Invalid module")
    if not data["payload"] or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", str(data["format"])):
        raise ValueError("Invalid format")
    host = ip_address(str(data["lhost"]))
    if host.is_unspecified or host.is_multicast or "%" in str(data["lhost"]):
        raise ValueError("Invalid listener")
    if type(data["lport"]) is not int or not 1 <= data["lport"] <= 65535:
        raise ValueError("Invalid port")
    if type(data["iterations"]) is not int or not 1 <= data["iterations"] <= 10:
        raise ValueError("Invalid iterations")
    argv = [
        "/opt/metasploit-framework/bin/msfvenom",
        "-p",
        str(data["payload"]),
        "-f",
        str(data["format"]),
        "-i",
        str(data["iterations"]),
        "LHOST=" + str(host),
        "LPORT=" + str(data["lport"]),
    ]
    if data["encoder"]:
        argv.extend(["-e", str(data["encoder"])])
    return argv


def main() -> int:
    line = sys.stdin.buffer.readline(8193)
    if len(line) > 8192 or not line.endswith(b"\n"):
        raise ValueError("Invalid request")
    argv = arguments(json.loads(line))
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())

    def monitor() -> None:
        # Parent holds stdin open while it owns this task; close cancels even through WSL.
        os.read(sys.stdin.fileno(), 1)
        stopped.set()

    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("RUBY", "GEM_", "BUNDLE_"))
    }
    child = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env=environment,
    )
    threading.Thread(target=monitor, daemon=True).start()
    selector = selectors.DefaultSelector()
    assert child.stdout is not None and child.stderr is not None
    selector.register(child.stdout, selectors.EVENT_READ, "data")
    selector.register(child.stderr, selectors.EVENT_READ, "progress")
    deadline, size, diagnostics = time.monotonic() + 90, 0, 0
    try:
        while selector.get_map():
            if stopped.is_set() or time.monotonic() > deadline:
                raise InterruptedError("Generation cancelled or timed out")
            for key, _ in selector.select(0.2):
                chunk = os.read(key.fd, 32768)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "data":
                    size += len(chunk)
                    if size > 8 * 1024 * 1024:
                        raise ValueError("Artifact exceeds limit")
                    emit({"type": "data", "base64": base64.b64encode(chunk).decode("ascii")})
                else:
                    diagnostics += len(chunk)
                    if diagnostics > 65536:
                        raise ValueError("Diagnostic output exceeds limit")
                    emit(
                        {
                            "type": "progress",
                            "message": chunk.decode("utf-8", errors="replace")[:4096],
                        }
                    )
        code = child.wait(timeout=2)
        emit({"type": "end", "ok": code == 0 and size > 0})
        return 0 if code == 0 and size else 1
    finally:
        selector.close()
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
        child.stdout.close()
        child.stderr.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print(
            "Payload generator failed or was cancelled. Check the dedicated installation.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
