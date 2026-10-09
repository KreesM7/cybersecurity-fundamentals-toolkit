"""Independent Linux PTY supervisor, private control socket and bounded JSONL proxy."""

from __future__ import annotations

import argparse
import json
import os
import queue
import re
import signal
import socket
import stat
import sys
import threading
import time
import tty
from pathlib import Path

LIMIT = 4 * 1024 * 1024


def control_path(token: str) -> Path:
    if not re.fullmatch(r"[a-f0-9]{32}", token):
        raise ValueError("Invalid control token")
    root = Path(f"/tmp/toolkit-msf-{os.getuid()}")
    if root.is_symlink():
        raise ValueError("Invalid control directory")
    root.mkdir(mode=0o700, exist_ok=True)
    info = root.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Control directory must be private")
    return root / (token + ".sock")


def emit(value: object) -> None:
    encoded = json.dumps(value, ensure_ascii=True, allow_nan=False)
    if len(encoded) > LIMIT:
        raise ValueError("Output limit")
    print(encoded, flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token", required=True)
    parser.add_argument("--cancel", action="store_true")
    options = parser.parse_args()
    path = control_path(options.token)
    if options.cancel:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(str(path))
            client.sendall(b"stop")
        return 0
    import pexpect  # type: ignore[import-untyped]  # Independent pinned library has no bundled stubs.

    directory = Path(__file__).resolve().parent
    executable = next(
        (
            path
            for path in (
                Path("/opt/metasploit-framework/bin/msfconsole"),
                Path("/usr/bin/msfconsole"),
            )
            if path.is_file()
        ),
        None,
    )
    if executable is None:
        raise ValueError("Metasploit is not installed")
    stop = threading.Event()
    requests: queue.Queue[bytes | None] = queue.Queue(maxsize=32)

    def interrupted(number: int, frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    environment = dict(os.environ)
    environment["TOOLKIT_BRIDGE_FILE"] = str(directory / "toolkit_bridge.rb")
    environment["TOOLKIT_BRIDGE_NONCE"] = options.token
    child = pexpect.spawn(
        str(executable),
        ["-q", "-n", "-r", str(directory / "toolkit_bridge.rc")],
        env=environment,
        echo=False,
        encoding=None,
        timeout=1,
        maxread=65536,
    )
    tty.setraw(child.child_fd)
    prefix = f"TOOLKIT/{options.token}/".encode()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    buffer = bytearray()
    bound = False

    def inputs() -> None:
        try:
            while not stop.is_set():
                line = sys.stdin.buffer.readline(1024 * 1024 + 1)
                if not line or not line.endswith(b"\n") or len(line) > 1024 * 1024:
                    break
                while not stop.is_set():
                    try:
                        requests.put(line, timeout=0.2)
                        break
                    except queue.Full:
                        continue
        finally:
            stop.set()

    def control() -> None:
        while not stop.is_set():
            try:
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(1)
                    if connection.recv(5) == b"stop":
                        os.kill(os.getpid(), signal.SIGTERM)
                        return
            except (OSError, TimeoutError):
                continue

    def reply(timeout: float) -> None:
        deadline = time.monotonic() + timeout
        observed = 0
        while time.monotonic() < deadline and not stop.is_set():
            try:
                buffer.extend(child.read_nonblocking(65536, timeout=0.2))
            except pexpect.TIMEOUT:
                continue
            if len(buffer) > LIMIT:
                raise ValueError("PTY output limit")
            while b"\n" in buffer:
                line, _, rest = buffer.partition(b"\n")
                buffer[:] = rest
                line = line.rstrip(b"\r")
                observed += len(line)
                if observed > LIMIT:
                    raise ValueError("PTY output limit")
                if line.startswith(prefix):
                    value = json.loads(line[len(prefix) :])
                    emit(value)
                    return
                if line:
                    emit(
                        {
                            "v": 1,
                            "type": "output",
                            "text": line.decode("utf-8", errors="replace")[:10000],
                        }
                    )
        raise TimeoutError("PTY reply timeout")

    try:
        server.bind(str(path))
        bound = True
        path.chmod(0o600)
        server.listen(1)
        server.settimeout(0.2)
        threading.Thread(target=control, daemon=True).start()
        # Initial banner lines are output frames; the desktop waits for the ready frame.
        reply(60)
        threading.Thread(target=inputs, daemon=True).start()
        while not stop.is_set():
            try:
                request = requests.get(timeout=0.2)
            except queue.Empty:
                continue
            if request is None:
                break
            child.send(request)
            reply(18)
        return 0
    finally:
        stop.set()
        server.close()
        if bound:
            path.unlink(missing_ok=True)
        child.close(force=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except Exception:
        print(
            "PTY host failed. Check the dedicated installation and bridge compatibility.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
