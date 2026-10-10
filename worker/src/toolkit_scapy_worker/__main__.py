"""Literal-path/stdin command, private transient spool and owned cancellation."""

from __future__ import annotations

import argparse
import importlib
import os
import re
import signal
import socket
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from types import FrameType

from toolkit_scapy_worker.capture import (
    MAX_BYTES,
    InputLimitError,
    WorkerCancelledError,
    decode,
    emit,
)


def _socket_path(token: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        raise ValueError("Invalid control token")
    return f"/tmp/toolkit-scapy-{token}.sock"


def cancel(token: str) -> int:
    path = _socket_path(token)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(0.2)
            try:
                client.connect(path)
                client.sendall(b"cancel")
                return 0
            except OSError:
                time.sleep(0.05)
    return 1


@contextmanager
def control(token: str | None) -> Iterator[None]:
    if token is None:
        yield
        return
    path = _socket_path(token)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stop = threading.Event()
    try:
        server.bind(path)
        os.chmod(path, 0o600)
        server.listen(1)
        server.settimeout(0.1)

        def listen() -> None:
            while not stop.is_set():
                try:
                    client, _ = server.accept()
                    with client:
                        client.settimeout(0.2)
                        if client.recv(7) == b"cancel":
                            os.kill(os.getpid(), signal.SIGTERM)
                            return
                except (OSError, TimeoutError):
                    continue

        thread = threading.Thread(target=listen, daemon=True)
        thread.start()
        try:
            yield
        finally:
            stop.set()
            thread.join(timeout=0.5)
    finally:
        server.close()
        Path(path).unlink(missing_ok=True)


def _cancel(_number: int, _frame: FrameType | None) -> None:
    raise WorkerCancelledError()


def _timeout(_number: int, _frame: FrameType | None) -> None:
    raise InputLimitError()


def main() -> int:
    # JSONL v1 requires UTF-8 and literal LF regardless of the host locale.
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    parser = argparse.ArgumentParser(description="Saved capture JSONL worker; no live capture")
    parser.add_argument("path", nargs="?")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--control-token")
    parser.add_argument("--cancel-token")
    args = parser.parse_args()
    if args.cancel_token:
        return cancel(args.cancel_token)
    if args.check:
        try:
            dependency = importlib.import_module("scapy")
            importlib.import_module("scapy.all")
            if dependency.__version__ != "2.8.0":
                return 1
        except ImportError:
            return 1
        print('{"worker":"toolkit-scapy-worker","version":"1.0.0","protocol":1,"scapy":"2.8.0"}')
        return 0
    signal.signal(signal.SIGTERM, _cancel)
    signal.signal(signal.SIGINT, _cancel)
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(60)
    # No library logs, exception text or capture contents may reach stderr.
    with open(os.devnull, "w") as quiet, suppress(BrokenPipeError):
        sys.stderr = quiet
        try:
            with control(args.control_token):
                if args.path:
                    with open(args.path, "rb") as source:
                        return decode(source, sys.stdout)
                with tempfile.TemporaryDirectory(prefix="toolkit-scapy-") as directory:
                    os.chmod(directory, 0o700)
                    path = Path(directory) / "input"
                    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, "wb") as destination:
                        used = 0
                        while chunk := sys.stdin.buffer.read(65536):
                            used += len(chunk)
                            if used > MAX_BYTES:
                                raise InputLimitError()
                            destination.write(chunk)
                    with path.open("rb") as source:
                        return decode(source, sys.stdout)
        except (OSError, InputLimitError, WorkerCancelledError) as exc:
            emit(sys.stdout, "meta", unit="packets")
            if not isinstance(exc, WorkerCancelledError):
                code = "INPUT_LIMIT" if isinstance(exc, InputLimitError) else "IO_ERROR"
                emit(
                    sys.stdout,
                    "error",
                    code=code,
                    message="Capture input unavailable",
                    index=1,
                    fatal=True,
                )
            emit(sys.stdout, "end", emitted=0, ignored_non_ip=0, malformed=0, complete=False)
            return (
                130
                if isinstance(exc, WorkerCancelledError)
                else (2 if isinstance(exc, InputLimitError) else 1)
            )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
