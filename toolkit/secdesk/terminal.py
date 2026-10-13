"""Real ConPTY/POSIX terminals with explicit ownership and bounded operations.

Callers serialize operations off the GUI/event loop. This module never chooses
a command or authorizes a tool: the service validates the manifest and consent.
"""

from __future__ import annotations

import codecs
import importlib
import os
import select
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import psutil


class NativeTerminal:
    def __init__(self, argv: list[str], directory: Path, *, extra_path: Path | None = None) -> None:
        try:
            self._psutil = importlib.import_module("psutil")
        except ImportError as error:
            raise ValueError(
                "Native process runtime missing; reinstall locked dependencies"
            ) from error
        if not argv or any("\0" in value for value in argv) or not directory.is_dir():
            raise ValueError("Valid arguments and working directory are required")
        allowed = {
            "PATH",
            "SystemRoot",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "TEMP",
            "TMP",
            "HOME",
            "USER",
            "LOGNAME",
            "LANG",
            "LC_ALL",
            "TERM",
            "PATHEXT",
        }
        environment = {key: value for key, value in os.environ.items() if key in allowed}
        if extra_path is not None:
            environment["PATH"] = str(extra_path) + os.pathsep + environment.get("PATH", "")
        environment.update(HISTFILE=os.devnull, HISTSIZE="0", HISTFILESIZE="0")
        self.closed = False
        self._decoder = codecs.getincrementaldecoder("utf8")("replace")
        self._pty: Any
        if os.name == "nt":
            try:
                module = importlib.import_module("winpty")
            except ImportError as error:
                raise ValueError("Windows terminal runtime missing; reinstall pywinpty") from error
            self._pty = module.PTY(80, 24, backend=module.Backend.ConPTY)
            spawned = self._pty.spawn(
                argv[0],
                cmdline=" " + subprocess.list2cmdline(argv[1:]),
                cwd=str(directory),
                env="\0".join(f"{key}={value}" for key, value in environment.items()) + "\0",
            )
            if not spawned:
                self._pty.cancel_io()
                raise ValueError("Native terminal process did not start")
        else:
            from toolkit.secdesk.posix_terminal import PosixPTY

            self._pty = PosixPTY(argv, directory, environment)
        if type(self._pty.pid) is not int or self._pty.pid <= 0 or self._pty.pid == os.getpid():
            raise ValueError("Invalid native process ownership")
        self._owner: psutil.Process | None = None
        self._created = 0.0
        try:
            self._owner = self._psutil.Process(self._pty.pid)
            self._created = self._owner.create_time()
        except self._psutil.NoSuchProcess:
            self._owner = None

    def alive(self) -> bool:
        return not self.closed and bool(self._pty.isalive())

    def read(self) -> str:
        if self.closed:
            return ""
        try:
            if os.name == "nt":
                text = str(self._pty.read(False))
            else:
                if not select.select([self._pty.fd], [], [], 0)[0]:
                    return ""
                text = self._decoder.decode(os.read(self._pty.fd, 65536))
        except Exception:
            if not self.alive():
                return ""
            raise
        if len(text) > 65536:
            raise ValueError("Terminal output exceeded the per-read limit")
        return text

    def write(self, text: str) -> None:
        if not self.alive() or len(text) > 4096 or "\0" in text:
            raise ValueError("Terminal closed or input exceeds limit")
        encoded = text.encode("utf8")
        written = self._pty.write(text if os.name == "nt" else encoded)
        # ConPTY 3.0.5 returns zero on successful writes, not a byte count.
        # Its failures raise WinptyError; POSIX exposes partial byte counts.
        if os.name != "nt" and written != len(encoded):
            raise ValueError("Incomplete terminal write; outcome unknown and not repeated")

    def resize(self, rows: int, columns: int) -> None:
        if not 2 <= rows <= 60 or not 10 <= columns <= 200:
            raise ValueError("Terminal dimensions exceed supported range")
        if self.alive():
            if os.name == "nt":
                self._pty.set_size(columns, rows)
            else:
                self._pty.setwinsize(rows, columns)

    def _live(self, processes: list[psutil.Process]) -> list[psutil.Process]:
        result = []
        for process in processes:
            try:
                if process.is_running() and process.status() != self._psutil.STATUS_ZOMBIE:
                    result.append(process)
            except self._psutil.NoSuchProcess:
                pass
        return result

    def close(self) -> None:
        if self.closed:
            return
        try:
            # Hold Process objects (including creation time), not unverified PID values.
            # Only this terminal's owned process tree is signalled.
            if (
                self._owner
                and self._owner.is_running()
                and self._owner.create_time() == self._created
            ):
                processes = self._owner.children(recursive=True) + [self._owner]
                for process in reversed(processes):
                    try:
                        process.terminate()
                    except self._psutil.NoSuchProcess:
                        pass
                if os.name != "nt":
                    self._pty.close(force=True)
                    processes = processes[:-1]
                _, alive = self._psutil.wait_procs(processes, timeout=2)
                # An exited child can remain a zombie under a container's PID 1.
                # Only its parent/init can reap it; it has no live handles or code.
                alive = self._live(alive)
                for process in alive:
                    try:
                        process.kill()
                    except self._psutil.NoSuchProcess:
                        pass
                _, alive = self._psutil.wait_procs(alive, timeout=2)
                if self._live(alive):
                    raise RuntimeError("Owned terminal processes did not exit")
        except self._psutil.NoSuchProcess:
            pass
        if os.name == "nt":
            self._pty.cancel_io()
            self._pty = None
        else:
            self._pty.close(force=True)
        self.closed = True
