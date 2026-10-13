"""Own a native script(1) PTY without Python forkpty in a multithreaded GUI.

The host's script executable owns the inner controlling terminal. Transcripts
go to /dev/null. Popen uses no Python preexec callback; only literal arguments
are quoted for script's documented command option.
"""

import os
import shlex
import signal
import struct
import subprocess
import sys
from pathlib import Path


class PosixPTY:
    fd: int
    closed: bool
    pid: int
    process: subprocess.Popen[bytes]

    def __init__(self, argv: list[str], directory: Path, environment: dict[str, str]) -> None:
        if sys.platform == "win32":
            raise ValueError("POSIX terminal helper is not supported on Windows")
        import pty

        script = Path("/usr/bin/script")
        if not script.is_file():
            raise ValueError("POSIX terminal helper missing; install the OS script utility")
        master, slave = pty.openpty()
        self.fd = master
        self.closed = False
        command = (
            [str(script), "-q", "-F", "/dev/null", *argv]
            if sys.platform == "darwin"
            else [str(script), "-q", "-f", "-c", shlex.join(argv), "/dev/null"]
        )
        try:
            self.process = subprocess.Popen(
                command,
                stdin=slave,
                stdout=slave,
                stderr=slave,
                cwd=directory,
                env=dict(environment, TERM="xterm", SHELL="/bin/sh"),
                start_new_session=True,
                close_fds=True,
            )
        except BaseException:
            os.close(master)
            raise
        finally:
            os.close(slave)
        self.pid = self.process.pid
        self.setwinsize(24, 80)

    def isalive(self) -> bool:
        return not self.closed and self.process.poll() is None

    def write(self, data: bytes) -> int:
        return os.write(self.fd, data)

    def setwinsize(self, rows: int, columns: int) -> None:
        if sys.platform == "win32":
            raise ValueError("POSIX terminal helper is not supported on Windows")
        import fcntl
        import termios

        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
        if self.isalive():
            try:
                os.kill(self.pid, signal.SIGWINCH)
            except ProcessLookupError:
                pass

    def close(self, force: bool = False) -> None:
        if self.closed:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process.wait()
        os.close(self.fd)
        self.closed = True
