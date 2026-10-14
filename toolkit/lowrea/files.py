"""Regular-file capture shared by CLI and MCP; parser inputs are immutable bytes."""

import os
import stat
from pathlib import Path

from shared.lowrea import LowreaOptions
from toolkit.lowrea.domain import Evidence
from toolkit.lowrea.static import inspect_bytes
from toolkit.task_context import TaskContext

MAX_INSPECTION_BYTES = 25 * 1024 * 1024


def inspect_path(path: Path, options: LowreaOptions, task: TaskContext | None = None) -> Evidence:
    task = task or TaskContext()
    task.check()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Supply a readable regular file.")
        if before.st_size > MAX_INSPECTION_BYTES:
            raise ValueError(
                "Static inspection memory limit is 25 MiB; "
                "use inventory-artifact for streaming identity of larger files."
            )
        parts = []
        remaining = before.st_size
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while remaining:
                task.check()
                chunk = stream.read(min(remaining, 65536))
                if not chunk:
                    raise ValueError("Artifact changed while capturing bytes.")
                parts.append(chunk)
                remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_ino) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_ino,
        ):
            raise ValueError("Artifact changed while capturing bytes.")
        return inspect_bytes(b"".join(parts), options, path.name, task)
    finally:
        os.close(descriptor)
