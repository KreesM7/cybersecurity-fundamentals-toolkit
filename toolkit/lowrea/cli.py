"""Static artifact identity boundary; target code is never executed."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import BinaryIO

from toolkit.lowrea.domain import Evidence


def read_identity(stream: BinaryIO, expected_size: int) -> tuple[str, str, int]:
    digest = hashlib.sha256()
    signature = b""
    size = 0
    while size < expected_size:
        chunk = stream.read(min(65536, expected_size - size))
        if not chunk:
            break
        if size == 0:
            signature = chunk[:16]
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), signature.hex(), size


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inventory = commands.add_parser(
        "inventory-artifact", help="Record byte identity without execution"
    )
    inventory.add_argument("path", type=Path)
    args = parser.parse_args(arguments)
    try:
        descriptor = os.open(args.path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("Expected a regular file")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                before = os.fstat(stream.fileno())
                digest, signature, size = read_identity(stream, before.st_size)
                after = os.fstat(stream.fileno())
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_ino) != (
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                    after.st_ino,
                ) or size != after.st_size:
                    raise ValueError("Artifact changed while recording identity")
        finally:
            os.close(descriptor)
        evidence = Evidence.create(
            "inventory_artifact",
            {"size": after.st_size, "signature_hex": signature},
            subject_sha256=digest,
            parameters={"path": str(args.path.absolute())},
            limitations=(
                "Byte identity only; no format, architecture or behavior inferred.",
                "Identity describes the bytes read, not an atomic filesystem snapshot. "
                "Concurrent writes cannot be ruled out without snapshot or cooperative locking.",
            ),
        )
        print(json.dumps({"isError": False, "evidence": evidence.record()}))
        return 0
    except (OSError, ValueError) as error:
        print(
            json.dumps(
                {
                    "isError": True,
                    "error": {
                        "code": "artifact_unreadable_or_changed",
                        "what_was_tried": "Read a regular local file and calculate SHA-256",
                        "partial_observations": [],
                        "reason": str(error),
                        "remediation": "Supply a readable regular file; retry after writes stop.",
                    },
                }
            )
        )
        return 1
