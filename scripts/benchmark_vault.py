"""Measure the fixed Argon2id cost on the running host, using only fixture data."""

import json
import math
import os
import platform
import statistics
import sys
import time
from pathlib import Path

from pydantic import SecretStr

from backend.services.vault_service import ARGON2_PARAMETERS, VaultService


def main() -> None:
    password, salt = SecretStr("public CI benchmark fixture"), bytes(range(32))
    VaultService.derive_argon2id(password, salt)
    timings = []
    for _ in range(20):
        started = time.perf_counter()
        VaultService.derive_argon2id(password, salt)
        timings.append((time.perf_counter() - started) * 1000)
    p95 = sorted(timings)[math.ceil(len(timings) * 0.95) - 1]
    result = {
        "kdf": "Argon2id",
        "parameters": ARGON2_PARAMETERS,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "processor": platform.processor(),
        "ci": bool(os.environ.get("GITHUB_ACTIONS")),
        "samples": len(timings),
        "median_ms": round(statistics.median(timings), 3),
        "p95_ms": round(p95, 3),
        "max_ms": round(max(timings), 3),
    }
    output = json.dumps(result, indent=2)
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_text(output + "\n", encoding="utf-8")
    print(output)
    if p95 >= 300:
        raise SystemExit("Argon2id p95 exceeds the 300 ms interactive budget")


if __name__ == "__main__":
    main()
