"""Stage the known CPython libffi build, without changing the installed Python."""

import hashlib
import io
import urllib.request
import zipfile
from pathlib import Path

URL = "https://github.com/python/cpython-bin-deps/archive/refs/tags/libffi-3.4.4.zip"
DIGEST = "681c0e6306b4bcb54ecce8305f67ca88ab03be922b6c4dcfd18240ad46e357d8"


def main():
    with urllib.request.urlopen(URL, timeout=60) as response:
        content = response.read(20 * 1024 * 1024)
    if hashlib.sha256(content).hexdigest() != DIGEST:
        raise RuntimeError("CPython libffi archive digest mismatch")
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        binary = archive.read("cpython-bin-deps-libffi-3.4.4/amd64/libffi-8.dll")
    output = Path(__file__).resolve().parents[1] / "work/native/libffi-8.dll"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(binary)
    print("Staged known x64 libffi 3.4.4; installed Python was not modified.")


if __name__ == "__main__":
    main()
