"""Install the same checksum-pinned Gitleaks binary for CI and local hooks."""

import argparse
import hashlib
import io
import os
import platform
import subprocess
import tarfile
import urllib.request
import zipfile
from pathlib import Path

VERSION = "8.30.1"
ARCHIVES = {
    ("Windows", "x64"): (
        "windows_x64.zip",
        "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",
    ),
    ("Linux", "x64"): (
        "linux_x64.tar.gz",
        "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    ),
    ("Linux", "arm64"): (
        "linux_arm64.tar.gz",
        "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
    ),
    ("Darwin", "arm64"): (
        "darwin_arm64.tar.gz",
        "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
    ),
    ("Darwin", "x64"): (
        "darwin_x64.tar.gz",
        "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
    ),
}


def install(directory: Path) -> Path:
    architecture = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64"
    archive, expected = ARCHIVES[(platform.system(), architecture)]
    directory.mkdir(parents=True, exist_ok=True)
    cached = directory / f"gitleaks_{VERSION}_{archive}"
    data = cached.read_bytes() if cached.exists() else b""
    if hashlib.sha256(data).hexdigest() != expected:
        url = f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/gitleaks_{VERSION}_{archive}"
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read(50 * 1024 * 1024 + 1)
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("Gitleaks archive checksum mismatch")
        cached.write_bytes(data)
    name = "gitleaks.exe" if platform.system() == "Windows" else "gitleaks"
    if archive.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as bundle:
            executable = bundle.read(name)
    else:
        with tarfile.open(fileobj=io.BytesIO(data)) as bundle:
            member = bundle.extractfile(name)
            if member is None:
                raise ValueError("Gitleaks archive does not contain the executable")
            executable = member.read()
    target = directory / name
    target.write_bytes(executable)
    target.chmod(0o755)
    return target.resolve()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("work/security-tools"))
    parser.add_argument("--scan-staged", action="store_true")
    parser.add_argument("--scan-history", action="store_true")
    args = parser.parse_args()
    executable = install(args.output)
    if args.scan_staged or args.scan_history:
        options = (
            ["--pre-commit", "--staged"]
            if args.scan_staged
            else ["--log-opts=--all --full-history"]
        )
        raise SystemExit(subprocess.call([str(executable), "git", "--redact", *options, "."]))
    if os.environ.get("GITHUB_PATH"):
        with open(os.environ["GITHUB_PATH"], "a", encoding="utf-8") as output:
            output.write(str(executable.parent) + "\n")
    print(executable)


if __name__ == "__main__":
    main()
