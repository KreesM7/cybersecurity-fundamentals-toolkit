"""Start an owned loopback TLS RPC server; credentials enter through private stdin."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import signal
import stat
import subprocess
import sys
from pathlib import Path


def private_directory(path: Path) -> None:
    for item in (path, *path.absolute().parents):
        if item.is_symlink():
            raise ValueError("RPC profile cannot contain symlinks.")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.stat().st_uid != getattr(os, "getuid")():
        raise ValueError("RPC profile must belong to the current user.")
    path.chmod(0o700)


def prepare_certificate(profile: Path) -> tuple[Path, Path]:
    private_directory(profile)
    certificate, key, combined = (
        profile / name for name in ("rpc-cert.pem", "rpc-key.pem", "rpc.pem")
    )
    for path in (certificate, key, combined):
        if path.is_symlink():
            raise ValueError("RPC certificate paths cannot be symlinks.")
        if path.exists() and (
            path.stat().st_uid != getattr(os, "getuid")()
            or stat.S_IMODE(path.stat().st_mode) != 0o600
        ):
            raise ValueError("RPC certificate files must be current-user-only (0600).")
    current = certificate.exists() and key.exists()
    if current:
        current = (
            subprocess.run(
                ["openssl", "x509", "-in", str(certificate), "-checkend", "604800", "-noout"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            ).returncode
            == 0
        )
    if not current:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:3072",
                "-nodes",
                "-days",
                "90",
                "-subj",
                "/CN=Toolkit-MSF",
                "-addext",
                "subjectAltName=IP:127.0.0.1,DNS:localhost",
                "-keyout",
                str(key),
                "-out",
                str(certificate),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    combined.write_bytes(key.read_bytes() + certificate.read_bytes())
    for path in (key, certificate, combined):
        path.chmod(0o600)
    return certificate, combined


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=Path.home() / ".toolkit-msf")
    parser.add_argument("--username", default="msf")
    parser.add_argument("--port", type=int, default=55553)
    parser.add_argument("--prepare", action="store_true")
    options = parser.parse_args()
    if not 1 <= options.port <= 65535 or not 1 <= len(options.username) <= 200:
        parser.error("Invalid RPC port or username")
    os.umask(0o077)
    certificate, combined = prepare_certificate(options.profile.absolute())
    if options.prepare:
        print(certificate)
        return 0
    password = (
        getpass.getpass("RPC password: ")
        if sys.stdin.isatty()
        else sys.stdin.readline(4098).rstrip("\r\n")
    )
    if not 1 <= len(password) <= 4096:
        parser.error("Supply one nonempty password on stdin (maximum4096 characters)")
    root = next(
        (
            path
            for path in (
                Path("/opt/metasploit-framework/embedded/framework"),
                Path("/usr/share/metasploit-framework"),
            )
            if (path / "lib/msfenv.rb").is_file()
        ),
        None,
    )
    if root is None:
        parser.error("Install Metasploit using provision-linux.sh first")
    ruby = (
        root.parent / "bin/ruby" if (root.parent / "bin/ruby").is_file() else Path("/usr/bin/ruby")
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if key
        not in {
            "GEM_HOME",
            "GEM_PATH",
            "GEM_ROOT",
            "RUBY_ENGINE",
            "RUBY_ROOT",
            "RUBYOPT",
            "MSF_LOCAL_LIB",
        }
    }
    environment["PATH"] = str(ruby.parent) + os.pathsep + environment.get("PATH", "")
    process = subprocess.Popen(
        [str(ruby), "-I", str(root / "lib"), str(Path(__file__).with_name("toolkit_rpc.rb"))],
        cwd=root,
        env=environment,
        stdin=subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdin is not None
    try:
        process.stdin.write(
            (
                json.dumps(
                    {
                        "username": options.username,
                        "password": password,
                        "certificate": str(combined),
                        "port": options.port,
                    }
                )
                + "\n"
            ).encode()
        )
        process.stdin.flush()
        password = ""

        def interrupted(signum: int, frame: object) -> None:
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, interrupted)
        return process.wait()
    except KeyboardInterrupt:
        return 130
    finally:
        process.stdin.close()
        if process.poll() is None:
            getattr(os, "killpg")(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                getattr(os, "killpg")(process.pid, getattr(signal, "SIGKILL"))
                process.wait()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError):
        print(
            "RPC startup failed. Verify installation, private profile and certificate permissions.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
