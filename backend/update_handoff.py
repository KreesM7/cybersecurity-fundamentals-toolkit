"""Windows handoff, called only by the owning desktop after graceful backend shutdown."""

import json
import os
import subprocess
from importlib.resources import files
from pathlib import Path

from backend.platform_utils import assert_private_path, atomic_private_write, hidden_process_options
from backend.services.update_service import (
    COSIGN_SHA256,
    EXE,
    UpdateError,
    UpdateService,
    checksum,
    identity_pattern,
    install_directory,
    installer_name,
    sha256,
    verifier_environment,
)


def silent_install_command(installer: Path, directory: Path) -> list[str]:
    return [
        str(installer),
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/SP-",
        "/DIR=" + str(directory),
    ]


def launch_pending_update(service: UpdateService) -> None:
    directory = install_directory()
    if not service.pending or service.progress.phase != "prepared" or directory is None:
        raise UpdateError("Installation was not explicitly prepared and verified.")
    if not service.progress.checksum_verified or not service.progress.signature_verified:
        raise UpdateError("Both update checks must pass before installation.")
    root = service.directory
    # No caller-supplied executable or destination; the currently installed executable owns both.
    plan = {
        "parent": os.getpid(),
        "version": service.notice.version,
        "installer": str(root / "installer.exe"),
        "verifier": str(root / "cosign.exe"),
        "checksums": str(root / "SHA256SUMS"),
        "signature": str(root / "installer.sigstore.json"),
        "checksums_signature": str(root / "SHA256SUMS.sigstore.json"),
        "verifier_hash": COSIGN_SHA256,
        "installer_hash": checksum(root / "SHA256SUMS", installer_name(service.notice.version)),
        "manifest_hash": sha256(root / "SHA256SUMS"),
        "identity": identity_pattern(service.notice.version),
        "directory": str(directory),
        "application": str(directory / EXE),
        "profile": str(service.profile),
        "flag": str(root / "updated.json"),
    }
    script = root / "apply-update.ps1"
    atomic_private_write(
        script, files("backend").joinpath("resources/apply-update.ps1").read_bytes()
    )
    plan_path = root / "apply.json"
    atomic_private_write(plan_path, json.dumps(plan).encode())
    # Pending marker cannot generate a success notification before the installer succeeds.
    atomic_private_write(
        root / "updated.json",
        json.dumps({"version": service.notice.version, "complete": False}).encode(),
    )
    powershell = (
        Path(os.environ.get("SystemRoot", "C:/Windows"))
        / "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    subprocess.Popen(
        [
            str(powershell),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-Plan",
            str(plan_path),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=verifier_environment(),
        **hidden_process_options(),
    )
    service.pending = False


def consume_update_message(profile: Path, current_version: str) -> str:
    flag = profile / "updates/updated.json"
    if not flag.exists():
        return ""
    try:
        assert_private_path(flag)
        if flag.stat().st_size > 1024:
            raise ValueError("Invalid update marker")
        data = json.loads(flag.read_text("utf-8-sig"))
        version = data["version"]
        installer_name(version)
        if data.get("complete") is True and version.removeprefix(
            "v"
        ) == current_version.removeprefix("v"):
            return f"Updated to {version}"
        return "Update did not complete. Open Settings to retry."
    except (ValueError, KeyError, TypeError, OSError):
        return "Update status unavailable. Open Settings to retry."
    finally:
        flag.unlink(missing_ok=True)
