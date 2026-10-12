"""Bounded Windows update downloads; no execution from API handlers or cached trust."""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from backend.events import EventHub
from backend.platform_utils import (
    assert_private_path,
    atomic_private_write,
    hidden_process_options,
    protect_private_path,
)
from shared.desktop import UpdateNotice, UpdateProgress

REPO = "KreesM7/cybersecurity-fundamentals-toolkit"
DOWNLOAD = f"https://github.com/{REPO}/releases/download/"
MAX_INSTALLER = 300 * 1024 * 1024
COSIGN_URL = "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-windows-amd64.exe"
# Official v3.1.3 cosign_checksums.txt. Never trust a downloaded verifier without this pin.
COSIGN_SIZE = 198819314
COSIGN_SHA256 = "9fe59be0eca1271873ce019061335eb1ac419b7059202e797828467ddabe33be"
ISSUER = "https://token.actions.githubusercontent.com"
WORKFLOW = f"https://github.com/{REPO}/.github/workflows/release-integrity.yml@"
EXE = "CybersecurityFundamentalsToolkit.exe"


class UpdateError(ValueError):
    pass


def installer_name(version: str) -> str:
    if not re.fullmatch(r"v?(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})", version):
        raise UpdateError("Invalid release version.")
    return f"Toolkit-{version.removeprefix('v')}-Windows-x64-Setup.exe"


def release_notice(version: str, result: dict[str, Any]) -> UpdateNotice:
    notice = UpdateNotice(version=version, url=f"https://github.com/{REPO}/releases/tag/{version}")
    name = installer_name(version)
    assets = result.get("assets", [])
    if not isinstance(assets, list):
        return notice
    selected: dict[str, dict[str, Any]] = {}
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            continue
        key = asset["name"]
        if key in selected:
            return notice  # Ambiguous release metadata is notify-only.
        selected[key] = asset
    required = [name, "SHA256SUMS", name + ".sigstore.json", "SHA256SUMS.sigstore.json"]
    for key in required:
        asset = selected.get(key, {})
        if asset.get("browser_download_url") != DOWNLOAD + version + "/" + key:
            return notice
        size = asset.get("size")
        if type(size) is not int or not 0 < size <= (MAX_INSTALLER if key == name else 1024 * 1024):
            return notice
    return notice.model_copy(
        update={
            "installer_url": selected[name]["browser_download_url"],
            "installer_size": selected[name]["size"],
            "checksums_url": selected["SHA256SUMS"]["browser_download_url"],
            "signature_url": selected[name + ".sigstore.json"]["browser_download_url"],
            "checksums_signature_url": selected["SHA256SUMS.sigstore.json"]["browser_download_url"],
        }
    )


def install_directory() -> Path | None:
    """Only an Inno-installed Windows build may replace itself; no second portable copy."""
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return None
    directory = Path(sys.executable).absolute().parent
    if Path(sys.executable).name != EXE or not (directory / "unins000.exe").is_file():
        return None
    return directory


def sha256(path: Path) -> str:
    assert_private_path(path)
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def checksum(manifest: Path, name: str) -> str:
    assert_private_path(manifest)
    if manifest.stat().st_size > 1024 * 1024:
        raise UpdateError("Checksum manifest is too large.")
    found: dict[str, str] = {}
    for line in manifest.read_text("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match or match[2] in found:
            raise UpdateError("Invalid checksum manifest.")
        found[match[2]] = match[1].lower()
    if name not in found:
        raise UpdateError("Installer is missing from the checksum manifest.")
    return found[name]


def identity_pattern(version: str) -> str:
    installer_name(version)
    return "^" + re.escape(WORKFLOW) + "(?:refs/heads/main|refs/tags/" + re.escape(version) + ")$"


def verifier_environment() -> dict[str, str]:
    # User proxy/TUF/Cosign overrides must not redirect the verification trust root.
    return {
        k: v
        for k, v in os.environ.items()
        if not k.upper().startswith(("COSIGN", "SIGSTORE", "TUF"))
        and k.upper()
        not in {
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        }
    }


def verify_signature(verifier: Path, artifact: Path, bundle: Path, version: str) -> None:
    if sha256(verifier) != COSIGN_SHA256:
        raise UpdateError("Update verifier checksum mismatch. Retry download.")
    for path in (artifact, bundle):
        assert_private_path(path)
    command = [
        str(verifier),
        "verify-blob",
        "--bundle",
        str(bundle),
        "--certificate-identity-regexp",
        identity_pattern(version),
        "--certificate-oidc-issuer",
        ISSUER,
        str(artifact),
    ]
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
            env=verifier_environment(),
            **hidden_process_options(),
        )
    except (OSError, subprocess.TimeoutExpired):
        raise UpdateError(
            "Signature verification unavailable or timed out. Retry download."
        ) from None
    if result.returncode != 0:
        raise UpdateError("Signature verification failed. Retry download.")


class UpdateService:
    def __init__(self, profile: Path, hub: EventHub) -> None:
        self.profile = profile.absolute()
        self.directory = self.profile / "updates"
        self.hub = hub
        self.progress = UpdateProgress(can_apply=install_directory() is not None)
        self.notice = UpdateNotice()
        self.task: asyncio.Task[None] | None = None
        self.pending = False
        self.transport: httpx.AsyncBaseTransport | None = None

    async def start(self) -> None:
        self.directory.mkdir(exist_ok=True, parents=True)
        protect_private_path(self.directory, directory=True)
        # No persisted "verified" bit: each new process must download/verify again.
        self._remove_downloads()

    def _remove_downloads(self) -> None:
        for name in (
            "installer.exe",
            "SHA256SUMS",
            "installer.sigstore.json",
            "SHA256SUMS.sigstore.json",
        ):
            path = self.directory / name
            if path.exists():
                assert_private_path(path)
                path.unlink()

    def publish(self, **changes: Any) -> None:
        self.progress = self.progress.model_copy(update=changes)
        self.hub.publish_nowait("update-progress", self.progress.model_dump(mode="json"))

    async def download_update(self, notice: UpdateNotice) -> UpdateProgress:
        if sys.platform != "win32":
            raise UpdateError("Automatic installation is available only for Windows installers.")
        if self.pending or (self.task and not self.task.done()):
            raise UpdateError("An update operation is already running.")
        name = installer_name(notice.version)
        expected = [name, "SHA256SUMS", name + ".sigstore.json", "SHA256SUMS.sigstore.json"]
        urls = [
            notice.installer_url,
            notice.checksums_url,
            notice.signature_url,
            notice.checksums_signature_url,
        ]
        if (
            any(
                url != DOWNLOAD + notice.version + "/" + key
                for url, key in zip(urls, expected, strict=True)
            )
            or not 0 < notice.installer_size <= MAX_INSTALLER
        ):
            raise UpdateError("This release has no complete signed Windows installer.")
        self._remove_downloads()
        self.notice = notice.model_copy()
        self.publish(
            version=notice.version,
            phase="downloading",
            received=0,
            total=notice.installer_size,
            checksum_verified=False,
            signature_verified=False,
            message="Downloading update…",
        )
        self.task = asyncio.create_task(self._download())
        return self.progress.model_copy()

    async def _fetch(
        self, client: httpx.AsyncClient, url: str, path: Path, cap: int, *, progress: bool = False
    ) -> None:
        atomic_private_write(path, b"")
        try:
            for _ in range(3):
                async with client.stream(
                    "GET", url, headers={"Accept-Encoding": "identity"}
                ) as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        target = response.headers.get("location", "")
                        parsed = urlsplit(target)
                        if (
                            parsed.scheme != "https"
                            or parsed.hostname != "release-assets.githubusercontent.com"
                            or parsed.port not in {None, 443}
                            or parsed.username
                            or parsed.password
                            or parsed.fragment
                        ):
                            raise UpdateError("Untrusted download redirect rejected.")
                        url = target
                        continue
                    response.raise_for_status()
                    if (
                        response.status_code != 200
                        or response.headers.get("content-encoding", "identity") != "identity"
                    ):
                        raise UpdateError("Unexpected download response.")
                    length = response.headers.get("content-length")
                    if length is not None and (not length.isdecimal() or int(length) > cap):
                        raise UpdateError("Download exceeds its size limit.")
                    received, last = 0, -1
                    with path.open("wb") as output:
                        async for chunk in response.aiter_bytes(65536):
                            received += len(chunk)
                            if received > cap:
                                raise UpdateError("Download exceeds its size limit.")
                            output.write(chunk)
                            percent = received * 100 // max(1, cap)
                            if progress and percent != last:
                                self.publish(received=received)
                                last = percent
                    if not received or (progress and received != cap):
                        raise UpdateError("Download is incomplete. Retry download.")
                    return
            raise UpdateError("Too many download redirects.")
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def verify(self) -> None:
        expected = checksum(self.directory / "SHA256SUMS", installer_name(self.notice.version))
        if sha256(self.directory / "installer.exe") != expected:
            raise UpdateError("Installer checksum mismatch. Retry download.")
        verifier = self.directory / "cosign.exe"
        verify_signature(
            verifier,
            self.directory / "SHA256SUMS",
            self.directory / "SHA256SUMS.sigstore.json",
            self.notice.version,
        )
        verify_signature(
            verifier,
            self.directory / "installer.exe",
            self.directory / "installer.sigstore.json",
            self.notice.version,
        )

    async def _verify_owned(self) -> None:
        # Wait for an in-flight verifier even on cancellation; never leave an owned process behind.
        task = asyncio.create_task(asyncio.to_thread(self.verify))
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            await asyncio.gather(task, return_exceptions=True)
            raise

    async def _download(self) -> None:
        try:
            async with asyncio.timeout(1800):
                async with httpx.AsyncClient(
                    verify=True,
                    trust_env=False,
                    follow_redirects=False,
                    timeout=httpx.Timeout(30, connect=5),
                    transport=self.transport,
                ) as client:
                    verifier = self.directory / "cosign.exe"
                    if (
                        not verifier.exists()
                        or await asyncio.to_thread(sha256, verifier) != COSIGN_SHA256
                    ):
                        self.publish(
                            received=0,
                            total=COSIGN_SIZE,
                            message="Downloading signature verifier (first use)…",
                        )
                        await self._fetch(client, COSIGN_URL, verifier, COSIGN_SIZE, progress=True)
                    if await asyncio.to_thread(sha256, verifier) != COSIGN_SHA256:
                        verifier.unlink(missing_ok=True)
                        raise UpdateError("Update verifier checksum mismatch. Retry download.")
                    self.publish(
                        received=0, total=self.notice.installer_size, message="Downloading update…"
                    )
                    for url, name, cap in (
                        (self.notice.checksums_url, "SHA256SUMS", 1024 * 1024),
                        (
                            self.notice.checksums_signature_url,
                            "SHA256SUMS.sigstore.json",
                            1024 * 1024,
                        ),
                        (self.notice.signature_url, "installer.sigstore.json", 1024 * 1024),
                        (self.notice.installer_url, "installer.exe", self.notice.installer_size),
                    ):
                        await self._fetch(
                            client,
                            url,
                            self.directory / name,
                            cap,
                            progress=name == "installer.exe",
                        )
                self.publish(phase="verifying", message="Verifying checksum and signatures…")
                await self._verify_owned()
                self.publish(
                    phase="verified",
                    checksum_verified=True,
                    signature_verified=True,
                    message="Checksum and signature verified.",
                )
        except asyncio.CancelledError:
            self._remove_downloads()
            raise
        except (OSError, ValueError, httpx.HTTPError, TimeoutError) as exc:
            self.fail(
                str(exc)
                if isinstance(exc, UpdateError)
                else "Update download failed. Retry download."
            )

    def fail(self, message: str) -> None:
        self.pending = False
        self.publish(
            phase="failed", checksum_verified=False, signature_verified=False, message=message
        )
        try:
            self._remove_downloads()
        except OSError:
            self.publish(
                message="Update failed; temporary files could not be removed. "
                "Close the app and retry."
            )

    async def apply_update(self, version: str) -> UpdateProgress:
        if install_directory() is None:
            raise UpdateError("Install & restart requires the installed Windows application.")
        if (
            version != self.notice.version
            or self.progress.phase != "verified"
            or not self.progress.checksum_verified
            or not self.progress.signature_verified
        ):
            raise UpdateError("Download and verify this update before installing.")
        self.publish(phase="preparing", message="Rechecking update before shutdown…")
        self.task = asyncio.create_task(self._prepare())
        return self.progress.model_copy()

    async def _prepare(self) -> None:
        try:
            await self._verify_owned()
            self.pending = True
            self.publish(phase="prepared", message="Verified. Closing safely to install…")
        except asyncio.CancelledError:
            self.pending = False
            raise
        except (ValueError, OSError) as exc:
            self.fail(
                str(exc)
                if isinstance(exc, UpdateError)
                else "Update verification failed. Retry download."
            )

    async def close(self) -> None:
        if self.task and not self.task.done():
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
