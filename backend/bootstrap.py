"""Reserve a loopback listener and publish a protected authenticated locator."""

from __future__ import annotations

import asyncio
import os
import secrets
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_serializer

from backend.platform_utils import (
    ProfileLease,
    acquire_profile_lease,
    assert_private_path,
    atomic_private_write,
    protect_private_path,
)
from backend.tls import TLSMaterial, ensure_tls


class InstanceLocator(BaseModel):
    """Private discovery record; secret token is excluded from diagnostic representations."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: int = Field(default=1, ge=1, le=1)
    pid: int = Field(gt=0)
    instance_id: UUID
    port: int = Field(ge=1, le=65535)
    token: SecretStr = Field(repr=False)
    certificate_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    clean_exit: bool = False

    @field_serializer("token")
    def serialize_private_token(self, value: SecretStr) -> str:
        # This model is serialized only into the owner-protected locator, never API/logs.
        return value.get_secret_value()

    @classmethod
    def fresh(cls, port: int, token: str, fingerprint: str) -> InstanceLocator:
        from backend.auth import TOKEN_PATTERN

        if not TOKEN_PATTERN.fullmatch(token):
            raise ValueError("Invalid instance token.")
        return cls(
            pid=os.getpid(),
            instance_id=uuid4(),
            port=port,
            token=SecretStr(token),
            certificate_fingerprint=fingerprint,
        )


def read_locator(profile: Path) -> InstanceLocator | None:
    path = profile / "instance.json"
    if not path.exists():
        return None
    assert_private_path(path)
    if path.stat().st_size > 4096:
        raise ValueError("Instance locator exceeds its size limit.")
    record = InstanceLocator.model_validate_json(path.read_bytes())
    from backend.auth import TOKEN_PATTERN

    if not TOKEN_PATTERN.fullmatch(record.token.get_secret_value()):
        raise ValueError("Invalid instance locator token.")
    return record


def write_locator(profile: Path, locator: InstanceLocator) -> None:
    atomic_private_write(profile / "instance.json", locator.model_dump_json().encode("utf-8"))


async def verify_existing(profile: Path, locator: InstanceLocator) -> bool:
    """Authenticate an existing instance using TLS, fingerprint and UUID, never PID alone."""
    if locator.clean_exit:
        return False
    tls_path = profile / "tls"
    cert_path = tls_path / "server.pem"
    ca_path = tls_path / "ca.pem"
    try:
        assert_private_path(cert_path)
        assert_private_path(ca_path)
    except FileNotFoundError:
        # Recovery still requires the exclusive profile lease in prepare_backend.
        # A running owner prevents replacement even if its on-disk certificates disappeared.
        return False
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    if not secrets.compare_digest(fingerprint, locator.certificate_fingerprint):
        raise ValueError(
            "Instance certificate identity changed; close the existing instance first."
        )
    material = TLSMaterial(ca_path, cert_path, tls_path / "server-key.pem", fingerprint)
    async with httpx.AsyncClient(
        verify=material.client_context(), trust_env=False, follow_redirects=False, timeout=2.0
    ) as client:
        try:
            reply = await client.get(
                f"https://127.0.0.1:{locator.port}/api/v1/health",
                headers={"Authorization": "Bearer " + locator.token.get_secret_value()},
            )
        except httpx.ConnectError as exc:
            # An inactive locator can be superseded only after an exclusive profile lease.
            if isinstance(exc.__cause__, OSError) or "connect" in str(exc).lower():
                return False
            raise ValueError("Existing backend TLS could not be verified.") from None
        reply.raise_for_status()
        stream = reply.extensions.get("network_stream")
        ssl_object = stream.get_extra_info("ssl_object") if stream is not None else None
        if ssl_object is None:
            raise ValueError("Existing backend TLS identity was unavailable.")
        peer = ssl_object.getpeercert(binary_form=True)
        if (
            not peer
            or x509.load_der_x509_certificate(peer).fingerprint(hashes.SHA256()).hex()
            != fingerprint
        ):
            raise ValueError("Existing backend certificate did not match the locator.")
        data = reply.json()
        if data.get("instance_id") != str(locator.instance_id) or data.get("schema_version") != 1:
            raise ValueError("Existing backend identity did not match the locator.")
        return True


@dataclass
class BackendInstance:
    profile: Path
    locator: InstanceLocator
    tls: TLSMaterial
    listener: socket.socket
    lease: ProfileLease
    server: uvicorn.Server

    async def serve(self) -> None:
        try:
            await self.server.serve(sockets=[self.listener])
        finally:
            self.listener.close()
            try:
                write_locator(self.profile, self.locator.model_copy(update={"clean_exit": True}))
            finally:
                self.lease.close()

    def stop(self) -> None:
        self.server.should_exit = True


def prepare_backend(profile: Path, *, lease: ProfileLease | None = None) -> BackendInstance:
    """Prepare TLS and reserve the socket before making a new locator discoverable."""
    from backend.main import create_app

    profile.mkdir(parents=True, exist_ok=True)
    protect_private_path(profile, directory=True)
    lease = lease or acquire_profile_lease(profile)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        tls = ensure_tls(profile)
        listener.bind(("127.0.0.1", 0))
        listener.setblocking(False)
        port = int(listener.getsockname()[1])
        locator = InstanceLocator.fresh(port, secrets.token_hex(32), tls.fingerprint)
        token = locator.token.get_secret_value()
        app = create_app(
            token,
            str(locator.instance_id),
            profile,
            allowed_origins={f"https://127.0.0.1:{port}", f"https://localhost:{port}"},
        )
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=port,
                ssl_certfile=str(tls.server_cert),
                ssl_keyfile=str(tls.server_key),
                access_log=False,
                log_config=None,
                log_level="warning",
                ws_max_size=65536,
                ws_max_queue=16,
                limit_concurrency=128,
                timeout_keep_alive=5,
                timeout_graceful_shutdown=10,
            )
        )
        write_locator(profile, locator)
        return BackendInstance(profile, locator, tls, listener, lease, server)
    except BaseException:
        listener.close()
        lease.close()
        raise


async def wait_ready(locator: InstanceLocator, tls: TLSMaterial, *, timeout: float = 10.0) -> None:
    """Retry transient startup transport failures within one authenticated TLS deadline."""
    async with httpx.AsyncClient(
        verify=tls.client_context(), trust_env=False, timeout=1.0, follow_redirects=False
    ) as client:
        async with asyncio.timeout(timeout):
            while True:
                try:
                    reply = await client.get(
                        f"https://127.0.0.1:{locator.port}/api/v1/health",
                        headers={"Authorization": "Bearer " + locator.token.get_secret_value()},
                    )
                    reply.raise_for_status()
                    if reply.json().get("instance_id") != str(locator.instance_id):
                        raise ValueError("Startup backend identity mismatch.")
                    return
                except (
                    httpx.ConnectError,
                    httpx.ReadError,
                    httpx.ConnectTimeout,
                    httpx.ReadTimeout,
                ) as exc:
                    # HTTPX wraps TLS errors as connection failures; retrying those would
                    # hide a trust/handshake failure behind a generic startup timeout.
                    cause: BaseException | None = exc
                    seen: set[int] = set()
                    while cause is not None and id(cause) not in seen:
                        seen.add(id(cause))
                        if isinstance(cause, ssl.SSLError):
                            raise
                        cause = cause.__cause__ or cause.__context__
                    await asyncio.sleep(0.05)
