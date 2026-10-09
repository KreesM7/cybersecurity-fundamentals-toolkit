"""Workspace Fernet vault with expiring memory keys and explicit reauthentication."""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from jose import JWTError, jwt  # type: ignore[import-untyped]  # Pinned library has no type stubs.
from pydantic import SecretStr
from sqlalchemy import select

from backend.events import EventHub
from backend.models import EncryptedCredential, Target, VaultConfig
from backend.services.workspace_service import WorkspaceService
from shared.vault import (
    CredentialInput,
    CredentialList,
    CredentialReveal,
    CredentialSaved,
    CredentialSummary,
    VaultStatus,
    VaultToken,
)

ITERATIONS = 600000
CHECK = b"toolkit-vault-v1"


class VaultAccessError(ValueError):
    """Credentials were wrong, or this memory-only vault session has expired/revoked."""


@dataclass
class Unlocked:
    cipher: Fernet
    jti: str
    expires: float
    last_used: float


class VaultService:
    def __init__(self, workspaces: WorkspaceService, events: EventHub) -> None:
        self.workspaces, self.events = workspaces, events
        self._signing_key = secrets.token_bytes(32)
        self._sessions: dict[UUID, Unlocked] = {}
        self._candidates: dict[UUID, dict[UUID, CredentialInput]] = {}
        self._lock = asyncio.Lock()
        self._reaper: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._reaper = asyncio.create_task(self._expire())

    async def _expire(self) -> None:
        while True:
            await asyncio.sleep(5)
            async with self._lock:
                now = time.monotonic()
                expired = [
                    scope
                    for scope, value in self._sessions.items()
                    if now >= value.expires or now - value.last_used >= 300
                ]
                for scope in expired:
                    self._discard(scope)
                    await self.events.publish(
                        "vault-locked", {"reason": "expired"}, workspace_id=scope
                    )

    @staticmethod
    def derive(password: SecretStr, salt: bytes, iterations: int) -> Fernet:
        if len(salt) != 32 or iterations != ITERATIONS:
            raise VaultAccessError("Vault parameters are invalid; restore a verified backup.")
        key = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
        ).derive(password.get_secret_value().encode("utf-8"))
        return Fernet(base64.urlsafe_b64encode(key))

    async def _verify(self, config: VaultConfig, password: SecretStr) -> Fernet:
        if config.kdf != "PBKDF2-HMAC-SHA256" or config.parameters != {
            "iterations": ITERATIONS,
            "length": 32,
        }:
            raise VaultAccessError("Vault parameters are invalid; restore a verified backup.")
        cipher = await asyncio.to_thread(self.derive, password, config.salt, ITERATIONS)
        try:
            if not secrets.compare_digest(cipher.decrypt(config.encrypted_check), CHECK):
                raise VaultAccessError("Incorrect vault password or damaged vault.")
        except InvalidToken as exc:
            raise VaultAccessError("Incorrect vault password or damaged vault.") from exc
        return cipher

    def _discard(self, workspace_id: UUID) -> None:
        self._sessions.pop(workspace_id, None)
        self._candidates.pop(workspace_id, None)

    def _access(self, workspace_id: UUID, token: str) -> Fernet:
        if workspace_id != self.workspaces.active_id:
            self._discard(workspace_id)
            raise VaultAccessError("Switching workspaces locks the vault.")
        unlocked = self._sessions.get(workspace_id)
        now = time.monotonic()
        if unlocked is None or now >= unlocked.expires or now - unlocked.last_used >= 300:
            self._discard(workspace_id)
            raise VaultAccessError("Vault is locked. Unlock it again.")
        try:
            claims = jwt.decode(
                token,
                self._signing_key,
                algorithms=["HS256"],
                options={
                    "require_exp": True,
                    "require_iat": True,
                    "require_sub": True,
                    "require_jti": True,
                },
            )
            if claims.get("sub") != str(workspace_id) or not secrets.compare_digest(
                str(claims.get("jti", "")), unlocked.jti
            ):
                raise VaultAccessError("Vault token belongs to another workspace or was revoked.")
        except JWTError as exc:
            raise VaultAccessError("Vault token is invalid or expired.") from exc
        unlocked.last_used = now
        return unlocked.cipher

    async def status(self, workspace_id: UUID) -> VaultStatus:
        async with self._lock, await self.workspaces.lease(workspace_id) as lease:
            async with lease.sessions() as session:
                config = await session.get(VaultConfig, 1)
            value = self._sessions.get(workspace_id)
            if value and (
                time.monotonic() >= value.expires or time.monotonic() - value.last_used >= 300
            ):
                self._discard(workspace_id)
            return VaultStatus(
                workspace_id=workspace_id,
                initialized=config is not None,
                unlocked=workspace_id in self._sessions,
            )

    async def authorize(self, workspace_id: UUID, token: str) -> None:
        async with self._lock:
            self._access(workspace_id, token)

    async def unlock(
        self, workspace_id: UUID, password: SecretStr, *, initialize: bool = False
    ) -> VaultToken:
        async with self._lock, await self.workspaces.lease(workspace_id) as lease:
            if workspace_id != self.workspaces.active_id:
                raise VaultAccessError("Select this workspace before unlocking its vault.")
            async with lease.sessions.begin() as session:
                config = await session.get(VaultConfig, 1)
                if config is None:
                    if not initialize or len(password.get_secret_value()) < 12:
                        raise VaultAccessError(
                            "Initialize this vault with a passphrase of at least 12 characters."
                        )
                    salt = secrets.token_bytes(32)
                    cipher = await asyncio.to_thread(self.derive, password, salt, ITERATIONS)
                    session.add(
                        VaultConfig(
                            id=1,
                            kdf="PBKDF2-HMAC-SHA256",
                            parameters={"iterations": ITERATIONS, "length": 32},
                            salt=salt,
                            encrypted_check=cipher.encrypt(CHECK),
                        )
                    )
                else:
                    cipher = await self._verify(config, password)
            now = time.monotonic()
            if workspace_id != self.workspaces.active_id:
                raise VaultAccessError(
                    "Workspace changed while unlocking. Unlock the selected vault."
                )
            jti = uuid4().hex
            self._sessions[workspace_id] = Unlocked(cipher, jti, now + 900, now)
            token = jwt.encode(
                {
                    "sub": str(workspace_id),
                    "jti": jti,
                    "iat": int(time.time()),
                    "exp": int(time.time()) + 900,
                },
                self._signing_key,
                algorithm="HS256",
            )
            return VaultToken(token=token)

    @staticmethod
    def _encrypt(cipher: Fernet, value: CredentialInput) -> bytes:
        return cipher.encrypt(
            json.dumps(value.transport_dump(), ensure_ascii=False).encode("utf-8")
        )

    @staticmethod
    def _decrypt(cipher: Fernet, row: EncryptedCredential) -> CredentialInput:
        try:
            return CredentialInput.model_validate_json(cipher.decrypt(row.ciphertext))
        except (InvalidToken, ValueError) as exc:
            raise VaultAccessError(
                "Credential could not be decrypted. Restore a verified backup."
            ) from exc

    @staticmethod
    def _summary(identifier: UUID, value: CredentialInput) -> CredentialSummary:
        return CredentialSummary(
            id=identifier, service=value.service, username=value.username, target_id=value.target_id
        )

    async def list(self, workspace_id: UUID, token: str) -> CredentialList:
        async with self._lock, await self.workspaces.lease(workspace_id) as lease:
            cipher = self._access(workspace_id, token)
            async with lease.sessions() as session:
                rows = await session.scalars(
                    select(EncryptedCredential).order_by(EncryptedCredential.created_at)
                )
                credentials = [
                    self._summary(UUID(row.id), self._decrypt(cipher, row)) for row in rows
                ]
            return CredentialList(
                credentials=credentials,
                candidates=[
                    self._summary(identifier, item)
                    for identifier, item in self._candidates.get(workspace_id, {}).items()
                ],
            )

    async def candidate(
        self, workspace_id: UUID, token: str, data: CredentialInput
    ) -> CredentialSaved:
        async with self._lock:
            self._access(workspace_id, token)
            values = self._candidates.setdefault(workspace_id, {})
            if len(values) >= 100:
                raise ValueError("Candidate limit reached; accept or discard existing candidates")
            identifier = uuid4()
            values[identifier] = data.model_copy(deep=True)
            return CredentialSaved(id=identifier)

    async def discard(self, workspace_id: UUID, token: str, identifier: UUID) -> None:
        async with self._lock:
            self._access(workspace_id, token)
            if self._candidates.get(workspace_id, {}).pop(identifier, None) is None:
                raise KeyError("Candidate is not in this vault")

    async def accept(self, workspace_id: UUID, token: str, identifier: UUID) -> CredentialSaved:
        async with self._lock, await self.workspaces.lease(workspace_id) as lease:
            cipher = self._access(workspace_id, token)
            data = self._candidates.get(workspace_id, {}).get(identifier)
            if data is None:
                raise KeyError("Candidate is not in this vault")
            ciphertext = self._encrypt(cipher, data)
            async with lease.sessions.begin() as session:
                if data.target_id and await session.get(Target, str(data.target_id)) is None:
                    raise ValueError("Credential target is not in this workspace")
                count = len(list(await session.scalars(select(EncryptedCredential.id).limit(1000))))
                if count >= 1000:
                    raise ValueError("Vault credential limit reached")
                session.add(
                    EncryptedCredential(
                        id=str(identifier),
                        vault_id=1,
                        target_id=str(data.target_id) if data.target_id else None,
                        ciphertext=ciphertext,
                        created_at=datetime.now(UTC),
                    )
                )
            del self._candidates[workspace_id][identifier]
            return CredentialSaved(id=identifier)

    async def reveal(
        self, workspace_id: UUID, token: str, identifier: UUID, password: SecretStr
    ) -> CredentialReveal:
        async with self._lock, await self.workspaces.lease(workspace_id) as lease:
            self._access(workspace_id, token)
            async with lease.sessions() as session:
                config = await session.get(VaultConfig, 1)
                if config is None:
                    raise VaultAccessError("Vault is not initialized")
                cipher = await self._verify(config, password)
                row = await session.get(EncryptedCredential, str(identifier))
                if row is None:
                    raise KeyError("Credential not in this workspace")
                value = self._decrypt(cipher, row)
                return CredentialReveal(
                    **self._summary(identifier, value).model_dump(),
                    secret=value.secret.get_secret_value(),
                    notes=value.notes,
                )

    async def delete(self, workspace_id: UUID, token: str, identifier: UUID) -> None:
        async with self._lock, await self.workspaces.lease(workspace_id) as lease:
            self._access(workspace_id, token)
            async with lease.sessions.begin() as session:
                row = await session.get(EncryptedCredential, str(identifier))
                if row is None:
                    raise KeyError("Credential not in this workspace")
                await session.delete(row)

    async def change_password(
        self, workspace_id: UUID, token: str, password: SecretStr, new_password: SecretStr
    ) -> None:
        if len(new_password.get_secret_value()) < 12:
            raise ValueError("Use a new passphrase with at least 12 characters")
        async with self._lock, await self.workspaces.lease(workspace_id) as lease:
            self._access(workspace_id, token)
            async with lease.sessions.begin() as session:
                config = await session.get(VaultConfig, 1)
                if config is None:
                    raise VaultAccessError("Vault is not initialized")
                previous = await self._verify(config, password)
                salt = secrets.token_bytes(32)
                replacement = await asyncio.to_thread(self.derive, new_password, salt, ITERATIONS)
                rows = list(await session.scalars(select(EncryptedCredential)))
                encrypted = [
                    (row, self._encrypt(replacement, self._decrypt(previous, row))) for row in rows
                ]
                for row, ciphertext in encrypted:
                    row.ciphertext = ciphertext
                config.salt = salt
                config.encrypted_check = replacement.encrypt(CHECK)
            self._discard(workspace_id)

    async def export(self, workspace_id: UUID, token: str, password: SecretStr) -> str:
        async with self._lock, await self.workspaces.lease(workspace_id) as lease:
            self._access(workspace_id, token)
            async with lease.sessions() as session:
                config = await session.get(VaultConfig, 1)
                if config is None:
                    raise VaultAccessError("Vault is not initialized")
                cipher = await self._verify(config, password)
                records = [
                    self._decrypt(cipher, row).transport_dump()
                    for row in await session.scalars(select(EncryptedCredential))
                ]
                return json.dumps(records, ensure_ascii=False, indent=2)

    async def lock_all(self) -> None:
        async with self._lock:
            self._sessions.clear()
            self._candidates.clear()
            await self.events.publish("vault-locked", {"reason": "locked"})

    async def close(self) -> None:
        if self._reaper:
            self._reaper.cancel()
            await asyncio.gather(self._reaper, return_exceptions=True)
        await self.lock_all()
        self._signing_key = b""
