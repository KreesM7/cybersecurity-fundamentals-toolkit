"""Workspace Fernet vault with expiring memory keys and explicit reauthentication."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import secrets
import sqlite3
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, closing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar
from uuid import UUID, uuid4

from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pydantic import SecretStr
from sqlalchemy import select

from backend.events import EventHub
from backend.models import EncryptedCredential, Target, VaultConfig
from backend.platform_utils import assert_private_path, atomic_private_write
from backend.services.workspace_service import WorkspaceLease, WorkspaceService
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
ARGON2_PARAMETERS = {"memory_cost": 19456, "time_cost": 2, "parallelism": 1, "length": 32}
CHECK = b"toolkit-vault-v1"
_T = TypeVar("_T")


async def _await_native(task: asyncio.Task[_T]) -> _T:
    """Retain native-work ownership even after repeated cancellation requests."""
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if not task.cancelled():
            task.exception()
        raise


class VaultAccessError(ValueError):
    """Credentials were wrong, or this memory-only vault session has expired/revoked."""


@dataclass
class Unlocked:
    key_material: bytearray = field(repr=False)
    token_hash: bytes = field(repr=False)
    expires: float
    last_used: float

    @property
    def cipher(self) -> Fernet:
        # Keep only the wipeable buffer in session state; operation-local copies are temporary.
        return Fernet(base64.urlsafe_b64encode(self.key_material))


class VaultService:
    def __init__(self, workspaces: WorkspaceService, events: EventHub) -> None:
        self.workspaces, self.events = workspaces, events
        self._sessions: dict[UUID, Unlocked] = {}
        self._candidates: dict[UUID, dict[UUID, CredentialInput]] = {}
        self._lock = asyncio.Lock()
        self._password_locks: dict[UUID, asyncio.Lock] = {}
        self._failures: dict[UUID, tuple[int, float]] = {}
        self._generation = 0
        self._derivations = asyncio.Semaphore(2)
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
                    self._discard(scope, expired=True)
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

    @staticmethod
    def derive_argon2id(password: SecretStr, salt: bytes) -> Fernet:
        if len(salt) != 32:
            raise VaultAccessError("Vault parameters are invalid; restore a verified backup.")
        key = hash_secret_raw(
            password.get_secret_value().encode("utf-8"),
            salt,
            time_cost=2,
            memory_cost=19456,
            parallelism=1,
            hash_len=32,
            type=Type.ID,
        )
        return Fernet(base64.urlsafe_b64encode(key))

    async def _derive(self, password: SecretStr, salt: bytes, *, legacy: bool = False) -> Fernet:
        async with self._derivations:
            task = asyncio.create_task(
                asyncio.to_thread(self.derive, password, salt, ITERATIONS)
                if legacy
                else asyncio.to_thread(self.derive_argon2id, password, salt)
            )
            # Cancellation must not free a slot while its native KDF still owns memory.
            return await _await_native(task)

    async def _verify(self, config: VaultConfig, password: SecretStr) -> Fernet:
        legacy = config.kdf == "PBKDF2-HMAC-SHA256"
        expected = {"iterations": ITERATIONS, "length": 32} if legacy else ARGON2_PARAMETERS
        if config.kdf not in {"PBKDF2-HMAC-SHA256", "Argon2id"} or config.parameters != expected:
            raise VaultAccessError("Vault parameters are invalid; restore a verified backup.")
        cipher = await self._derive(password, config.salt, legacy=legacy)
        try:
            if not secrets.compare_digest(cipher.decrypt(config.encrypted_check), CHECK):
                raise VaultAccessError("Incorrect vault password or damaged vault.")
        except InvalidToken as exc:
            raise VaultAccessError("Incorrect vault password or damaged vault.") from exc
        return cipher

    @staticmethod
    def _backup_vault(path: Path) -> None:
        """Snapshot SQLite (including WAL) into an owner-only, encrypted old-format backup."""
        assert_private_path(path)
        backup = path.with_name(f"{path.stem}.pre-argon2-{uuid4().hex}.db")
        atomic_private_write(backup, b"")
        try:
            with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as source:
                with closing(sqlite3.connect(backup)) as destination:
                    source.backup(destination)
                    if destination.execute("PRAGMA quick_check").fetchone() != ("ok",):
                        raise VaultAccessError("Vault backup failed; migration cancelled.")
            assert_private_path(backup)
        except BaseException:
            backup.unlink(missing_ok=True)
            raise

    async def _migrate_legacy(
        self, lease: WorkspaceLease, generation: int, password: SecretStr, previous: Fernet
    ) -> Fernet:
        salt = secrets.token_bytes(32)
        replacement = await self._derive(password, salt)
        database = lease.engine.url.database
        if database is None:
            raise VaultAccessError("Vault backup failed; migration cancelled.")
        backup = asyncio.create_task(asyncio.to_thread(self._backup_vault, Path(database)))
        await _await_native(backup)
        async with self._lock, lease.sessions.begin() as session:
            self._check_generation(lease.workspace_id, generation)
            config = await session.get(VaultConfig, 1)
            if config is None or config.kdf != "PBKDF2-HMAC-SHA256":
                raise VaultAccessError("Vault changed while unlocking. Unlock it again.")
            rows = list(await session.scalars(select(EncryptedCredential)))
            encrypted = [
                (row, self._encrypt(replacement, self._decrypt(previous, row))) for row in rows
            ]
            for row, ciphertext in encrypted:
                row.ciphertext = ciphertext
            config.kdf = "Argon2id"
            config.parameters = dict(ARGON2_PARAMETERS)
            config.salt = salt
            config.encrypted_check = replacement.encrypt(CHECK)
        return replacement

    def _audit(self, workspace_id: UUID, action: str, outcome: str) -> None:
        self.events.publish_nowait(
            "vault-audit", {"action": action, "outcome": outcome}, workspace_id=workspace_id
        )
        logging.getLogger("toolkit.vault").info(
            "Vault %s %s workspace=%s", action, outcome, workspace_id
        )

    def _discard(self, workspace_id: UUID, *, expired: bool = False) -> None:
        value = self._sessions.pop(workspace_id, None)
        if value is not None:
            value.key_material[:] = b"\x00" * len(value.key_material)
            value.token_hash = b""
            if expired:
                self._audit(workspace_id, "session-expired", "locked")
        self._candidates.pop(workspace_id, None)

    def _access(self, workspace_id: UUID, token: str) -> Fernet:
        if workspace_id != self.workspaces.active_id:
            self._discard(workspace_id)
            raise VaultAccessError("Switching workspaces locks the vault.")
        unlocked = self._sessions.get(workspace_id)
        now = time.monotonic()
        if unlocked is None or now >= unlocked.expires or now - unlocked.last_used >= 300:
            self._discard(workspace_id, expired=unlocked is not None)
            raise VaultAccessError("Vault is locked. Unlock it again.")
        presented = hashlib.sha256(token.encode("utf-8")).digest()
        if not secrets.compare_digest(presented, unlocked.token_hash):
            raise VaultAccessError("Vault token is invalid or expired.")
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
                self._discard(workspace_id, expired=True)
            return VaultStatus(
                workspace_id=workspace_id,
                initialized=config is not None,
                unlocked=workspace_id in self._sessions,
            )

    async def authorize(self, workspace_id: UUID, token: str) -> None:
        async with self._lock:
            self._access(workspace_id, token)

    def _check_generation(self, workspace_id: UUID, generation: int) -> None:
        if generation != self._generation or workspace_id != self.workspaces.active_id:
            raise VaultAccessError("Vault is locked. Unlock it again.")

    @asynccontextmanager
    async def _password_operation(
        self, workspace_id: UUID
    ) -> AsyncIterator[tuple[WorkspaceLease, int]]:
        async with self._lock:
            if workspace_id != self.workspaces.active_id:
                raise VaultAccessError("Incorrect vault password or damaged vault.")
            gate = self._password_locks.setdefault(workspace_id, asyncio.Lock())
            generation = self._generation
        async with gate, await self.workspaces.lease(workspace_id) as lease:
            self._check_generation(workspace_id, generation)
            yield lease, generation

    @asynccontextmanager
    async def _reauthenticate(
        self, workspace_id: UUID, token: str, password: SecretStr
    ) -> AsyncIterator[tuple[WorkspaceLease, Fernet]]:
        async with self._password_operation(workspace_id) as (lease, generation):
            async with self._lock:
                self._access(workspace_id, token)
            async with lease.sessions() as session:
                config = await session.get(VaultConfig, 1)
                if config is None:
                    raise VaultAccessError("Vault is not initialized")
            cipher = await self._verify(config, password)
            async with self._lock:
                self._check_generation(workspace_id, generation)
                self._access(workspace_id, token)
                yield lease, cipher

    async def unlock(
        self, workspace_id: UUID, password: SecretStr, *, initialize: bool = False
    ) -> VaultToken:
        try:
            result = await self._unlock(workspace_id, password, initialize=initialize)
        except Exception:
            self._audit(workspace_id, "unlock", "failure")
            raise
        self._audit(workspace_id, "unlock", "success")
        return result

    async def _unlock(
        self, workspace_id: UUID, password: SecretStr, *, initialize: bool = False
    ) -> VaultToken:
        async with self._password_operation(workspace_id) as (lease, generation):
            _, retry_at = self._failures.get(workspace_id, (0, 0.0))
            await asyncio.sleep(max(0, retry_at - time.monotonic()))
            self._check_generation(workspace_id, generation)
            async with lease.sessions() as session:
                config = await session.get(VaultConfig, 1)
            try:
                if config is None:
                    if not initialize or len(password.get_secret_value()) < 12:
                        raise VaultAccessError("Incorrect vault password or damaged vault.")
                    salt = secrets.token_bytes(32)
                    cipher = await self._derive(password, salt)
                else:
                    cipher = await self._verify(config, password)
            except VaultAccessError:
                async with self._lock:
                    failures = min(self._failures.get(workspace_id, (0, 0.0))[0] + 1, 7)
                    self._failures[workspace_id] = (
                        failures,
                        time.monotonic() + min(2 ** (failures - 1), 60),
                    )
                raise
            if config is not None and config.kdf == "PBKDF2-HMAC-SHA256":
                cipher = await self._migrate_legacy(lease, generation, password, cipher)
            async with self._lock:
                self._check_generation(workspace_id, generation)
                if config is None:
                    async with lease.sessions.begin() as session:
                        session.add(
                            VaultConfig(
                                id=1,
                                kdf="Argon2id",
                                parameters=dict(ARGON2_PARAMETERS),
                                salt=salt,
                                encrypted_check=cipher.encrypt(CHECK),
                            )
                        )
                self._check_generation(workspace_id, generation)
                self._failures.pop(workspace_id, None)
                now = time.monotonic()
                token = secrets.token_urlsafe(32)
                self._discard(workspace_id)
                self._sessions[workspace_id] = Unlocked(
                    bytearray(cipher._signing_key + cipher._encryption_key),
                    hashlib.sha256(token.encode("utf-8")).digest(),
                    now + 900,
                    now,
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
        async with self._reauthenticate(workspace_id, token, password) as (lease, cipher):
            async with lease.sessions() as session:
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
        async with self._password_operation(workspace_id) as (lease, generation):
            async with self._lock:
                self._access(workspace_id, token)
            async with lease.sessions() as session:
                config = await session.get(VaultConfig, 1)
                if config is None:
                    raise VaultAccessError("Vault is not initialized")
            previous = await self._verify(config, password)
            salt = secrets.token_bytes(32)
            replacement = await self._derive(new_password, salt)
            async with self._lock, lease.sessions.begin() as session:
                self._check_generation(workspace_id, generation)
                self._access(workspace_id, token)
                config = await session.get(VaultConfig, 1)
                if config is None:
                    raise VaultAccessError("Vault is not initialized")
                rows = list(await session.scalars(select(EncryptedCredential)))
                encrypted = [
                    (row, self._encrypt(replacement, self._decrypt(previous, row))) for row in rows
                ]
                for row, ciphertext in encrypted:
                    row.ciphertext = ciphertext
                config.salt = salt
                config.kdf = "Argon2id"
                config.parameters = dict(ARGON2_PARAMETERS)
                config.encrypted_check = replacement.encrypt(CHECK)
                self._discard(workspace_id)

    async def export(self, workspace_id: UUID, token: str, password: SecretStr) -> str:
        async with self._reauthenticate(workspace_id, token, password) as (lease, cipher):
            async with lease.sessions() as session:
                records = [
                    self._decrypt(cipher, row).transport_dump()
                    for row in await session.scalars(select(EncryptedCredential))
                ]
                return json.dumps(records, ensure_ascii=False, indent=2)

    async def lock_all(self) -> None:
        async with self._lock:
            self._generation += 1
            for workspace_id in tuple(self._sessions):
                self._discard(workspace_id)
            self._candidates.clear()
            await self.events.publish("vault-locked", {"reason": "locked"})

    async def close(self) -> None:
        if self._reaper:
            self._reaper.cancel()
            await asyncio.gather(self._reaper, return_exceptions=True)
        await self.lock_all()
