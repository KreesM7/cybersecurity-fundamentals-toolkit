import asyncio
import hashlib
import secrets
import shutil
import sqlite3
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy import select

from backend.main import create_app
from backend.models import EncryptedCredential, VaultConfig
from backend.platform_utils import protect_private_path
from backend.services.vault_service import CHECK, ITERATIONS, VaultAccessError, VaultService
from shared.vault import CredentialInput


async def legacy_copy(tmp_path):
    """Construct a disposable old-format fixture, then test only a separate copy."""
    original = tmp_path / "original"
    password = SecretStr("legacy fixture passphrase")
    identifier = uuid4()
    app = create_app("f" * 64, "legacy-fixture", original)
    async with app.router.lifespan_context(app):
        scope = app.state.workspaces.active_id
        salt = secrets.token_bytes(32)
        cipher = VaultService.derive(password, salt, ITERATIONS)
        async with await app.state.workspaces.lease(scope) as lease:
            async with lease.sessions.begin() as session:
                session.add(
                    VaultConfig(
                        id=1,
                        kdf="PBKDF2-HMAC-SHA256",
                        parameters={"iterations": ITERATIONS, "length": 32},
                        salt=salt,
                        encrypted_check=cipher.encrypt(CHECK),
                    )
                )
                await session.flush()
                session.add(
                    EncryptedCredential(
                        id=str(identifier),
                        vault_id=1,
                        ciphertext=VaultService._encrypt(
                            cipher,
                            CredentialInput(
                                service="fixture", username="alice", secret=SecretStr("preserve-me")
                            ),
                        ),
                        created_at=datetime.now(UTC),
                    )
                )
    hashes = {p: hashlib.sha256(p.read_bytes()).digest() for p in original.rglob("*.db")}
    copied = tmp_path / "copied"
    shutil.copytree(original, copied)
    protect_private_path(copied, directory=True)
    for path in sorted(copied.rglob("*"), key=lambda p: len(p.parts)):
        protect_private_path(path, directory=path.is_dir())
    return copied, scope, identifier, password, hashes


@pytest.mark.asyncio
async def test_pbkdf2_copy_migrates_atomically_and_preserves_credentials(tmp_path):
    copied, scope, identifier, password, hashes = await legacy_copy(tmp_path)
    app = create_app("f" * 64, "migration-test", copied)
    async with app.router.lifespan_context(app):
        service = app.state.vault
        token = (await service.unlock(scope, password)).token
        async with await app.state.workspaces.lease(scope) as lease:
            async with lease.sessions() as session:
                config = await session.get(VaultConfig, 1)
                assert config.kdf == "Argon2id"
                assert config.parameters["memory_cost"] == 19456
        assert (await service.reveal(scope, token, identifier, password)).secret == "preserve-me"
        backups = list(copied.rglob("*.pre-argon2-*.db"))
        assert len(backups) == 1
        with sqlite3.connect(backups[0]) as connection:
            assert (
                connection.execute("select kdf from vault_config").fetchone()[0]
                == "PBKDF2-HMAC-SHA256"
            )
        await service.lock_all()
        await service.unlock(scope, password)
        assert len(list(copied.rglob("*.pre-argon2-*.db"))) == 1
    assert all(hashlib.sha256(p.read_bytes()).digest() == h for p, h in hashes.items())


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["backup", "encrypt", "commit"])
async def test_migration_failure_keeps_old_vault_readable(tmp_path, monkeypatch, failure):
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    copied, scope, identifier, password, hashes = await legacy_copy(tmp_path)
    app = create_app("f" * 64, "migration-rollback", copied)
    async with app.router.lifespan_context(app):
        service = app.state.vault

        def fail(*args):
            raise RuntimeError("injected migration failure")

        def fail_commit(session):
            if any(isinstance(row, VaultConfig) and row.kdf == "Argon2id" for row in session.dirty):
                fail()

        if failure == "commit":
            event.listen(Session, "before_commit", fail_commit)
        else:
            monkeypatch.setattr(
                service, "_backup_vault" if failure == "backup" else "_encrypt", fail
            )
        try:
            with pytest.raises(RuntimeError, match="injected migration failure"):
                await service.unlock(scope, password)
        finally:
            if failure == "commit":
                event.remove(Session, "before_commit", fail_commit)
        assert scope not in service._sessions
        async with await app.state.workspaces.lease(scope) as lease:
            async with lease.sessions() as session:
                config = await session.get(VaultConfig, 1)
                assert config.kdf == "PBKDF2-HMAC-SHA256"
                cipher = await service._verify(config, password)
                row = (await session.scalars(select(EncryptedCredential))).one()
                assert service._decrypt(cipher, row).secret.get_secret_value() == "preserve-me"
    assert all(hashlib.sha256(p.read_bytes()).digest() == h for p, h in hashes.items())


@pytest.mark.asyncio
async def test_wrong_password_never_migrates_and_bad_kdf_cost_fails_closed(tmp_path):
    copied, scope, _, password, _ = await legacy_copy(tmp_path)
    app = create_app("f" * 64, "migration-invalid", copied)
    async with app.router.lifespan_context(app):
        service = app.state.vault
        with pytest.raises(VaultAccessError):
            await service.unlock(scope, SecretStr("wrong"))
        assert not list(copied.rglob("*.pre-argon2-*.db"))
        async with await app.state.workspaces.lease(scope) as lease:
            async with lease.sessions() as session:
                config = await session.get(VaultConfig, 1)
                assert config.kdf == "PBKDF2-HMAC-SHA256"
                config.kdf = "Argon2id"
                config.parameters = {"memory_cost": 2**31}
                with pytest.raises(VaultAccessError, match="parameters"):
                    await service._verify(config, password)
        with pytest.raises(VaultAccessError, match="parameters"):
            service.derive_argon2id(password, b"short")


@pytest.mark.asyncio
async def test_cancelled_native_kdf_keeps_concurrency_slot(tmp_path, monkeypatch):
    import threading

    app = create_app("f" * 64, "bounded-kdf", tmp_path)
    async with app.router.lifespan_context(app):
        service = app.state.vault
        gate, entered = threading.Event(), threading.Event()
        mutex = threading.Lock()
        active, maximum = 0, 0
        original = service.derive_argon2id

        def slow(password, salt):
            nonlocal active, maximum
            with mutex:
                active += 1
                maximum = max(maximum, active)
                if active == 2:
                    entered.set()
            try:
                assert gate.wait(5)
                return original(password, salt)
            finally:
                with mutex:
                    active -= 1

        monkeypatch.setattr(service, "derive_argon2id", slow)
        tasks = [
            asyncio.create_task(service._derive(SecretStr("fixture"), bytes(32))) for _ in range(3)
        ]
        try:
            assert await asyncio.to_thread(entered.wait, 3)
            tasks[0].cancel()
            await asyncio.sleep(0.02)
            tasks[0].cancel()
            await asyncio.sleep(0.02)
            assert not tasks[0].done() and maximum == 2
        finally:
            gate.set()
            results = await asyncio.gather(*tasks, return_exceptions=True)
        assert isinstance(results[0], asyncio.CancelledError)
        assert maximum == 2
