import asyncio
import hashlib
import secrets
import time

import pytest
from pydantic import SecretStr

from backend.main import create_app
from backend.services.vault_service import VaultAccessError


@pytest.mark.asyncio
async def test_unlock_backoff_is_workspace_scoped_capped_and_reset(tmp_path):
    app = create_app("f" * 64, "vault-backoff", tmp_path)
    async with app.router.lifespan_context(app):
        service, scope = app.state.vault, app.state.workspaces.active_id
        password = SecretStr("fixture master passphrase")
        await service.unlock(scope, password, initialize=True)
        for expected in (1, 2, 4, 8, 16, 32, 60, 60):
            before = time.monotonic()
            with pytest.raises(VaultAccessError, match="Incorrect vault password or damaged vault"):
                await service.unlock(scope, SecretStr("wrong"))
            failures, retry_at = service._failures[scope]
            assert expected <= retry_at - before < expected + 2
            service._failures[scope] = (failures, 0)
        await service.unlock(scope, password)
        assert scope not in service._failures


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["unlock", "reveal", "export", "change_password"])
async def test_derivation_does_not_hold_global_lock_and_lock_revokes_pending_unlock(
    tmp_path, monkeypatch, operation
):
    from shared.vault import CredentialInput
    from shared.workspaces import WorkspaceCreate

    app = create_app("f" * 64, "vault-concurrency", tmp_path)
    async with app.router.lifespan_context(app):
        service, scope = app.state.vault, app.state.workspaces.active_id
        password = SecretStr("fixture master passphrase")
        token = (await service.unlock(scope, password, initialize=True)).token
        candidate = await service.candidate(
            scope,
            token,
            CredentialInput(
                service="fixture", username="alice", secret=SecretStr("fixture-secret")
            ),
        )
        await service.accept(scope, token, candidate.id)
        other = await app.state.workspaces.create(WorkspaceCreate(name="Other"))
        entered, proceed = asyncio.Event(), asyncio.Event()
        original = service._verify

        async def slow(*args):
            entered.set()
            await proceed.wait()
            return await original(*args)

        monkeypatch.setattr(service, "_verify", slow)
        calls = {
            "unlock": lambda: service.unlock(scope, password),
            "reveal": lambda: service.reveal(scope, token, candidate.id, password),
            "export": lambda: service.export(scope, token, password),
            "change_password": lambda: service.change_password(
                scope, token, password, SecretStr("replacement passphrase")
            ),
        }
        pending = asyncio.create_task(calls[operation]())
        try:
            await asyncio.wait_for(entered.wait(), 2)
            assert not service._lock.locked()
            await asyncio.wait_for(service.status(other.id), 2)
            await asyncio.wait_for(service.lock_all(), 2)
        finally:
            proceed.set()
            result = await asyncio.gather(pending, return_exceptions=True)
        assert isinstance(result[0], VaultAccessError)
        assert scope not in service._sessions


@pytest.mark.asyncio
async def test_backoff_wait_survives_cancellation_and_unknown_scope_is_generic(tmp_path):
    from uuid import uuid4

    app = create_app("f" * 64, "vault-delay", tmp_path)
    async with app.router.lifespan_context(app):
        service, scope = app.state.vault, app.state.workspaces.active_id
        password = SecretStr("fixture master passphrase")
        await service.unlock(scope, password, initialize=True)
        with pytest.raises(VaultAccessError) as wrong:
            await service.unlock(scope, SecretStr("wrong"))
        with pytest.raises(VaultAccessError) as missing:
            await service.unlock(uuid4(), SecretStr("wrong"))
        assert str(wrong.value) == str(missing.value)
        pending = asyncio.create_task(service.unlock(scope, password))
        await asyncio.sleep(0.05)
        assert not pending.done() and not service._lock.locked()
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
        assert scope in service._failures
        started = time.monotonic()
        remaining = service._failures[scope][1] - started
        await service.unlock(scope, password)
        assert time.monotonic() - started >= remaining
        assert scope not in service._failures


@pytest.mark.asyncio
async def test_opaque_tokens_are_hashed_revoked_and_unforgeable(tmp_path):
    app = create_app("f" * 64, "vault-hardening", tmp_path)
    async with app.router.lifespan_context(app):
        service, scope = app.state.vault, app.state.workspaces.active_id
        password = SecretStr("fixture master passphrase")
        token = (await service.unlock(scope, password, initialize=True)).token
        assert len(token) == 43 and "." not in token
        state = service._sessions[scope]
        assert state.token_hash == hashlib.sha256(token.encode()).digest()
        assert token not in repr(state)
        for invalid in (secrets.token_urlsafe(32), token + "x", "", "eyJhbGc.payload.signature"):
            with pytest.raises(VaultAccessError):
                await service.authorize(scope, invalid)
        await service.authorize(scope, token)
        replacement = (await service.unlock(scope, password)).token
        assert replacement != token
        with pytest.raises(VaultAccessError):
            await service.authorize(scope, token)
        await service.authorize(scope, replacement)
        await service.lock_all()
        with pytest.raises(VaultAccessError):
            await service.authorize(scope, replacement)
