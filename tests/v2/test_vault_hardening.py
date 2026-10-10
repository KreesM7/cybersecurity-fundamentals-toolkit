import hashlib
import secrets

import pytest
from pydantic import SecretStr

from backend.main import create_app
from backend.services.vault_service import VaultAccessError


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
