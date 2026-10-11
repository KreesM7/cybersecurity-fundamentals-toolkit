import asyncio

import pytest
from pydantic import SecretStr

from backend.main import create_app
from backend.services.vault_service import VaultAccessError


@pytest.mark.asyncio
@pytest.mark.parametrize("trigger", ["lock", "access", "status", "reaper", "replace"])
async def test_key_material_wiped_and_expiry_audited(tmp_path, trigger):
    app = create_app("f" * 64, "vault-wipe", tmp_path)
    async with app.router.lifespan_context(app):
        service, scope = app.state.vault, app.state.workspaces.active_id
        password = SecretStr("private master fixture")
        token = (await service.unlock(scope, password, initialize=True)).token
        retained = service._sessions[scope]
        key = retained.key_material
        assert isinstance(key, bytearray) and any(key)
        if trigger == "lock":
            await service.lock_all()
        elif trigger == "replace":
            await service.unlock(scope, password)
        else:
            retained.expires = 0
            if trigger == "access":
                with pytest.raises(VaultAccessError):
                    await service.authorize(scope, token)
            elif trigger == "status":
                assert not (await service.status(scope)).unlocked
            else:
                async with asyncio.timeout(7):
                    while any(key):
                        await asyncio.sleep(0.05)
        assert key == bytearray(32)
        events = [event for event in app.state.events.recent if event.topic == "vault-audit"]
        assert any(event.data["outcome"] == "success" for event in events)
        if trigger in {"access", "status", "reaper"}:
            assert sum(event.data["action"] == "session-expired" for event in events) == 1
        assert token not in str(events) and password.get_secret_value() not in str(events)


@pytest.mark.asyncio
async def test_failed_unlock_audit_contains_no_secrets_or_attempt_count(tmp_path):
    app = create_app("f" * 64, "vault-audit", tmp_path)
    async with app.router.lifespan_context(app):
        service, scope = app.state.vault, app.state.workspaces.active_id
        await service.unlock(scope, SecretStr("private master fixture"), initialize=True)
        with pytest.raises(VaultAccessError):
            await service.unlock(scope, SecretStr("client_secret=do-not-record"))
        event = app.state.events.recent[-1]
        assert event.topic == "vault-audit"
        assert event.data == {"action": "unlock", "outcome": "failure"}
        assert "do-not-record" not in event.model_dump_json()
