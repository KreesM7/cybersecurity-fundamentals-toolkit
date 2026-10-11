from uuid import uuid4

import httpx
import pytest

from backend.main import create_app


@pytest.mark.asyncio
async def test_unlock_replay_never_retains_or_reissues_token(tmp_path, monkeypatch):
    app = create_app("f" * 64, "vault-replay", tmp_path)
    async with app.router.lifespan_context(app):
        scope = app.state.workspaces.active_id
        calls = 0
        original = app.state.vault.unlock

        async def counted(*args, **kwargs):
            nonlocal calls
            calls += 1
            return await original(*args, **kwargs)

        monkeypatch.setattr(app.state.vault, "unlock", counted)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app),
            base_url="https://127.0.0.1",
            headers={"Authorization": "Bearer " + "f" * 64},
        ) as client:
            path = f"/api/v1/vault/unlock?workspace_id={scope}"
            identifier = uuid4()
            headers = {"X-Request-ID": str(identifier)}
            body = {"password": "fixture master passphrase", "initialize": True}
            response = await client.post(path, json=body, headers=headers)
            assert response.status_code == 200, response.text
            token = response.json()["token"]
            record = app.state.mutations._secrets.records[(scope, identifier)]
            assert record.result == {"status": "unlocked"}
            assert token not in repr(app.state.mutations._secrets.records)
            for locked in (False, True):
                if locked:
                    await app.state.vault.lock_all()
                duplicate = await client.post(path, json=body, headers=headers)
                assert duplicate.status_code == 409
                assert "new request ID" in duplicate.text
                assert token not in duplicate.text
                assert calls == 1
            conflict = await client.post(
                path, json=body | {"password": "different passphrase"}, headers=headers
            )
            assert conflict.status_code == 409 and calls == 1
            fresh = await client.post(
                path,
                json=body | {"initialize": False},
                headers={"X-Request-ID": str(uuid4())},
            )
            assert fresh.status_code == 200 and calls == 2
            assert fresh.json()["token"] != token
