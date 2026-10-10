import pytest
from pydantic import SecretStr

from backend.main import create_app
from shared.vault import CredentialInput


@pytest.mark.asyncio
async def test_vault_encryption_candidates_reauth_rotation_and_workspace_lock(tmp_path):
    from backend.services.vault_service import VaultAccessError
    from shared.workspaces import WorkspaceCreate

    app = create_app("f" * 64, "vault-test", tmp_path)
    async with app.router.lifespan_context(app):
        service = app.state.vault
        scope = app.state.workspaces.active_id
        password = SecretStr("fixture master passphrase")
        token = (await service.unlock(scope, password, initialize=True)).token
        candidate = await service.candidate(
            scope,
            token,
            CredentialInput(
                service="fixture", username="alice", secret=SecretStr("private-credential")
            ),
        )
        assert not (await service.list(scope, token)).credentials
        credential = await service.accept(scope, token, candidate.id)
        assert len((await service.list(scope, token)).credentials) == 1
        with pytest.raises(VaultAccessError):
            await service.reveal(scope, token, credential.id, SecretStr("wrong"))
        assert (
            await service.reveal(scope, token, credential.id, password)
        ).secret == "private-credential"
        other = await app.state.workspaces.create(WorkspaceCreate(name="Other"))
        with pytest.raises(VaultAccessError):
            await service.list(other.id, token)
        new_password = SecretStr("a new fixture master passphrase")
        await service.change_password(scope, token, password, new_password)
        with pytest.raises(VaultAccessError):
            await service.list(scope, token)
        with pytest.raises(VaultAccessError):
            await service.unlock(scope, password)
        fresh = (await service.unlock(scope, new_password)).token
        assert (
            await service.reveal(scope, fresh, credential.id, new_password)
        ).secret == "private-credential"
        assert "private-credential" in await service.export(scope, fresh, new_password)
        await service.lock_all()
        await app.state.workspaces.activate(other.id)
        with pytest.raises(VaultAccessError):
            await service.list(scope, fresh)
    assert not any(b"private-credential" in path.read_bytes() for path in tmp_path.rglob("*.db"))
    assert not any(
        b"fixture master passphrase" in path.read_bytes() for path in tmp_path.rglob("*.db")
    )


@pytest.mark.asyncio
async def test_vault_idle_expiry_and_atomic_rotation_failure(tmp_path, monkeypatch):
    from backend.services.vault_service import VaultAccessError

    app = create_app("f" * 64, "vault-test", tmp_path)
    async with app.router.lifespan_context(app):
        service, scope = app.state.vault, app.state.workspaces.active_id
        password = SecretStr("fixture master passphrase")
        token = (await service.unlock(scope, password, initialize=True)).token
        candidate = await service.candidate(
            scope,
            token,
            CredentialInput(service="fixture", username="alice", secret=SecretStr("keep-me")),
        )
        saved = await service.accept(scope, token, candidate.id)
        original = service._encrypt

        def failure(*args):
            raise RuntimeError("injected encryption failure")

        monkeypatch.setattr(service, "_encrypt", failure)
        with pytest.raises(RuntimeError):
            await service.change_password(
                scope, token, password, SecretStr("replacement passphrase")
            )
        monkeypatch.setattr(service, "_encrypt", original)
        assert (await service.reveal(scope, token, saved.id, password)).secret == "keep-me"
        service._sessions[scope].last_used -= 301
        with pytest.raises(VaultAccessError):
            await service.list(scope, token)
        assert scope not in service._sessions


@pytest.mark.asyncio
async def test_vault_api_revokes_on_switch_and_never_replays_plaintext(tmp_path):
    from uuid import uuid4

    import httpx
    from sqlalchemy import select

    from backend.models import VaultConfig

    app = create_app("f" * 64, "vault-api", tmp_path)
    async with app.router.lifespan_context(app):
        scope = app.state.workspaces.active_id
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app),
            base_url="https://127.0.0.1",
            headers={"Authorization": "Bearer " + "f" * 64},
        ) as client:

            async def post(path, data=None, token=None, identifier=None):
                headers = {"X-Request-ID": str(identifier or uuid4())}
                if token:
                    headers["X-Vault-Token"] = token
                return await client.post(
                    f"/api/v1/vault/{path}?workspace_id={scope}", json=data, headers=headers
                )

            password = {"password": "fixture master passphrase"}
            response = await post("unlock", password | {"initialize": True})
            assert response.status_code == 200, response.text
            token = response.json()["token"]
            candidate = await post(
                "candidates",
                {"service": "fixture", "username": "alice", "secret": "protected-secret"},
                token,
            )
            assert candidate.status_code == 200, candidate.text
            identifier = candidate.json()["id"]
            assert (await post(f"candidates/{identifier}/accept", token=token)).status_code == 200
            replay_id = uuid4()
            assert (
                await post(f"credentials/{identifier}/reveal", password, token, replay_id)
            ).json()["secret"] == "protected-secret"
            assert (await post("lock")).status_code == 200
            assert (
                await post(f"credentials/{identifier}/reveal", password, token, replay_id)
            ).status_code == 423
            token = (await post("unlock", password)).json()["token"]
            other = await client.post(
                "/api/v1/workspaces/",
                json={"name": "Other"},
                headers={"X-Request-ID": str(uuid4())},
            )
            switched = await client.post(
                f"/api/v1/workspaces/{other.json()['id']}/activate",
                headers={"X-Request-ID": str(uuid4())},
            )
            assert switched.status_code == 200
            assert not app.state.vault._sessions
            assert (await post("export", password, token)).status_code == 423
            assert "protected-secret" not in repr(list(app.state.events.recent))
        async with await app.state.workspaces.lease(scope) as lease:
            async with lease.sessions() as session:
                config = (await session.scalars(select(VaultConfig))).one()
                assert len(config.salt) == 32 and config.kdf == "Argon2id"
                assert config.parameters == {
                    "memory_cost": 19456,
                    "time_cost": 2,
                    "parallelism": 1,
                    "length": 32,
                }
    assert not any(b"protected-secret" in path.read_bytes() for path in tmp_path.rglob("*.db"))
