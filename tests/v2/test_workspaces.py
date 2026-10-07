"""Workspace isolation, migration recovery and target boundaries against real SQLite/ASGI."""

import asyncio
import hashlib
import importlib.util
from contextlib import asynccontextmanager
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


def load_service():
    try:
        found = importlib.util.find_spec("backend.services.workspace_service")
    except ModuleNotFoundError:
        found = None
    assert found is not None, "Workspace persistence is missing"
    from backend.services.workspace_service import WorkspaceService

    return WorkspaceService


@pytest.fixture
async def runtime(tmp_path):
    service_type = load_service()
    from backend.database import SQLAlchemyMutationStore
    from backend.events import EventHub
    from backend.mutations import MutationConflictError, MutationCoordinator, UnknownOutcomeError
    from backend.routers.targets import router as targets
    from backend.routers.workspaces import router as workspaces
    from backend.services.workspace_service import WorkspaceConflict, WorkspaceNotFound

    @asynccontextmanager
    async def lifespan(app):
        app.state.workspaces = service_type(tmp_path)
        await app.state.workspaces.start()
        app.state.mutations = MutationCoordinator(
            SQLAlchemyMutationStore(app.state.workspaces.catalog_sessions)
        )
        app.state.events = EventHub()
        yield
        await app.state.events.close()
        await app.state.workspaces.close()

    app = FastAPI(lifespan=lifespan)
    app.include_router(workspaces, prefix="/api/v1")
    app.include_router(targets, prefix="/api/v1")

    async def conflict(request: Request, exc: Exception):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    async def missing(request: Request, exc: Exception):
        return JSONResponse({"detail": str(exc)}, status_code=404)

    async def invalid(request: Request, exc: Exception):
        return JSONResponse({"detail": str(exc)}, status_code=422)

    for kind in (WorkspaceConflict, MutationConflictError, UnknownOutcomeError):
        app.add_exception_handler(kind, conflict)
    app.add_exception_handler(WorkspaceNotFound, missing)
    app.add_exception_handler(ValueError, invalid)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://localhost"
        ) as client:
            yield app, client


def request_id():
    return {"X-Request-ID": str(uuid4())}


async def test_workspace_restart_keeps_active_identity_notes_and_original_lease(tmp_path):
    service = load_service()(tmp_path)
    from backend.services.workspace_service import WorkspaceConflict
    from shared.workspaces import WorkspaceCreate

    await service.start()
    original = service.active_id
    lease = await service.lease()
    created = await service.create(WorkspaceCreate(name="../../name", description="preserved"))
    await service.activate(created.id)
    assert lease.workspace_id == original
    second_lease = await service.lease(created.id)
    assert lease.engine is not second_lease.engine
    with pytest.raises(WorkspaceConflict):
        await service.delete(original)
    with pytest.raises(WorkspaceConflict):
        await service.delete(created.id)
    await service.set_notes(created.id, "A note")
    await lease.release()
    await service.delete(original)
    assert not (tmp_path / "workspaces" / str(original)).exists()
    # close checks outstanding leases; callers must release before disposing.
    await second_lease.release()
    await service.close()
    restarted = load_service()(tmp_path)
    await restarted.start()
    assert restarted.active_id == created.id
    assert await restarted.get_notes(created.id) == "A note"
    assert (await restarted.get(created.id)).description == "preserved"
    assert (tmp_path / "workspaces" / str(created.id) / "data.db").exists()
    assert not (tmp_path / "name").exists()
    await restarted.close()


async def test_workspace_routes_replay_catalog_mutations_and_require_request_ids(runtime):
    app, client = runtime
    listing = (await client.get("/api/v1/workspaces/")).json()
    assert len(listing) == 1 and listing[0]["active"]
    headers = request_id()
    response = await client.post("/api/v1/workspaces/", json={"name": "second"}, headers=headers)
    assert response.status_code == 201
    identifier = response.json()["id"]
    replay = await client.post("/api/v1/workspaces/", json={"name": "second"}, headers=headers)
    assert replay.json() == response.json()
    assert len((await client.get("/api/v1/workspaces/")).json()) == 2
    assert (
        await client.post("/api/v1/workspaces/", json={"name": "other"}, headers=headers)
    ).status_code == 409
    assert (await client.post("/api/v1/workspaces/", json={"name": "missing"})).status_code == 422
    assert (
        await client.post(f"/api/v1/workspaces/{identifier}/activate", headers=request_id())
    ).status_code == 200
    assert app.state.workspaces.active_id == UUID(identifier)
    assert (
        await client.delete(f"/api/v1/workspaces/{identifier}", headers=request_id())
    ).status_code == 409
    assert (await client.get(f"/api/v1/workspaces/{uuid4()}")).status_code == 404
    assert (
        await client.put(
            f"/api/v1/workspaces/{identifier}/notes", json={"notes": "hello"}, headers=request_id()
        )
    ).json()["notes"] == "hello"
    assert (await client.get(f"/api/v1/workspaces/{identifier}/notes")).json()["notes"] == "hello"


async def test_targets_filter_update_export_transfer_and_delete(runtime):
    app, client = runtime
    body = {
        "address": "8.8.8.8",
        "hostname": "dns.example",
        "notes": "<quoted>,note",
        "ports": [{"port": 53, "protocol": "udp", "service": "domain"}],
    }
    added = await client.post("/api/v1/targets/", json=body, headers=request_id())
    assert added.status_code == 201
    identifier = added.json()["id"]
    changed = await client.patch(
        f"/api/v1/targets/{identifier}", json={"status": "open"}, headers=request_id()
    )
    assert changed.status_code == 200 and changed.json()["status"] == "open"
    assert (
        len(
            (await client.get("/api/v1/targets/", params={"status": "open", "query": "dns"})).json()
        )
        == 1
    )
    assert (await client.get("/api/v1/targets/", params={"status": "exploited"})).json() == []
    for format in ("json", "csv", "nmap"):
        export = await client.get("/api/v1/targets/export", params={"format": format})
        assert export.status_code == 200 and "8.8.8.8" in export.text
    nmap = await client.get("/api/v1/targets/export", params={"format": "nmap"})
    assert "&lt;quoted&gt;" not in nmap.text  # only Nmap fields are exported
    transfer = await client.post(
        f"/api/v1/targets/{identifier}/use-as-rhosts", headers=request_id()
    )
    assert transfer.json()["rhosts"] == "8.8.8.8"
    assert app.state.events.recent[-1].topic == "target-transfer"
    assert app.state.events.recent[-1].workspace_id == app.state.workspaces.active_id
    assert (
        await client.delete(f"/api/v1/targets/{identifier}", headers=request_id())
    ).status_code == 204
    assert (await client.get(f"/api/v1/targets/{identifier}")).status_code == 404


@pytest.mark.parametrize(
    "address",
    [
        "::1",
        "0.1.2.3",
        "224.0.0.1",
        "255.255.255.255",
        "169.254.1.1",
        "127.1",
        "2130706433",
        "01.2.3.4",
    ],
)
async def test_target_rejects_unsupported_address_without_insert(runtime, address):
    _, client = runtime
    response = await client.post(
        "/api/v1/targets/", json={"address": address}, headers=request_id()
    )
    assert response.status_code == 422
    assert (await client.get("/api/v1/targets/")).json() == []


async def test_bulk_and_nmap_validation_is_atomic_and_bounded(runtime):
    _, client = runtime
    assert (
        await client.post(
            "/api/v1/targets/bulk", json={"cidr": "192.168.4.0/23"}, headers=request_id()
        )
    ).status_code == 422
    bulk = await client.post(
        "/api/v1/targets/bulk", json={"cidr": "192.168.4.0/30"}, headers=request_id()
    )
    assert bulk.status_code == 201 and len(bulk.json()) == 2
    duplicate = await client.post(
        "/api/v1/targets/bulk", json={"cidr": "192.168.4.0/29"}, headers=request_id()
    )
    assert duplicate.status_code == 409
    assert len((await client.get("/api/v1/targets/")).json()) == 2
    xml = (
        b'<nmaprun><host><address addr="8.8.4.4" addrtype="ipv4"/>'
        b'<hostnames><hostname name="dns.example"/></hostnames><ports>'
        b'<port protocol="tcp" portid="443"><state state="open"/>'
        b'<service name="https"/></port></ports></host></nmaprun>'
    )
    result = await client.post(
        "/api/v1/targets/import/nmap", files={"file": ("scan.xml", xml)}, headers=request_id()
    )
    assert result.status_code == 201 and result.json()[0]["ports"][0]["port"] == 443
    invalid = xml.replace(b"8.8.4.4", b"224.0.0.1")
    for malformed in (
        invalid,
        b'<!DOCTYPE nmaprun [<!ENTITY x "boom">]><nmaprun/>',
        b"<nmaprun>",
        b"x" * (25 * 1024 * 1024 + 1),
    ):
        assert (
            await client.post(
                "/api/v1/targets/import/nmap",
                files={"file": ("bad.xml", malformed)},
                headers=request_id(),
            )
        ).status_code == 422
    assert len((await client.get("/api/v1/targets/")).json()) == 3


async def test_sql_mutations_survive_restart_and_unknown_outcome(tmp_path):
    service_type = load_service()
    from backend.database import SQLAlchemyMutationStore
    from backend.mutations import MutationCoordinator, MutationRecord

    service = service_type(tmp_path)
    await service.start()
    scope, request, pending = service.active_id, uuid4(), uuid4()
    store = SQLAlchemyMutationStore(service.catalog_sessions)
    calls = 0

    async def action():
        nonlocal calls
        calls += 1
        return {"result": "durable"}

    assert await MutationCoordinator(store).execute(scope, request, "test", {}, action) == {
        "result": "durable"
    }
    await store.reserve(MutationRecord(scope, pending, "test", "unused", "pending"))
    await service.close()
    service = service_type(tmp_path)
    await service.start()
    store = SQLAlchemyMutationStore(service.catalog_sessions)
    assert await MutationCoordinator(store).execute(scope, request, "test", {}, action) == {
        "result": "durable"
    }
    assert calls == 1
    assert (await store.get(scope, pending)).state in ("pending", "unknown")
    await service.close()


async def test_corrupt_catalog_fails_actionably_without_erasing_bytes(tmp_path):
    from backend.platform_utils import atomic_private_write

    service_type = load_service()
    data = b"not a database; preserve this evidence"
    atomic_private_write(tmp_path / "catalog.db", data)
    service = service_type(tmp_path)
    with pytest.raises(RuntimeError, match="catalog.*repair|catalog.*restore"):
        await service.start()
    assert (tmp_path / "catalog.db").read_bytes() == data
    await service.close()


async def test_target_mutations_keep_captured_workspace_across_selection_switch(runtime):
    app, client = runtime
    from backend.services.target_service import TargetService
    from shared.workspaces import TargetCreate

    original = app.state.workspaces.active_id
    target_service = TargetService(app.state.workspaces, original)
    created = await client.post("/api/v1/workspaces/", json={"name": "other"}, headers=request_id())
    other = created.json()["id"]
    await client.post(f"/api/v1/workspaces/{other}/activate", headers=request_id())
    await target_service.create(TargetCreate(address="127.0.0.1"))
    assert (await client.get("/api/v1/targets/")).json() == []
    await client.post(f"/api/v1/workspaces/{original}/activate", headers=request_id())
    assert (await client.get("/api/v1/targets/")).json()[0]["address"] == "127.0.0.1"


async def test_persistent_pending_record_never_dispatches_and_store_insert_is_atomic(tmp_path):
    service = load_service()(tmp_path)
    from backend.database import SQLAlchemyMutationStore
    from backend.mutations import (
        MutationConflictError,
        MutationCoordinator,
        MutationRecord,
        UnknownOutcomeError,
    )

    await service.start()
    store = SQLAlchemyMutationStore(service.catalog_sessions)
    scope, identifier = service.active_id, uuid4()
    fingerprint = hashlib.sha256(b"{}").hexdigest()
    pending = MutationRecord(scope, identifier, "test", fingerprint, "pending")
    assert sorted(await asyncio.gather(store.reserve(pending), store.reserve(pending))) == [
        False,
        True,
    ]
    await service.close()
    service = load_service()(tmp_path)
    await service.start()
    store = SQLAlchemyMutationStore(service.catalog_sessions)

    async def must_not_run():
        pytest.fail("A pending mutation must never dispatch again")

    with pytest.raises(UnknownOutcomeError):
        await MutationCoordinator(store).execute(scope, identifier, "test", {}, must_not_run)
    with pytest.raises(MutationConflictError):
        await store.finish(MutationRecord(scope, identifier, "different", fingerprint, "complete"))
    assert (await store.get(scope, identifier)).state == "unknown"
    await service.close()


async def test_failed_migration_rolls_back_ddl_and_preserves_previous_tables(tmp_path, monkeypatch):
    from sqlalchemy import text

    import backend.database as database

    engine = database.private_engine(tmp_path / "data.db")
    await database.migrate(engine, "workspace")
    async with engine.begin() as connection:
        await connection.execute(text("INSERT INTO notes (id,text) VALUES (1,'keep')"))

    def broken_upgrade(connection, scope):
        connection.exec_driver_sql("CREATE TABLE should_roll_back (id INTEGER)")
        connection.exec_driver_sql("UPDATE notes SET text = 'lost'")
        raise RuntimeError("injected upgrade failure")

    monkeypatch.setattr(database, "_upgrade", broken_upgrade)
    with pytest.raises(database.WorkspaceStartupError):
        await database.migrate(engine, "workspace")
    async with engine.connect() as connection:
        assert (await connection.execute(text("SELECT text FROM notes"))).scalar_one() == "keep"
        assert (
            await connection.execute(
                text("SELECT name FROM sqlite_master WHERE name='should_roll_back'")
            )
        ).first() is None
        assert (
            await connection.execute(text("SELECT version_num FROM alembic_version"))
        ).scalar_one() == "0001"
        assert (await connection.execute(text("PRAGMA foreign_keys"))).scalar_one() == 1
    await engine.dispose()


async def test_uuid_validation_creates_no_paths_and_close_rejects_leases(tmp_path):
    service = load_service()(tmp_path)
    from backend.services.workspace_service import WorkspaceConflictError, WorkspaceNotFoundError

    await service.start()
    before = set((tmp_path / "workspaces").iterdir())
    with pytest.raises(WorkspaceNotFoundError):
        await service.lease(uuid4())
    with pytest.raises(WorkspaceNotFoundError):
        await service.get("../../outside")
    assert set((tmp_path / "workspaces").iterdir()) == before
    lease = await service.lease()
    with pytest.raises(WorkspaceConflictError):
        await service.close()
    await lease.release()
    await lease.release()
    await service.close()


async def test_target_update_validation_and_duplicate_address_roll_back(runtime):
    _, client = runtime
    first = await client.post(
        "/api/v1/targets/", json={"address": "10.1.2.3"}, headers=request_id()
    )
    second = await client.post(
        "/api/v1/targets/", json={"address": "10.1.2.4"}, headers=request_id()
    )
    identifier = second.json()["id"]
    duplicate = await client.patch(
        f"/api/v1/targets/{identifier}",
        json={"address": "10.1.2.3", "notes": "must roll back"},
        headers=request_id(),
    )
    assert duplicate.status_code == 409
    persisted = (await client.get(f"/api/v1/targets/{identifier}")).json()
    assert persisted["address"] == "10.1.2.4" and persisted["notes"] == ""
    for change in (
        {"address": "224.0.0.1"},
        {"notes": None},
        {"ports": [{"port": 0, "protocol": "tcp"}]},
        {"unexpected": True},
    ):
        assert (
            await client.patch(f"/api/v1/targets/{identifier}", json=change, headers=request_id())
        ).status_code == 422
    assert (await client.get(f"/api/v1/targets/{first.json()['id']}")).status_code == 200


async def test_corrupt_catalog_identity_has_actionable_startup_state(tmp_path):
    import sqlite3

    from backend.database import WorkspaceStartupError

    service_type = load_service()
    service = service_type(tmp_path)
    await service.start()
    old_id = service.active_id
    await service.close()
    with sqlite3.connect(tmp_path / "catalog.db") as connection:
        connection.execute("UPDATE workspaces SET id='corrupt-uuid'")
        connection.execute("UPDATE selection SET workspace_id='corrupt-uuid'")
    service = service_type(tmp_path)
    with pytest.raises(WorkspaceStartupError, match="catalog.*repair|catalog.*restore"):
        await service.start()
    assert (tmp_path / "workspaces" / str(old_id) / "data.db").exists()
    await service.close()
