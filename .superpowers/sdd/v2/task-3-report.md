# Slice 3: workspace persistence and targets

Status: implemented and verified in the owned files. Root owns application factory,
authentication, lifespan, jobs/events endpoint integration and the platform helper.
No GUI, vault encryption, report rendering, external targets or publication were added.

## Interfaces for root

```python
from backend.database import SQLAlchemyMutationStore, WorkspaceStartupError
from backend.services.workspace_service import (
    WorkspaceService, WorkspaceConflictError, WorkspaceNotFoundError,
)
from backend.routers.workspaces import router as workspace_router
from backend.routers.targets import router as target_router

workspaces = WorkspaceService(profile)
await workspaces.start()
mutations = MutationCoordinator(SQLAlchemyMutationStore(workspaces.catalog_sessions))
app.state.workspaces = workspaces
app.state.mutations = mutations
app.state.events = events
app.include_router(workspace_router, prefix="/api/v1")
app.include_router(target_router, prefix="/api/v1")
# Shutdown must drain jobs and their cleanup before:
await workspaces.close()
```

`WorkspaceService` exposes `active_id: UUID`, `catalog_engine`,
`catalog_sessions`, async `start/close/list/create/get/activate/delete/lease`,
and `get_notes/set_notes`. `create` takes `shared.workspaces.WorkspaceCreate`.
`lease(workspace_id=None)` returns a `WorkspaceLease` with `workspace_id`,
`engine`, `sessions` and idempotent async `release`; it is also an async context
manager. Capture `active_id` before submitting a job and use its lease cleanup.
`close` rejects outstanding references instead of disposing an engine in use.

`SQLAlchemyMutationStore` takes an `async_sessionmaker[AsyncSession]` from the
catalog. It implements `get/reserve/finish` against the root `MutationRecord`.
Reservation is an atomic unique insert; finishing requires matching operation
and fingerprint. Pending/unknown records read as unknown after restart. Request
bodies never reach the store. Records are retained after workspace deletion.
Catalog create/delete/activate use `UUID(int=0)`; target requests capture the
active workspace before any await. Activation captures its former selection for
the event but omits it from the fingerprint so replay remains stable.

Map `WorkspaceConflictError` to 409, `WorkspaceNotFoundError` to 404 and ordinary
validation/parsing `ValueError` to safe 422. Short aliases `WorkspaceConflict` and
`WorkspaceNotFound` are available. Root maps mutation exceptions separately.
Every mutation endpoint requires UUID `X-Request-ID`; routes reconstruct strict
DTOs from JSON-safe coordinator replay. Events use root `EventHub.publish`:
`workspace-created`, `workspace-activated`, `workspace-deleted`, `target-transfer`.

## Storage and migrations

Catalog lives at `profile/catalog.db`. Each workspace uses exactly
`profile/workspaces/<uuid>/data.db`; display names never become paths.
UUID existence is validated before constructing paths for existing workspaces.
Directories and database files use platform owner-only protections. Deletion
uses root's `remove_private_tree(path, root)` after active/reference checks.
Engine caches contain stable session factories and reference counts; switching
selection changes no existing lease.

ORM catalog and workspace metadata are separate. Catalog holds identities,
selection with an enforced same-file FK, and mutation outcomes without a
workspace FK/cascade. Workspace schema contains targets and notes, framework
identity, explicit remote session/job associations, favorites/recent history,
redacted-only console history, future KDF/check and encrypted credential fields,
and report/artifact metadata. Same-file relationships/indexes are documented.
There are no cross-file foreign keys. Root's binding interface places replay
outcomes in the catalog so deleting a workspace cannot erase request history.

Alembic revision `0001` has explicit frozen DDL for both scopes. Python resources
in `backend.repositories.migrations` ship with the package; startup materializes
them using `importlib.resources` and runs `upgrade head` inside
`AsyncConnection.run_sync`. `alembic.ini` points to these scripts. No `create_all`
is used. Explicit SQLite BEGIN makes DDL, data updates and revision stamping
transactional; foreign keys are on, busy timeout is 5000ms and journal mode is
DELETE. Corrupt bytes and malformed catalog identities produce actionable local
startup errors, preserving databases and disposing failed-start engines.

## Target behavior

Dedicated extra-forbid DTOs in `shared/workspaces.py` implement workspace name
1–100, description/notes at most 100000, hostname at most 253, ports 1–65535
with TCP/UDP, status enum and per-target port lists at most 1024. IPv4 validation
uses the preserved `toolkit.security` policy; numeric/legacy, IPv6, 0/8,
multicast, reserved and link-local targets are rejected, ordinary public and
loopback targets are accepted. CIDR uses the preserved strict subnet policy and
at most 256 addresses; host expansion and insertion are all-or-nothing.

CRUD, status/query filtering, atomic bounded Nmap upload, and JSON/CSV/Nmap XML
exports are implemented. Nmap input is limited to 25 MiB, UTF-8, 4096 hosts and
1024 port entries per host. DTD/entity declarations and NUL-based alternate
encodings are rejected before parsing. All malformed address/port/document
errors reject the full import. XML exports escape attributes; CSV uses proper
quoting and makes formula prefixes inert. Exports contain target fields only,
never vault/credential/artifact storage. Static routes precede UUID routes.

## Verification

Tests run in the pinned `.venv` using native Python with approved escalation,
`TEMP/TMP` set to `work/tmp`. They use real private SQLite databases, explicit
ASGI lifespan and HTTPX ASGITransport; no network scan is dispatched.

Commands:

```powershell
.venv/Scripts/python.exe -m pytest tests/v2/test_workspaces.py -q
.venv/Scripts/python.exe -m ruff check backend/database.py backend/models backend/repositories backend/services backend/routers shared/workspaces.py tests/v2/test_workspaces.py
.venv/Scripts/python.exe -m black --check backend/database.py backend/models backend/repositories backend/services backend/routers shared/workspaces.py tests/v2/test_workspaces.py
.venv/Scripts/python.exe -m mypy backend/database.py backend/models backend/repositories backend/services backend/routers shared/workspaces.py
.venv/Scripts/python.exe -m pytest -q
```

Final owned suite: **20 passed**. Ruff clean; Black unchanged; strict Mypy:
**no issues in 14 production files**. Full suite before the final corrupt-UUID
startup test/fix and before root factory integration: **125 passed, 2 skipped,
50 subtests passed**, one upstream StarletteDeprecationWarning from the preserved
TestClient usage. Root factory integration was being edited when this slice
finished; root will perform final integrated suite verification.

Observed initial red: missing workspace persistence assertion. During
implementation SQLAlchemy 2.1 required its asyncio extra; root changed the pinned
dependency to `sqlalchemy[asyncio]==2.1.3` and installed greenlet 3.5.6. No other
dependency was added. Observed additional red→green regression: corrupt catalog
UUID previously raised a raw ValueError; it now gives WorkspaceStartupError and
preserves the original workspace DB.

Coverage includes switch/lease engine immutability, active/leased deletion
protection, idempotent lease release and close protection, restart identities
and notes, catalog mutation replay/conflicts/header enforcement, target CRUD and
filtering, unsupported/public IPv4, duplicate update rollback, atomic bulk/import
rollback, escaped exports/transfer events, captured workspace operations after
selection change, concurrent SQL reservation, unknown replay across restart,
conditional mutation completion, corrupt byte/identity preservation, UUID/path
validation and actual DDL/data/revision rollback on injected migration failure.

## Concerns / remaining integration

- Root must keep jobs' cleanup before `workspaces.close()` and install the shared
  router/error/event hooks described above. This slice did not alter main.py.
- Root was notified that Windows directory protection should inherit owner-only
  grants to newly created SQLite rollback journal children; DB files themselves
  are explicitly protected before connection. The platform adapter is root-owned.
- Deletion commits catalog removal before recursive filesystem cleanup. A rare
  cleanup failure preserves recoverable orphan data and fails the mutation as
  uncertain rather than leaving a catalog identity pointing to erased data.
  No automatic orphan deletion or destructive migration recovery is attempted.
- Future vault/report/session consumers must enforce ciphertext-only and
  redacted-only write contracts; this slice defines their storage metadata and
  relationships without implementing those later features.
