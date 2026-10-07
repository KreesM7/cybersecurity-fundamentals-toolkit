# Slice 3 integration report
Root integration commit d5c8b3f, service commit a2affb7, mutation coordinator f8ca1dd. Review base1b1d625.

Factory now owns authentication on every HTTP path and authenticated WS handshakes, private Swagger/OpenAPI bearer documentation, workspace lifespan, durable non-secret mutations and memory-only secret tracking, two active/32 queued jobs, cancellation/draining, clear-result API, bounded256 event fanout and100 recent events with redaction before retention. Request bodies are bounded before parsing. Validation errors omit raw inputs/messages/context. Job events contain metadata only. Shutdown drains workers before closing workspace engines. Existing frontend WSS can use /ws paths and still rejects redirects.

Windows regression reproduced SQLite-created child inheriting exposed default DACL; directory owner ACE now OICI while explicit files retain owner-only grants. Child-file regression passes. Safe workspace deletion helper checks resolved containment, links/reparse, ownership, and all descendants before removal.

TDD: initial three core API tests failed (404/missing lifecycle). After integration pass. New private-directory child test failed with PermissionError before OICI fix, then passes. Full v2 test run initially82total with two WS failures from global HTTPBearer dependency; resolved by documenting bearer in PrivateAPI.openapi rather than applying HTTP-only dependency to WS, and explicit WS paths preserve future fixtures/channels.

Verification: .venv/Scripts/python.exe -m pytest tests/v2 -q =>82passed,1skipped(Windows symlink privilege),2subtests,1upstream StarletteDeprecationWarning about test-only httpx compatibility. Final PrivateAPI refactor covering tests/v2/test_api_core.py =>4passed samewarning. Black check44filesclean; Ruff backend/frontend/shared/tests/v2 clean; strict mypy backend/frontend/shared34filesclean. Native runtime needs approved escalation here; project TEMP/TMP. No implementation/release claims beyond these slices. The warning is retained as evidence for CI/tooling cleanup, not hidden.

Self review: validation payloads do not appear in error responses; GET job scopes checked; request IDs replay outcomes; delete clears input closures/results; process shutdown closes owned workers and then storage. Planned later tool, MSF, vault/report, GUI integration and final security review are not in this gate.

## Review repair round 1

Fixed the three independent review findings in owned jobs/redaction/main files. Cancellation now shares one owned cancellation task per record, shields native-worker draining and cleanup from repeated cancellation, and retains active slots until cleanup completes. Concurrent clear callers erase the captured record safely; shutdown snapshots records so concurrent clears cannot invalidate its lookup. Already-finishing successful work is drained without interrupting cleanup. Record eviction now requires completed cleanup. The two-active/32-queued contract and original workspace association remain covered.

Registered secrets and console patterns are removed before the 10,000-character output bound, so both secrets crossing that boundary and maximum-length 65,536-character registered secrets are safe before queue/history retention. Inspection found the same pre-truncation issue in JobContext.progress's 1,000-character limit; it now redacts before that shorter limit too.

The WS route independently watches subscription closure while transport sending is blocked. Overflow cancels and joins the sender/receiver, attempts code 1013 with REST-resynchronization guidance, bounds a stalled close attempt to one second, and joins all connection tasks. The actual ASGI-route regression gates transport send and optionally close, and checks that no new asyncio tasks remain.

Root-requested fourth fix: the installed FastAPI 0.142.2 source defaults tracing, metrics, logs, operation_spans and auto_configure to true and can configure exporters from the environment. The factory now explicitly disables all five before any request. Its regression checks the resulting configuration and disabled native telemetry. No exporter or SDK dependency was added.

Observed RED evidence before each corresponding fix:
- Initial focused command below: 5 failed, 12 passed, 1 retained upstream warning. Failures: premature cleanup while a gated native thread remained active; boundary secret and 65,536-character secret subtests; stalled WebSocket send with normal and stalled close variants.
- Additional shutdown-caller cancellation regression: 1 failed, 6 passed; shutdown returned while cleanup remained gated.
- Factory telemetry regression: 1 failed, 6 deselected; default tracing was true.
- Progress-boundary regression: 1 failed, 3 deselected; retained progress exposed the secret prefix.

Final Windows checks (approved project .venv/Scripts/python.exe; TEMP/TMP=work/tmp; QT_QPA_PLATFORM=offscreen):
- `python -m pytest tests/v2/test_events_jobs.py tests/v2/test_redaction.py tests/v2/test_api_core.py -q --tb=short`: 18 passed, 2 subtests passed, 1 upstream StarletteDeprecationWarning, 3.48 seconds.
- `python -m black --check backend/jobs.py backend/redaction.py backend/main.py tests/v2/test_events_jobs.py tests/v2/test_redaction.py tests/v2/test_api_core.py`: six files unchanged.
- `python -m ruff check` with those same six paths: all checks passed.
- `python -m mypy --strict backend/jobs.py backend/redaction.py backend/main.py`: no issues in three source files.

Broader verification is explicitly not green: `python -m pytest -q --tb=short` finished with 1 failed, 135 passed, 2 skipped, 52 subtests passed, 1 warning in 76.82 seconds. Root subsequently directed separate legacy PySide6 and v2 PyQt6 processes. Fresh `python -m pytest tests/v2 -q --tb=short` still had 1 failed, 87 passed, 1 skipped, 4 subtests passed, 1 warning in 23.66 seconds (before the final added progress regression). Both failures were `tests/v2/test_live_tls.py::LiveTLS::test_fresh_profile_https_wss_identity_and_clean_shutdown`: httpx.ConnectTimeout at backend/bootstrap.py:207 during wait_ready. Inspection confirms wait_ready catches ConnectError and ReadError but not ConnectTimeout despite its overall startup budget. This unchanged bootstrap issue was handed back to root; no bootstrap file was edited and no success was inferred by discarding the failed runs. The upstream Starlette warning remains unsuppressed for the planned compatibility cleanup. No release claim is made.
