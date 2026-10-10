# Adding a tool

V2 keeps ordinary analysis functions in `toolkit/modules/`, backend registrations
in `backend/tools/`, shared schemas in `shared/tools.py`, and Qt views under
`frontend/views/tools/`. GUI views call ViewModels and authenticated APIs, never
analysis functions directly. Use the Caesar implementation as the smallest example.

1. Add pure analysis/result types and `MODULE = ModuleSpec(id, title, order, create_panel)`
   in `toolkit/modules/example.py`. Factories lazily import the Qt view and accept
   `ToolsViewModel`. Keep identifiers unique and stable. Missing optional imports
   must produce an actionable readiness message.
2. Add a validated options schema/discriminator to the shared tool-options union.
   Bound strings, arrays and input size. Secrets use explicit transport serialization
   and never enter ordinary model representations or persisted replay records.
3. Add `backend/tools/example.py` exporting `TOOL = ToolSpec(...)`. Its async run
   callback receives ordinary options, optional file bytes, a display filename and
   `JobContext`; return JSON-compatible results. Use `context.run_sync` for blocking
   analysis and `context.check()`/`context.progress()` for cancellation/progress.
   A custom callback can call its own analysis function; existing seven registrations
   delegate to `ToolService.analyze`. No filesystem path supplied by a client becomes
   a managed storage identity.
4. Add a panel to the frontend factory in `frontend/views/tools/__init__.py`, reusing
   `ToolPanel` and `ToolsViewModel` request/progress handling. Capture workspace and
   input values at submission. Discard stale responses after edits or switches.
5. Add controlled fixtures covering analysis, schema bounds, missing dependencies,
   cancellation and navigation. Enforce network restrictions in analysis functions
   before any network operation. Require independent review for new security boundaries.

Both loaders discover registrations automatically. The PyInstaller spec collects
the discovered module packages on rebuild; it does not download extensions at runtime.
Place text resources in `toolkit/resources/` and access them through the resource
helpers in `toolkit/core.py`, independent of the working directory. Additional resource
types may require updating package-data and the spec.

Saved captures cross the separate worker boundary documented in
[SCAPY_WORKER.md](SCAPY_WORKER.md). Do not import Scapy into the desktop to implement
a new capture feature. Keep that standalone JSONL contract versioned.
