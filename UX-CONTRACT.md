# Native desktop interaction contract

Canonical owners: theme/spacing (`frontend/theme.py`), icons (`frontend/icons.py`),
navigation (`Navigation`), fields/help and status (`presentation.py`), background
requests (`AppViewModel` / `ToolsViewModel`), jobs/cancellation (`JobManager`).

| Capability | Canonical owner | Source of truth | Allowed variants | Verification |
|---|---|---|---|---|
| Table Selection | Qt trees/tables | presentation.py + view model | Local row activation and scroll | navigation, long content, keyboard |
| Select/Listbox | QComboBox | theme.py + shared schemas | Native platform popup | keyboard and open popup |
| Form | Qt fields | shared Pydantic schemas | Per-tool typed fields | validation, no submitted-secret echo |
| Scrollbar | Qt scroll areas | shared theme templates | Native geometry | dark/light/narrow layout |
| Toast | StatusBadge + Qt status bar | presentation.py | Inline corrections and update message | pending/success/failure/unknown |
| CRUD | Existing workspace panels | AppViewModel + backend services | Local workspace data/export | tests/v2/test_workspaces.py |

Actions keep the same names everywhere. `Inspect file` uses the selected file; busy
controls prevent duplicate submission and Cancel remains available. Clear removes
memory results. Workspace changes never show another workspace's analysis. Prior jobs
remain associated with their original workspace. Next/Previous inspects a new window
and checks the previous artifact SHA-256 before joining observations.

Use native QWidget/QPushButton semantics, accessible names/tooltips, visible focus,
plain text for data, and no hover-only actions. Empty/error states give a next action.
User passwords remain masked; commands are neither echoed nor recorded. Authentication,
vault encryption, private TLS and verified installation retain their existing owners.

This is a native desktop, not a DOM application: ARIA, URLs for form state, web CSS,
browser dialogs and browser-runner checks have native Qt equivalents. No telemetry or
new decorative animation is added. The informational legal notice requires no checkbox.
