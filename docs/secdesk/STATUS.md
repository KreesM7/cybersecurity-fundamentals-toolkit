# SecDesk delivery status

Source candidate: 2.2.0. Published installers remain 2.1.0; this work does not silently replace or publish them. LowREA remains a separate unfinished integration.

Implemented: ten strict manifests; bundled educational guides; JSON-schema validation; passive local doctor and a visible startup checklist; manifest-driven cards and seven-section details; existing Metasploit page links; four owned native sessions with workspace leases; Windows ConPTY and Linux OS PTY helper; input/resize/stop, bounded screen output, redacted readiness failures; durable UTC launch records; explicit HTTPS web-console navigation; USB-serial metadata and a pluggable firmware transport; redacted, deduplicated workspace findings imports and existing HTML/PDF report summaries; keyboard labels, tooltips and terminal focus isolation. Native processes never follow startup checks automatically.

## Milestone record

| Milestone | Verified implementation | Unverified / known limits | Next |
| --- | --- | --- | --- |
| M0 | Manifest contracts, passive discovery, missing-resource isolation, authenticated API and owned supervision | Native vendor installations are not established by controlled fixtures | Verify on configured tool deployments |
| M1 | Tool grid/details and real Windows/Linux terminal input, resize, normal exit and cancellation | Terminal is a monochrome VT viewport, without scrollback, mouse integration or guaranteed full xterm behavior; macOS runtime unverified | Native CLI workflow captures |
| M2 | Four commercial tools have linked HTTPS consoles and visible Not detected license badges; requests are acknowledged locally | No license API, service health or remote management is claimed; credentials stay in the existing vault/vendor login flow | Deployment-specific service/license adapters |
| M3 | Legacy NetStumbler guidance, advisory netsh substitute and local checklist | Modern NetStumbler compatibility unknown; no adapter/capture permissions inferred from executable presence | Test a compatible host/adapter |
| M4 | Burp education; passive serial metadata; real transport adapter interface with bounded writes/reads and fail-closed authorization | No Burp edition/native shortcut verified; firmware protocol, VID/PID and capabilities not supplied; all device actions disabled, as agreed | Supply firmware specification and matching device |
| M5 | Primary/vendor research and documented community/competitor gap review | Research samples are not representative demand | User selected keeping current scope; no extras added |
| M6 | Existing workspace/vault/report infrastructure reused; local audit; explicit findings import, deduplication/redaction and report summaries; keyboard navigation | Raw vendor outputs are not guessed into findings; only normalized JSON/CSV supported. No custom animation is used, so reduced-motion users receive static transitions | Native/deployment verification and vendor-specific import formats |

Rulings: reuse PyQt6/FastAPI instead of Tauri because existing tested packaging, auth, vault, workspaces and Metasploit ownership should not be duplicated. Cost: no new web/xterm shell. Startup remains passive to honor explicit visible action and no silent target operations. Cost: versions/services/permissions/licenses remain unknown until checked in the native tool or vendor console. Normalize only explicit records rather than infer vulnerabilities from terminal text. Cost: vendor exports may need conversion. Firmware actions remain disabled until the real protocol is supplied; no wire command is guessed.

## Verification (2026-10-13)

- Windows: `python -m pytest --cov --cov-report=xml --cov-report=term -v` — 425 passed, 8 skipped, 50 subtests passed; 80.60% coverage (75% gate preserved). One existing Starlette/httpx test-client deprecation warning; no new lint/type warnings.
- Linux (dedicated Toolkit-MSF test environment): SecDesk registry, native terminal and workflow suites — 30 passed. Controlled Python/shell fixtures only; no security targets or captures.
- Black check (221 files), Ruff, strict mypy (148 source files) for Windows and Linux, and `uv lock --check` — passed.
- Windows `PyInstaller toolkit.spec` — passed. Source and frozen `--self-test` — 18 panels and all ten manifests loaded; frozen run used a different working directory and a disposable profile.
- Build inventory — 67 actual bundled Windows distributions recorded in local candidate evidence; original published 2.1.0 inventories remain unchanged.
- Independent read-only runtime review — three ownership/session race findings fixed. Reviewer independently ran 22 focused tests, including GUI descendants after parent exit and monitor cancellation before start; no remaining actionable blocker in those fixes.
- Real Qt screenshots inspected for grid/details, semantic license/idle badges and documentation/launch layout. No decorative image assets added.

Release and deployment limits remain as listed above. No 2.2.0 installer was published, no vendor deployment/license was verified, and no firmware command was sent. Production profiles/vaults were not migrated in these checks.

Final follow-up: interface-specific discovery supports headless TShark without the GUI binary. Windows and Linux SecDesk suites each passed 32 tests. Container cleanup distinguishes exited zombies from live children; Docker's test process uses an init reaper. The report fixture awaits the existing job-completion API with a bounded timeout, rather than asserting a two-second shared-runner disk-speed limit. Production report behavior and functional/redaction assertions remain unchanged.

## Direct action update

Run, Generate and Launch now submit directly, without ownership checkboxes or required ownership fields. Legacy acknowledgment fields remain accepted for client compatibility but are not enforcement gates. Audit records retain a supplied legacy acknowledgment; new requests do not fabricate one. Removed disclaimer documents, policy-based feature exclusions and name-based manifest bans. Adding a manifest no longer fails startup verification merely because the registry grows beyond ten tools. Actual OS privileges, missing providers, input validation, resource budgets, cancellation, credential protections and update verification still describe implementation behavior.

Verified direct-action update: Windows full suite 432 passed, 8 skipped, 50 subtests passed; coverage 80.75%. Linux direct-action/native/UI subset 45 passed. Black, Ruff and strict mypy for Windows/Linux passed; Windows build and source/frozen startup each loaded all 18 panels. Independent review findings were fixed and rereview found no blocker. Auth/TLS/bootstrap/target-validation files and module-option validation remain unchanged.
