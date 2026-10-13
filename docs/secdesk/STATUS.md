# SecDesk delivery status

Source candidate: 2.2.0. Published installers remain 2.1.0; this work does not silently replace or publish them. LowREA remains a separate unfinished integration.

Implemented: ten strict manifests; bundled educational guides; JSON-schema validation; passive local doctor and a visible startup checklist; manifest-driven cards and seven-section details; existing Metasploit page links; explicit ownership acknowledgment; four owned native sessions with workspace leases; Windows ConPTY and Linux OS PTY helper; input/resize/stop, bounded screen output, redacted readiness failures; durable UTC launch acknowledgments; explicit HTTPS web-console navigation; USB-serial metadata and a pluggable firmware transport; redacted, deduplicated workspace findings imports and existing HTML/PDF report summaries; keyboard labels, tooltips and terminal focus isolation. Native processes never follow startup checks automatically.

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
