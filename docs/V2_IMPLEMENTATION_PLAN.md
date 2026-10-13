# Cybersecurity Fundamentals Toolkit v2.0.0 — Implementation Handoff

Status: approved requirements and implementation schedule. This document describes the v2 work to perform; it does not claim that v2 has been implemented or verified.

## 1. Summary and licensing decision

Upgrade the existing toolkit to a **PyQt6 frontend and local FastAPI backend**, preserving all seven tools, public-target support, and the compact flat interface. Add the Metasploit, workspace, vault, reporting, and automation features from the v2 brief.

The confirmed licensing decision is:

- Keep PyQt6 and python-nmap. Our source files retain MIT notices; the combined desktop distribution follows applicable GPLv3 terms because of these dependencies. [PyQt licensing](https://www.riverbankcomputing.com/software/pyqt/intro), [python-nmap licensing](https://pypi.org/project/python-nmap/0.7.1/)
- Keep Scapy in a separately installed, independently usable traffic-reader worker. Neither Scapy nor its runtime environment is included in the frozen desktop application.
- The Scapy separation addresses its GPL-2.0-only boundary; it does not remove the separate GPLv3 obligations above. Verify that boundary and the distribution inventory before publishing. Directly combining GPLv2-only and GPLv3 code is incompatible. [GNU compatibility guidance](https://www.gnu.org/licenses/gpl-faq.en.html#v2v3Compatibility)

Publish to **KreesM7/cybersecurity-fundamentals-toolkit**, with Windows x64 and Linux x86_64 installers, corresponding source, notices, and checksums.

## 2. Architecture and public interfaces

### Process and responsibilities

- Keep the GUI and FastAPI backend in one desktop process. Run Uvicorn in a dedicated QThread and frontend asynchronous clients in another.
- Reserve a socket bound to `127.0.0.1:0` and pass that socket to Uvicorn, avoiding port-selection races.
- Preserve `python -m toolkit` and the Windows launcher. Missing Metasploit, Scapy, Nmap, or libmagic components produce readiness messages without preventing startup.
- Views contain widgets and signal connections; ViewModels own client state; backend services own analysis, persistence, and external connections.
- Define Pydantic schemas once in a shared Python package. Centralize platform paths, executable discovery, WSL invocation, and subprocess handling in the platform adapter.
- Replace the widget-bearing extension contract with backend `ToolSpec` registrations and frontend panel factories sharing stable tool IDs. Preserve discovery, isolated loading failures, progress, cancellation, and bundled-resource access.

### Per-instance authentication

- Generate a fresh 256-bit token for each new backend instance using `secrets.token_hex(32)`.
- Atomically write a private JSON lock file containing schema version, PID, instance UUID, port, token, certificate fingerprint, and clean-exit state.
- Restrict its directory/file permissions to the current user: owner-only permissions on Linux and an appropriate Windows ACL.
- The frontend reads the locator at startup and sends `Authorization: Bearer <token>` on every API request and WebSocket handshake.
- Use constant-time token comparison. Reject missing, malformed, and incorrect tokens. Never put tokens in URLs or logs.
- Validate browser origins separately; CORS is not authentication. Verify TLS, token, and instance UUID before offering connection to an existing backend.
- Swagger documents bearer authentication. Scripts use the same protected locator and certificate trust configuration.

### First-launch TLS

- Use `cryptography.x509` to generate an application-private self-signed CA and a server certificate containing SANs for `127.0.0.1` and `localhost`.
- Store keys and certificates under the platform configuration directory's `tls/` folder: Linux `~/.cybersecurity-fundamentals-toolkit/tls/`; Windows `%APPDATA%\CybersecurityFundamentalsToolkit\tls\`.
- Use a one-year CA and 90-day server certificate; renew the server certificate during startup when fewer than seven days remain. Protect private keys with the same user-only permissions.
- Configure Uvicorn with `ssl_certfile` and `ssl_keyfile`. Create a client SSL context trusting the private CA, with hostname verification enabled; pass it as HTTPX's `verify` argument and WebSockets' `ssl` argument. [Uvicorn configuration](https://uvicorn.dev/settings/), [HTTPX TLS](https://www.python-httpx.org/advanced/ssl/), [WebSocket TLS](https://websockets.readthedocs.io/en/stable/reference/asyncio/client.html)
- Disable proxies for loopback clients. Never fall back to `verify=False` or install the CA into the OS trust store.
- First-launch tests must establish authenticated HTTPS and WSS connections without manually installing certificates.

### API, tasks, and persistence

- Implement the v2 brief's `/api/v1` routes and WebSocket channels. Add toolkit runs/uploads, job detail/cancellation, artifact downloads, target bulk import/export, workspace notes, and vault setup/password-change/refresh operations.
- Handle slash-containing Metasploit module paths without shadowing favorites/history routes.
- Use stable request IDs and payload fingerprints for mutations. Reject conflicting duplicates and report unknown execution outcomes without automatically repeating commands. Keep secret-bearing inputs and password-analysis replay state out of persistent request records.
- Limit analysis to two active tasks and 32 queued tasks; reject overflow explicitly. Bound each WebSocket subscriber queue to 256 messages and disconnect slow consumers with a resynchronization path.
- Use a catalog database plus one SQLite database per workspace, managed by Alembic. Jobs retain their original workspace and database lease across switches.
- Record framework-instance identities and explicit session/job associations. Switching workspaces must not relabel existing activity.
- Shutdown cancels local tasks, closes database connections, and stops owned processes. Confirm termination when an owned fallback process still has active sessions/jobs; never stop an externally managed daemon.

## 3. Seven existing tools and Scapy worker contract

Port these existing modules into backend analysis services and matching PyQt6 panels, preserving their stable IDs.

| Tool and ID | Existing module | Behaviors to preserve |
|---|---|---|
| Caesar Cipher — `caesar` | [caesar.py](../toolkit/modules/caesar.py) | ASCII shifts 1–25; preserve case and other characters; encryption/decryption round trips; all 25 candidates; 100,000-character input limit. |
| Password Strength — `password-strength` | [password_strength.py](../toolkit/modules/password_strength.py) | zxcvbn estimates, `log2(guesses)`, attributed common-password list, illustrative rates of 10/10,000/10 billion guesses per second, 72-character limit, masked input and Clear; no plaintext or matched tokens in results/logs. |
| Local Network Scanner — `network-scanner` | [network_scanner.py](../toolkit/modules/network_scanner.py) | Public/private IPv4 hosts or CIDRs, maximum 256 addresses; optional attached-RFC1918-interface mode; existing 18-port preset; sequential bounded TCP connect scans; Responded versus Inconclusive results. |
| DoS Pattern Detector — `dos-detector` | [dos_detector.py](../toolkit/modules/dos_detector.py) | Saved access logs, CSV, PCAP/PCAPNG; UTC one-second bins; default 100 events/IP/second; flag strictly above threshold; requests versus packets labels; out-of-order and malformed-input handling. |
| SQL Injection Checker — `sql-checker` | [sql_checker.py](../toolkit/modules/sql_checker.py) | Editable discovered forms; one selected form; two stable baselines; three quote-only probes across at most 12 fields; possible-issue wording; the selected form and explicitly enabled POST. Preserve pinned DNS, same-origin actions, verified TLS, disabled redirects/proxies, one request/second, 40 requests/run, bounded sizes/timeouts, and stale-result rejection. |
| Network Anomaly Detector — `anomaly-detector` | [anomaly_detector.py](../toolkit/modules/anomaly_detector.py) | Volume/protocol comparisons against preceding windows; defaults of one-second bins, 30-bin baseline, and absolute z-score above 3; insufficient-baseline and zero-variance reporting; existing detail limits. |
| File Type Identifier — `file-type` | [file_type.py](../toolkit/modules/file_type.py) | MIME, signature description, extension mismatches; first-1-MiB sample; task-local libmagic handles; clear unreadable-file and missing-native-component errors. |

Keep shared input limits of **25 MiB and 250,000 events**. CSV requires `timestamp,source_ip`, plus `bytes,protocol` for traffic analysis. Accept Unix seconds or timezone-bearing ISO timestamps.

Encode infinite anomaly scores as `zscore: null` plus an explicit `score_kind` enum; render infinity in the UI.

### Scapy JSONL protocol, version 1

The standalone worker accepts a saved capture path or binary capture data on stdin. It emits UTF-8 JSON objects, one per LF-delimited line, on stdout. Diagnostics go to bounded, sanitized stderr.

```json
{"v":1,"type":"meta","unit":"packets"}
{"v":1,"type":"packet","index":1,"timestamp":1700000000.125,"source_ip":"192.168.1.10","bytes":60,"protocol":"TCP"}
{"v":1,"type":"error","code":"MALFORMED_CAPTURE","message":"Capture record is truncated","index":2,"fatal":true}
{"v":1,"type":"end","emitted":1,"ignored_non_ip":0,"malformed":1,"complete":false}
```

- `index` is the original one-based capture record number. `timestamp` is finite Unix seconds; `source_ip` is canonical IPv4/IPv6; `bytes` uses reported wire length when available, otherwise captured length.
- Protocol labels preserve current classification: `TCP`, `UDP`, `ICMP`, or `IP-<protocol-number>`.
- Error codes distinguish malformed captures, invalid packets, input limits, missing dependencies, and I/O failures. Messages exclude captured payloads.
- Require metadata first and one final `end` record. Reject unsupported versions, invalid schemas, and lines over 64 KiB. Unexpected EOF marks analysis incomplete.
- Exit codes: 0 complete, 2 incomplete results, 1 startup/runtime failure, 130 cancellation. Preserve partial records while clearly marking incomplete analysis.
- The worker imports no application databases, authentication code, or GUI packages.

`OpenClawGateway` is a pre-existing WSL distribution discovered on this PC whose contents were not inspected; the toolkit has no dependency on it. A separate Ubuntu 24.04 WSL2 distribution named `Toolkit-MSF` will host Metasploit and the Scapy worker without modifying that existing distribution.

## 4. New features and security behavior

- **Metasploit:** retain pymetasploit3 behind a verified-TLS, timeout-controlled adapter with controlled token lifetime and serialized calls. Reconnect with 1/2/4-second backoff capped at 30 seconds.
- **Full PTY fallback:** expose the same module/options/run/session/job service interface through a shipped Ruby resource bridge and framed JSON. Separate structured replies from console output, validate framework compatibility, serialize commands, and expose uncertain outcomes. Do not silently change framework instances while fallback work remains active.
- **Module browser:** cached search/filter tree, metadata, favorites, recent history, dynamic option fields, tooltips, selected-target transfer, and streamed launch results.
- **Payload generator panel:** payload selector, format selector, LHOST/LPORT, encoder selector, iteration control, Save As picker, Generate/Cancel controls, progress state, and a bounded streaming output console. Validate fields against framework metadata. Generate through fixed subprocess arguments and return managed artifact IDs for download.
- **Targets/sessions/jobs/console:** target CRUD, bounded CIDR expansion, Nmap XML import/export, notes/status actions, session terminals, job controls, redacted history, and a console capped at 10,000 displayed lines.
- **Vault:** Fernet; PBKDF2-HMAC-SHA256 at 600,000 iterations; 32-byte salt and stored KDF parameters; memory-only keys; revocable workspace-bound 15-minute JWTs; server-enforced inactivity locking; explicit reauthentication for reveal; transactional password changes.
- Credential candidates remain temporary until accepted. Redact secrets from logs, persisted history, events, and default reports. Lock the vault on workspace changes and shutdown. Store MSFRPC passwords only in the OS keyring.
- **Reports:** backend-owned escaped Jinja2 templates, managed artifact paths, blocked external resource fetching, and optional WeasyPrint PDF generation with explicit HTML fallback.
- **Desktop:** dashboard counts and tool readiness, workspace selector, compact navigation, dark/light/system themes, connection/vault status, command palette, shortcuts, onboarding, debounced settings, and inline retry messages.
- **Update checker:** when enabled, perform a silent background startup GET to the public repository's GitHub Releases API using verified TLS, a five-second timeout, bounded response size, and conditional requests. Compare valid stable versions; display a dismissible newer-version banner. Offline, rate-limit, and missing-release responses remain quiet. No automatic download or installation. [GitHub Releases API](https://docs.github.com/en/rest/releases/releases#get-the-latest-release)

Passwords and toolkit analysis results remain in memory unless users explicitly save supported results. Errors remain local; plugin selection does not enable telemetry.

## 5. Sixteen slices, verification, and publication

Implement these **16 verified slices**. Commit actual completed work; do not fabricate fixes or history.

| Slice | Acceptance criterion |
|---|---|
| 1. Foundation | Desktop shell and shared schemas work; views communicate through API clients; platform calls are centralized. |
| 2. Secure bootstrap | Fresh-profile launch establishes authenticated HTTPS/WSS; invalid tokens/certificates fail; existing-instance identity is verified. Apply the expired-certificate implementation note below before starting Uvicorn. |
| 3. Workspaces | Create, switch, and delete inactive workspaces; running jobs retain their original workspace; migrations recover safely. |
| 4. Seven-tool migration | Every tool panel uses REST; existing non-PCAP regression tests pass; unavailable dependencies produce readiness messages. |
| 5. External traffic worker | PCAP/PCAPNG fixtures satisfy JSONL v1; malformed/out-of-order inputs, limits, partial results, and cancellation are handled. |
| 6. RPC integration | Dedicated WSL/native setup connects using verified TLS and bounded calls; disconnect/reconnect tests pass; includes Toolkit-MSF provisioning script and documented setup. |
| 7. Full PTY fallback | Module metadata/runs, sessions, jobs, and terminal operations pass controlled-lab tests, including interleaved output and uncertain outcomes. |
| 8. Module browser | Search, filters, favorites, history, dynamic forms, and target transfer work through REST/WS. |
| 9. Payload generation | All specified form controls work; progress streams; cancellation and artifact Save As pass. |
| 10. Sessions, jobs, console | Live updates, terminal commands, history, kill confirmations, queue bounds, and resynchronization pass. |
| 11. Vault | Wrong-password rejection, encryption, expiry/revocation, candidate acceptance, export, and atomic password changes pass. |
| 12. Reports | Escaped HTML and available PDF output generate correctly; secrets and external resource access remain blocked by default. |
| 13. Desktop completion | Themes, shortcuts, onboarding, settings, readiness, and update-banner cases pass navigation tests. |
| 14. CI | Public repository receives verified history; Windows/Linux × Python 3.11/3.12 checks pass with at least 75% coverage. |
| 15. Installers and compliance | Windows/Linux installer smoke tests pass; frozen imports exclude Scapy; dependency notices and corresponding source match shipped versions; independent security review of network and credential safeguards passed. |
| 16. Documentation and release | Documentation reflects verified behavior; independent security review of network and credential safeguards passed for the release source; v2.0.0 assets, checksums, source, and release notes are published only after all gates pass. |

### Slice 2 implementation note: expired certificates

Generate missing certificates and evaluate certificate validity **before Uvicorn starts and before frontend readiness polling**. The renewal predicate for an existing server certificate is `cert_is_expired or days_remaining < 7`. Validate the CA as well; regenerate an expired CA and its server certificate before publishing the new instance locator. Include a simulated return after more than 90 days, plus an expired-CA case, in the bootstrap tests. Renewal never disables TLS verification.

### Slice 6 deliverables: provisioning and setup documentation

Include a Windows Toolkit-MSF import/setup script, a Linux provisioning script, the MSFRPC startup configuration, and a README section describing setup and verification. The import/setup script accepts the installation directory and a verified Ubuntu 24.04 rootfs archive. Provisioning installs Metasploit, the separately installed Scapy worker and its dependencies, and the required verified-TLS RPC configuration. Use fixed arguments, do not alter other distributions, and keep real RPC passwords out of command-line arguments and generated plaintext configuration. The actual setup procedure belongs in these deliverables, rather than being expanded into this plan.

### Slice 15 hard gate: independent security review

Schedule an independent second developer or review agent after slice 14 passes and before slice 16 can start. The reviewer must be independent of the author of the safeguards being reviewed. Review network target enforcement, REST/WS authentication and TLS, subprocess boundaries, workspace isolation, vault lifecycle, credential handling/redaction, exports, and report resource restrictions against controlled fixtures.

Record the reviewed source revision, reviewer, findings, and retest evidence. Resolve all critical/high findings and document the disposition of other findings before signoff. A subsequent change to security-relevant code invalidates signoff until reviewed again. A matching successful review is a mandatory release gate, not a post-release follow-up.

### Verification and release outputs

Verification includes cipher round trips, common/repeated passwords, detector boundaries, insufficient baselines, renamed signatures, target-validation failures, redirect/cross-origin rejection, disabled POST, duplicate mutations, secret redaction, workspace isolation, cancellation, shutdown, discovery, and launching from another working directory. Use controlled fixtures and owned lab targets.

Require Black, Ruff, strict mypy, unit/integration/WebSocket tests, installer smoke tests, and the scheduled independent security review.

Use `pyproject.toml` as authoritative configuration with reproducible dependency locks. Build Windows with PyInstaller/Inno Setup and Linux with PyInstaller/AppImage tooling plus the Debian package skeleton. Include resources, migrations, and discovered tools; provide the test-only Dockerfile.

Deliver setup/build/API-authentication guides, worker and module-extension specifications, native prerequisite discovery, troubleshooting, security/contributing policies, changelog, real screenshots, software inventory, release announcement, repository description, and topics. Installers remain unsigned unless signing credentials are supplied.
