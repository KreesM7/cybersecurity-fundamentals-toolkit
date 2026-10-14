# Desktop controls

Dashboard shows the selected workspace, target and historical session counts, active local
jobs, saved reports, tool readiness, framework connection and vault status. The workspace
selector locks the vault when switching; running jobs retain their original workspace.

Settings → General offers dark, light and system appearance. Changes save after a short
pause, through the authenticated API. Failed saves show an inline retry instruction.
Settings → Metasploit contains connection setup. The first-launch guide can be dismissed.

**Settings → General → Check for updates** checks the latest stable release on demand,
even when startup checks are disabled. A successful check with no newer release displays
**You are up to date**. A newer Windows release offers **Update to vX.X.X**, which downloads
and verifies the installer through the existing updater. **Install & restart** still requires
a separate click after verification. Failed checks show a retry message; they never report
that the application is current. A manual check resurfaces a previously dismissed release.
This does not enable automatic startup checks. Other platforms retain release notification
and the release-page link.

Shortcuts: **Ctrl+K** opens a searchable page palette; **Ctrl+T** opens Modules;
**Ctrl+L** opens Sessions / Jobs / Console; **Ctrl+S** saves the active workspace's notes;
**F5** refreshes session/job lists. Terminal commands are never silently retried.

Update checks are optional and initially disabled. When enabled, startup performs one
background request to the public GitHub latest-release endpoint, using verified TLS,
no proxies or redirects, a five-second total deadline, a 64 KiB response cap and ETags.
Only newer stable versions produce a dismissible banner. The launcher waits before
opening the main window; offline, missing releases and rate limits produce a retry
notification without blocking use. Disabling startup checks cancels an in-flight
startup check. Release-request bounds and polling behavior are unchanged.

## Windows: download, verify, install and restart

Settings → General shows **Update to vX.X.X** when a newer stable release publishes
its Windows setup executable, SHA256SUMS and both corresponding `.sigstore.json`
bundles. Downloads start only on your click. A themed progress bar shows the current
stage; checksum/signature badges must pass before **Install & restart** is enabled.
Failures show an inline reason and **Retry download**, leaving the current install intact.
An unavailable signed asset set remains notify-only.

The first download also obtains the official Cosign 3.1.3 Windows verifier (about
190 MiB), pinned by SHA-256 and size in `backend/services/update_service.py`.
Subsequent downloads reuse it only after checking its hash. Installer downloads are
capped at 300 MiB, manifests/bundles at 1 MiB each; downloads have explicit connection,
read and total deadlines. HTTPS is verified, proxies disabled, and asset redirects
are permitted only to GitHub's HTTPS release-asset host. Release discovery still
refuses redirects. Cosign requires the expected repository's release-integrity
workflow identity (main or that exact tag), GitHub OIDC issuer, and its standard
certificate/transparency checks. Verification may need Sigstore's public trust service.
Neither an arbitrary URL nor an installer path is accepted by the update API.

**Install & restart** is a separate explicit action. It rechecks the files, asks about
active owned work through the existing shutdown flow, then closes API listeners,
workers and the application. A hidden helper waits for process exit, locks the files
against modification, checks hashes and both signatures again, and runs Inno Setup
with `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-` and `/DIR` pointing to the running
installation. It relaunches the executable in that same directory with the same
profile. The app shows a one-time “Updated to vX” notification only if installation
succeeded and the running version matches. A failed handoff shows a retry notification
on relaunch. An installer exceeding its 15-minute limit is left running; restart only
after checking its outcome. There is no automatic rollback after an installer starts.

Automatic application requires an installed Windows build (the executable and Inno
uninstaller in the same folder), and the window owning the backend. Source/portable
runs may download and verify but cannot overwrite themselves or create a second copy.
Each app launch discards previous installer downloads and verification status; users
must download/verify again. No cached flag authorizes execution. Existing installations
need a release containing this feature before they can use it.

The private `profile/updates/` directory holds temporary downloads and a one-shot
handoff record. The authenticated API exposes `POST /api/v1/updates/download`,
`POST /api/v1/updates/apply` (version body and stable X-Request-ID), and
`GET /api/v1/updates/progress`; EventHub publishes `update-progress`. API preparation
alone never executes an installer: only the owning desktop's explicit install flow
hands off after graceful shutdown.

macOS and Linux/AppImage remain **notify-only**, with View release. Auto-apply is not
in scope: those targets have no single silent-install convention or install location.

Tests use a mocked GitHub API plus harmless fixture executables. Windows tests run
the actual handoff script and verify silent arguments, Unicode paths, relaunch and
refusal on checksum/signature failures. They never run a downloaded installer.


## SecDesk source candidate (2.2.0)

Normal launches show **Checking for updates…** before creating the main window.
The existing Settings startup-update preference controls the GitHub request.
The launcher waits for the backend's existing release check, preserving its
TLS verification, ETag, five-second deadline and 64 KiB response cap; it does
not issue a second release request. A seven-second UI fallback opens the app
with a retry message if the local request stalls. Offline use remains available.
Successful checks show **You are up to date** or an update notice in Settings.
Downloads and verified installation still require explicit clicks. Closing the
launcher cancels its callbacks, preventing a late response reopening the app.
The default disposable `--self-test` remains deterministic and skips this UI wait.

Open SecDesk from the Tools navigation. Startup checks are passive and local: executable presence, dependency discovery and serial metadata. They do not start services, open serial connections, run captures or probe endpoints. Unknown services/permissions/licenses are displayed with Setup guidance. Recheck repeats only those passive checks.

Open a tool detail view, read Setup, then launch its native GUI or terminal. A terminal starts the OS shell with the selected tool directory on PATH and a private workspace working directory; no scan command is prefilled or executed. Metasploit's existing Settings, Modules, Sessions & Jobs and Payloads pages are linked from its manifest. Native discovery does not inspect WSL installations. For commercial tools, enter a credential-free HTTPS console URL, open it explicitly; vendor login and HTTPS certificate verification apply. A local console-request record means navigation was requested, not that vendor health/licensing was verified.

Four native sessions are allowed. Stop/close and app shutdown reap owned processes and release workspace leases; failed cleanup preserves ownership for retry. Save native captures/documents before closing. POSIX terminals require the host `/usr/bin/script`; no helper is auto-installed and transcripts go to `/dev/null`. Windows uses locked pywinpty ConPTY. Shell history is disabled for the owned session, but external tools can persist data according to their own configuration. Input is limited to 4096 characters per frame and output to 64 KiB per read; the redacted viewport is bounded. Ctrl+Tab/Shift+Tab leave the terminal; other terminal control keys take precedence over app shortcuts. Mutation bookkeeping retains the existing 10,000-request instance cap; reconcile sessions before restarting if reached. No unknown input outcome is automatically repeated.

Windows GUI launches enter a non-breakaway Job Object before their suspended parent resumes; child ownership survives a launcher exiting. Linux GUI launches own a process session. Processes that deliberately create a new POSIX session or hand work to an existing external service can escape that session; those detached services are not managed or killed. Avoid daemonizing commands in an owned terminal. Existing independent applications/services are never adopted merely because a launcher contacts them. macOS process cleanup remains unverified.

Workspace findings accepts a JSON array of `{"title":"Observation","severity":"info","target":"127.0.0.1","evidence":"Your observed evidence"}` or UTF-8 CSV with exact columns `title,severity,target,evidence`. This is a format illustration, not a tool finding. Severity is one of info/low/medium/high/critical. Limits: 5 MiB, 1000 records per import, 500 displayed/report records; excess rows are not silently parsed. Same source/title/target merges, with latest supplied severity/evidence. Secrets are redacted before persistence. Default Reports includes finding summaries and excludes native terminal output/evidence. Original tool exports are not automatically interpreted.

Use `python -m toolkit secdesk doctor` for local CLI discovery. For source development, use `python -m toolkit --profile work/secdesk-dev`; keep the installed release/profile separate. The new workspace schema adds audit/findings tables transactionally. Back up profiles before promoting a new installer; older binaries do not understand newer Alembic revisions. No production vault was used for this development test run.

[SOURCES](secdesk/SOURCES.md), [STATUS](secdesk/STATUS.md), [GAPS](GAPS.md) and [DEV_WORKFLOW](DEV_WORKFLOW.md) record provenance, limits and resource ownership.
