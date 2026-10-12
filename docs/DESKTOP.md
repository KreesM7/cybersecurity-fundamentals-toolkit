# Desktop controls

Dashboard shows the selected workspace, target and historical session counts, active local
jobs, saved reports, tool readiness, framework connection and vault status. The workspace
selector locks the vault when switching; running jobs retain their original workspace.

Settings → General offers dark, light and system appearance. Changes save after a short
pause, through the authenticated API. Failed saves show an inline retry instruction.
Settings → Metasploit contains connection setup. The first-launch guide can be dismissed.

Shortcuts: **Ctrl+K** opens a searchable page palette; **Ctrl+T** opens Modules;
**Ctrl+L** opens Sessions / Jobs / Console; **Ctrl+S** saves the active workspace's notes;
**F5** refreshes session/job lists. Terminal commands are never silently retried.

Update checks are optional and initially disabled. When enabled, startup performs one
background request to the public GitHub latest-release endpoint, using verified TLS,
no proxies or redirects, a five-second total deadline, a 64 KiB response cap and ETags.
Only newer stable versions produce a dismissible banner. Offline, missing releases and
rate limits stay quiet. Disabling checks cancels an in-flight check. Polling behavior is unchanged.

## Windows: download, verify, install and restart

Settings → General shows **Download update** when a newer stable release publishes
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
