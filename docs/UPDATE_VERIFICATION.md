# In-app update verification — 2026-10-12

Lane D, branch `update-apply`. Application version remains 2.0.0; no release was published.

- Full Windows/Python 3.12 suite: **379 passed, 11 skipped, 50 subtests passed**.
- Coverage: **80.65%**, exceeding the 75% gate and the previous 80.24% baseline.
- Updater-specific tests: **31 passed**. They cover exact release asset selection,
  bounded downloads, restricted redirects, checksum/signature failures, modified
  downloads, discarded cached trust, authenticated/idempotent API requests, explicit
  install clicks, rejected shutdown confirmation, and verifier cancellation ownership.
- Actual Windows handoff script exercised with harmless compiled fixture executables:
  verified silent flags, same destination, paths containing spaces/Unicode, relaunch,
  and no installer execution after checksum/signature failure.
- Pinned official Cosign 3.1.3 verified the actual published v2.0.0 SHA256SUMS bundle.
  No downloaded release installer was executed by these checks.
- Black, Ruff, strict mypy (127 files), Git whitespace checks and `uv lock --check` passed.
  The full suite retains an upstream Starlette/httpx deprecation warning.
- Isolated PyInstaller Windows build succeeded. The packaged PowerShell helper matches
  the source hash. Fresh-profile startup from another working directory passed: 17 panels.
- Settings verified/failure states inspected with the app's theme, shared badges and
  icon set. The install action remains disabled until both checks pass.

Protected authentication, TLS, existing-instance verification, target safeguards and
module-option validation were not modified. Release polling retains its existing TLS,
ETag, five-second deadline and 64 KiB cap. No automatic installer execution occurs from
release checks, downloads, API preparation alone or a persisted verification flag.

The real production upgrade/release publication remains a release-time check. These
results validate local source, packaging, cryptographic verification and the Windows
handoff with controlled fixtures; they do not claim a deployed newer release or testing
on macOS/Linux hosts. Those platforms retain notify-only behavior.
