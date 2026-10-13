# Changelog


## 2.1.0 — 2026-10-12

- Guided desktop workflows, consistent navigation, field help and accessible status badges.
- Windows Settings: explicit download, SHA-256 and Sigstore verification, then install/restart in place.
- Argon2id vault migration, opaque sessions, unlock backoff, broader secret redaction and audit events.
- Locked dependency auditing, full-history secret scanning, CodeQL and signed release inventories/SBOMs.
- Linux remains notify-only for updates. External Nmap, libmagic and Metasploit remain separate prerequisites.

Existing 2.0.0 installations need this installer once to gain the in-app installer.
Detached Sigstore signatures verify provenance; Windows Authenticode remains unavailable.

## Unreleased

- Redact prefixed secret fields, JSON values, credential URLs, sensitive headers, JWTs and exception logs; bound work on long log identifiers.
- Replace vault JWT sessions with hashed opaque tokens and exclude issued tokens from mutation replay storage.
- Add workspace-scoped unlock backoff and move password derivation outside the shared vault lock.
- Use Argon2id for new vaults and atomically migrate legacy PBKDF2 vaults after making a protected backup; benchmark costs in CI.
- Wipe mutable session key buffers on discard, record redacted vault audit events, and apply common WebSocket size/rate limits.

## 2.0.0

- PyQt6 desktop with private authenticated HTTPS/WSS backend and isolated local profiles.
- Seven fundamentals tools retained, with bounded authorized targets and saved-file analysis.
- Workspace/target records, Nmap XML import/export, module browsing and target transfer.
- Dedicated Metasploit RPC setup, supervised PTY fallback, sessions/jobs/console and payload artifacts.
- Encrypted workspace vault with temporary candidates, explicit acceptance and reauthentication.
- Escaped reports, optional source-install PDF support and explicit HTML fallback.
- Themes, command palette, onboarding, settings and optional update banner.
- Independent Scapy JSONL worker; worker runtime is excluded from desktop bundles.
- Four-platform/Python CI, shutdown regressions, installer recipes, source inventories and notices.

Known limits: unsigned installers; Linux AppImage targets Ubuntu 24.04+; external
tools require separate installation; default packaged reports use HTML; no live
capture; Qt/Python do not promise secure memory erasure. Unknown external-command
outcomes require manual reconciliation and are never silently replayed.
