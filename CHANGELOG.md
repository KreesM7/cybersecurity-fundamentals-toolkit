# Changelog

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
