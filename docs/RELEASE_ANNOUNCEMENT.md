# Cybersecurity Fundamentals Toolkit 2.1.0

This release includes the updated desktop and in-app Windows updater, plus the vault,
redaction and supply-chain hardening completed since 2.0.0.

## Download

- **Windows x64:** `Toolkit-2.1.0-Windows-x64-Setup.exe` upgrades the existing per-user installation.
- **Windows portable:** extract the entire portable ZIP and keep `_internal` beside the executable.
- **Linux x86_64:** the AppImage targets Ubuntu 24.04+; use `--appimage-extract-and-run` without FUSE.

Install 2.1.0 once from this release if you are on 2.0.0. Future Windows updates can be
installed from Settings: Download update, wait for checksum/signature verification,
then explicitly click Install & restart. Source/portable and Linux installations do
not auto-apply. Update checks remain optional and off by default.

Seven fundamentals tools are included alongside guided workspaces, targets, modules,
sessions/jobs, encrypted credentials and reporting. Nmap, compatible libmagic and
Toolkit-MSF/Scapy remain separately installed prerequisites.

## Integrity and limits

SHA256SUMS, Sigstore bundles, CycloneDX SBOMs, exact platform inventories and corresponding
sources accompany the release. Follow `docs/RELEASE_VERIFICATION.md` to verify the
GitHub OIDC workflow identity and checksums. Signatures are detached; Windows may still
show SmartScreen because the installer does not have Authenticode signing.

Results are not a penetration-test certification. Test only systems you own or have
permission to assess. Capture analysis uses saved files. Packaged reports use HTML;
PDF support is optional in source installations. Back up important workspaces before
upgrading; Python/Qt cannot guarantee perfect memory erasure.
