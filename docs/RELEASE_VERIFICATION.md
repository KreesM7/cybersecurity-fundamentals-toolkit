# Release candidate verification

Application security signoff: a7a1ae650678ff45b648aea2452fad967d9264c1 (see SECURITY_REVIEW.md).

- GitHub CI run 38023742065: all four Windows/Ubuntu × Python 3.11/3.12 jobs passed, including 75% coverage gate, strict mypy, formatting, lint, and fresh-profile startup.
- Windows x64 PyInstaller application: fresh-profile startup from a different working directory passed, 17 panels.
- Inno Setup 7.1.0 per-user install into a disposable workspace directory, installed-app startup from another directory, and uninstall: passed. No existing installation was replaced.
- Linux x86_64 AppImage on Ubuntu 24.04 in Toolkit-MSF: FUSE-free extraction/run from /tmp, fresh-profile authenticated startup and 17 panels passed with the offscreen Qt platform.
- Six screenshots capture real desktop views with a disposable empty profile; no simulated findings or credentials.
- Scapy/worker code absent from the desktop analysis inventory. Both remain separately installed. Native tools and host Linux libraries are excluded by the final bundle filter.
- Optional PDF test skipped on Windows because WeasyPrint is not installed there; Linux source-install PDF tests were verified separately. Packaged reports explicitly fall back to HTML.

These checks establish startup/navigation and packaging behavior on the tested hosts, not every desktop distribution, display server, network target, or Metasploit module. Installers are unsigned. The Debian directory is a skeleton; no .deb or container deployment is claimed as tested.

## Keyless signatures and CycloneDX SBOMs

`Release integrity` runs on publication or manual dispatch from main for an
existing release tag. All assets must be uploaded first. It resolves the tagged
commit, verifies downloaded assets against SHA256SUMS, and runs locked
`cyclonedx-py` tooling against the tagged platform inventories. Each SBOM records
dependency versions/source hashes, native filenames, CPython, the source commit,
and the authoritative inventory's SHA-256. Exact inventories are also published.
Native filenames without recorded versions/hashes remain unversioned; the CI
environment is not presented as an inventory of the installed application.

The workflow adds SBOM/inventory hashes to SHA256SUMS, signs every listed artifact
and the manifest using GitHub OIDC, verifies every Sigstore bundle, then publishes
the bundles and generated files. No maintained private key is stored. Rerun after
any release-asset change. Existing releases gain signatures only after a successful run.

Download the desired artifact, its `.sigstore.json`, SHA256SUMS and its bundle.
For a manual run from main, verify using Cosign 3.1.3:

```sh
identity='https://github.com/KreesM7/cybersecurity-fundamentals-toolkit/.github/workflows/release-integrity.yml@refs/heads/main'
issuer='https://token.actions.githubusercontent.com'
cosign verify-blob --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" --bundle SHA256SUMS.sigstore.json SHA256SUMS
cosign verify-blob --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" --bundle Toolkit-2.0.0-Windows-x64-Setup.exe.sigstore.json Toolkit-2.0.0-Windows-x64-Setup.exe
sha256sum --ignore-missing --check SHA256SUMS
```

For automatic release runs use the exact `@refs/tags/vX.Y.Z` workflow identity
shown in that release's run. Verify SBOM/inventory bundles the same way. Never
disable identity, issuer, certificate, or transparency-log checks. See
[Sigstore's blob-signing documentation](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/).
Detached signatures prove provenance; they do not provide Windows Authenticode,
macOS notarization, or remove SmartScreen prompts. Historical installer test
results above remain unchanged.
