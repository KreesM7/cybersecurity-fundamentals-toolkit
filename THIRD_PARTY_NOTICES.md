# Dependency and distribution notices

Our original source is MIT licensed (LICENSE). The combined PyQt6/python-nmap desktop is distributed under GPLv3 (COPYING). This does not relicense third-party components; their original notices and applicable terms remain in force. No warranty is provided.

## Distribution boundary

- PyQt6 6.11.0: GPLv3; PyQt6-sip 13.13.0 retains its wheel notices.
- Qt 6.11.2: LGPLv3 and module-specific third-party licenses. Qt libraries remain separate dynamic libraries and can be replaced with compatible modified builds. Reverse engineering for debugging modifications to these libraries is permitted. Build instructions and corresponding sources accompany release assets.
- python-nmap 0.7.1: GPLv3. The external Nmap executable is not bundled and has its own NPSL terms.
- Scapy 2.8.0: GPL-2.0-only, installed independently in a separate worker environment. Neither Scapy nor its Python runtime is in the desktop installer. The worker is independently usable via the documented JSONL interface. Separation does not remove PyQt6/python-nmap GPLv3 obligations. GPLv2-only and GPLv3 code must not be linked together into this desktop.
- Metasploit and its dependencies are independently installed in Toolkit-MSF or a native Linux environment; they are not included in desktop assets.
- Native libmagic and its database are separately installed. The Python wrapper is included under MIT.
- PyInstaller 6.22.3 includes its GPL exception for generated applications; that exception does not waive dependency terms. Inno Setup is a build tool, not an application dependency.

For each platform, `compliance/inventory.json` in the frozen folder records actual collected Python distributions, versions, native filenames, source URLs and source hashes. `compliance/licenses/` preserves installed notices, including vendored packages. The release source archives include original project files, Python dependency source distributions and Qt source. `uv.lock` records exact transitive dependency resolution; optional and development packages in the lock are not necessarily in the installer. Native runtime notices accompany the inventory. See docs/BUILD.md for reproducing and replacing components.

Relevant upstream terms: [PyQt](https://www.riverbankcomputing.com/software/pyqt/intro), [Qt](https://www.qt.io/licensing/open-source-lgpl-obligations), [PyInstaller](https://pyinstaller.org/en/stable/license.html), [Nmap](https://nmap.org/npsl/), [Scapy](https://github.com/secdev/scapy/blob/master/LICENSE).

## Common-password sample

`toolkit/resources/common_passwords.txt` contains the first 1,000 nonempty lines of Daniel Miessler's [SecLists common-password list](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt), obtained 2026-10-06. Upstream Git blob: `a93ea7f91f095b38728795ecd6ec731e59b8c112`. The exact MIT notice is in `toolkit/resources/SECLISTS_LICENSE.txt`. This is a small public sample, not a comprehensive breach-password check.

## Rebuilding or redistributing

Preserve LICENSE, COPYING, these notices, and the generated dependency notices. Provide matching corresponding source and build scripts alongside binaries, including modified dependency sources if changed. Preserve the independent Scapy boundary. Re-audit inventories after any dependency, platform, or packaging change. We do not assert legal clearance for a third party's modified distribution.


## Optional update verifier

The Windows in-app updater downloads **Sigstore Cosign 3.1.3** on explicit download
request, under the Apache-2.0 license; it is not vendored into the Python environment.
The executable is SHA-256 pinned, checked before use, and used only to verify release
bundles. Official source/license: https://github.com/sigstore/cosign/tree/v3.1.3 .
Checksum source: https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign_checksums.txt .
