# Third-party notices and release constraint

The root MIT license covers this project's original source and examples. It does not relicense dependencies or the bundled password corpus. This is a local source/build-recipe delivery. No combined executable, Nmap binary, capture driver, or libmagic binary is delivered for redistribution.

## Requested direct dependencies

| Package | Pinned version | Upstream license / source |
|---|---|---|
| PySide6-Essentials | 6.11.2 | [LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only; Qt licensing choices apply](https://pypi.org/project/PySide6-Essentials/6.11.2/) |
| Scapy | 2.8.0 | [GPL-2.0-only, upstream metadata](https://github.com/secdev/scapy/blob/v2.8.0/pyproject.toml) |
| python-nmap | 0.7.1 | [GPL-3.0](https://pypi.org/project/python-nmap/0.7.1/) |
| psutil | 7.2.2 | [BSD-3-Clause](https://pypi.org/project/psutil/7.2.2/) |
| python-magic | 0.4.27 | [MIT; native libmagic is separate](https://pypi.org/project/python-magic/0.4.27/) |
| zxcvbn | 4.5.0 | [MIT](https://pypi.org/project/zxcvbn/4.5.0/) |
| urllib3 | 2.8.0 | [MIT](https://pypi.org/project/urllib3/2.8.0/) |
| Beautiful Soup | 4.15.0 | [MIT](https://pypi.org/project/beautifulsoup4/4.15.0/) |
| PyInstaller (build tool) | 6.22.3 | [GPL-2.0-or-later with the PyInstaller bootloader exception](https://pyinstaller.org/en/stable/license.html) |

**Unresolved binary redistribution issue:** Scapy's GPL-2.0-only and python-nmap's GPL-3.0 licenses cannot simply be treated as one compatible license for a combined application. Keeping both requested libraries and placing MIT on our source does not settle combined-binary obligations. Before releasing an executable, resolve the license compatibility/architecture question and comply with all dependencies' source, notice, linking, replacement, and other applicable requirements. PyInstaller's exception does not waive the licenses of libraries it packages. No legal clearance or public-distribution approval is claimed here.

Qt/PySide and Shiboken carry their own alternative licenses and third-party notices. Consult the actual installed distribution and Qt's licensing terms before redistribution; dynamic inclusion alone is not a complete compliance assessment. Nmap has [separate licensing terms](https://nmap.org/npsl/) beyond the Python wrapper; do not infer permission to bundle it from python-nmap's license.

## Bundled common-password sample

`toolkit/resources/common_passwords.txt` contains the first 1,000 nonempty lines of Daniel Miessler's [SecLists `Passwords/Common-Credentials/10k-most-common.txt`](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt), obtained 2026-10-06. Upstream file Git blob SHA: `a93ea7f91f095b38728795ecd6ec731e59b8c112`. This is a public sample, not a comprehensive breach-password check. The exact upstream MIT notice is preserved in [`toolkit/resources/SECLISTS_LICENSE.txt`](toolkit/resources/SECLISTS_LICENSE.txt).

## Transitive and external components

The local environment also installs Shiboken6 (same Qt license alternatives), soupsieve (MIT), typing-extensions (PSF-2.0), and build dependencies such as altgraph, pefile, pywin32-ctypes, packaging, setuptools, and pyinstaller-hooks-contrib. Preserve and review their actual distribution notices for any release. The direct pins do not freeze every transitive dependency; capture a tested build environment when preparing a release.

External Windows libmagic DLL/database packages and their dependencies have separate licenses. The MSYS2 UCRT64 file package uses BSD-2-Clause; its dependency tree includes additional BSD, LGPL, and GCC runtime-exception terms. They are installed separately and are not included in this source delivery. Use the package manager to keep the DLL, database, and dependencies matched. Npcap/WinPcap are unnecessary for saved-file analysis; the toolkit does not ship either.
