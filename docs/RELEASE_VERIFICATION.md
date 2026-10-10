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
