# Cybersecurity Fundamentals Toolkit 2.0.0

A native desktop for seven security fundamentals tools, local workspaces, dedicated Metasploit integration, an encrypted vault, and reports.

Windows: download the x64 Setup executable, install for your user, and launch from Start. Python is included. The portable ZIP must remain intact beside its `_internal` folder. Linux: use the x86_64 AppImage on Ubuntu 24.04+; the README lists host libraries and FUSE-free startup.

External Metasploit, Scapy, Nmap and libmagic are installed separately. The app opens with actionable readiness messages when they are absent. Scanning and web testing require explicit authorization; saved traffic analysis does not generate traffic. Only assess systems you own or have permission to test.

This release includes themes, searchable navigation, workspace/target management, module options and target transfer, bounded session/job consoles, cancellable payload artifacts, a credential vault with explicit acceptance, and escaped reports. Packaged PDF requests fall back to HTML. Update checking is optional and does not install anything.

Verification: four Windows/Linux and Python 3.11/3.12 CI jobs, independent application security review, and fresh-profile installer smoke tests. See docs/RELEASE_VERIFICATION.md for scope and limitations.

The installers are unsigned. Compare downloaded files with SHA256SUMS. Original source is MIT; combined desktop distribution follows GPLv3. Matching dependency sources and Qt source accompany the assets, with licenses and software inventories included in each bundle. Source/build instructions permit rebuilding and replacing compatible Qt libraries.
