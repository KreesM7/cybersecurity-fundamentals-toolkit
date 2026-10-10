# Debian package skeleton

Target Ubuntu 24.04 amd64. Create a fresh staging directory, copy `control` to
`DEBIAN/control`, the complete Linux frozen folder to `opt/toolkit`, and
`../linux/toolkit.desktop` to `usr/share/applications/toolkit.desktop` (change
Exec to `/opt/toolkit/CybersecurityFundamentalsToolkit`). Copy the SVG to
`usr/share/icons/hicolor/scalable/apps/toolkit.svg`. Include COPYING, notices,
and the generated compliance folder from the frozen build. Run
`dpkg-deb --root-owner-group --build STAGING`. This skeleton is not a published
or smoke-tested .deb. It does not install Metasploit, Scapy, Nmap, or libmagic.
