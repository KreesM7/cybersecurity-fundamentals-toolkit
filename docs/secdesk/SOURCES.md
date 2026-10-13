# Source ledger

Research date: 2026-10-13. Statements below are documented capabilities, not claims of installed or locally tested tools.

| Tool | Official source | Verified from source | Real tool run |
| --- | --- | --- | --- |
| Wireshark/TShark | https://www.wireshark.org/docs/man-pages/tshark.html and https://www.wireshark.org/docs/man-pages/wireshark | Packet inspection, saved-file reading, version option; GUI/terminal distinction | Unverified: executables absent in this Windows/Toolkit-MSF test environment |
| Tcpdump | https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in | CLI packet analysis; saved-file `-r`, numeric addresses `-n`, version option | Unverified: executable absent |
| Aircrack-ng | https://www.aircrack-ng.org/doku.php?id=install_aircrack and https://aircrack-ng.org/doku.php?id=install_drivers | CLI suite and Windows adapter/driver limits; no integration delivered yet | Unverified |
| Metasploit | https://docs.rapid7.com/metasploit/getting-started/ and https://help.rapid7.com/metasploit/Content/framework/about-msf.html | Framework console; existing Toolkit connection/console will be reused later | No SecDesk launch tested |
| Nessus | https://docs.tenable.com/nessus/Content/NessusCLI.htm | Admin CLI with license-dependent help and administrator requirements | Commercial integration pending |
| Nikto | https://github.com/sullo/nikto/wiki | Official documentation located; command research pending | Unverified |
| Splunk | https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.3/administer-splunk-enterprise-with-the-command-line-interface-cli/about-the-cli | CLI administration documentation located; integration pending | Unverified |

Forcepoint, Nexpose/InsightVM, NetStumbler, Burp and community gap research remain pending. No readiness, compatibility, licensing or output is asserted for them. Native success/failure examples are explicitly unverified; no fake sample output is stored. Installed/absent doctor tests simulate discovery only and do not establish native tool behavior.
