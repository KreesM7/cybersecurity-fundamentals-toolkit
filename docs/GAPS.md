# SecDesk gap research

Research date: 2026-10-13. Priorities below are proposals, not automatically enabled tools. User decision: **keep the current scope**. Kali, Sprinto, Nmap, John the Ripper and KisMAC remain excluded as cards/integrations; Nmap stays a prerequisite only.

| Missing category / capability | Evidence and justification | Proposed priority |
| --- | --- | --- |
| Web content discovery (ffuf family) | [Official Kali package catalog](https://www.kali.org/tools/kali-meta/) lists broader web testing categories than this hub. A separate discovery workflow could complement Nikto. This is an inference, not a claim it must be installed | Future, not selected |
| Native reversing (Ghidra/radare2 family) | [Kali catalog](https://www.kali.org/tools/kali-meta/) includes reverse engineering categories. The existing LowREA code is a separate incomplete integration; it is not silently promoted to a finished tool | Future, not selected |
| Reporting templates and vendor-format imports | [Pentesting discussion](https://www.reddit.com/r/Pentesting/comments/1ijjwsr/tools_for_report_automation/) and [workflow discussion](https://www.reddit.com/r/Pentesting/comments/j7hy43) describe report-writing friction. SecDesk now accepts explicit normalized JSON/CSV and uses existing HTML/PDF summaries; raw vendor-format parsers remain a gap | High follow-up within current tools |
| Search/lab onboarding for SIEMs | [Cybersecurity discussion](https://www.reddit.com/r/cybersecurity/comments/1kw2o3v) asks for hands-on Splunk/Sentinel learning. This hub provides vendor-linked guidance, not a maintained lab environment | Medium follow-up |
| Session visualization and collaboration | [Cobalt Strike feature overview](https://www.cobaltstrike.com/product/features) demonstrates a broader team console. Filterable local sessions are useful; shared team control would require new authorization and data-sharing design | Low; no collaboration added |
| Proxy/capture explanation | [AskNetsec discussion](https://ca.reddit.com/r/AskNetsec/comments/cz3yqg/ssl_proxy_creating_decrypted_pcap/) concerns encrypted traffic workflows. The Burp section links primary vendor guidance and never installs a CA silently | Current educational section |
| Native error examples and verified compatibility | Existing vendor docs establish interfaces, but most binaries/licensed deployments and the DIY device are unavailable on this host. Real native outputs, current NetStumbler compatibility and service/license validation cannot be asserted | High verification work after setup |

Community samples are self-selected, dated anecdotes, not representative demand or technical authorities. Searches included r/netsec, r/AskNetsec, r/Pentesting and r/cybersecurity. r/netsec did not yield a directly verifiable relevant thread in this pass; no conclusion is fabricated from it. Tool claims use the primary sources in SOURCES.md, not community guesses.
