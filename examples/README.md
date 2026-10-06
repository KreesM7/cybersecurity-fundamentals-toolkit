# Small saved-file examples

All data is synthetic. These files contain no real requests, captured user traffic, or credentials. The PCAP was constructed locally; no traffic was sent.

| File | Contents / expected result |
|---|---|
| `requests.csv` | 101 requests from `10.0.0.8` at one second, and 100 from `10.0.0.9` at the next. With DoS threshold 100, only the 101-request bin is flagged. |
| `traffic.csv` | Thirty one-second TCP bins of 1,000 bytes, then ten UDP events of 2,000 bytes in the next bin. The default anomaly detector flags volume/protocol changes against the unchanged baseline and shows infinite z where variance is zero. The request-style DoS count stays below 100. |
| `access.log` | Four Common/Combined entries, intentionally out of order; HTTP byte counts are parsed and events sorted. Too short for the default anomaly baseline. |
| `malformed.csv` | Two valid traffic records plus a bad timestamp and an invalid source IP. Both detectors report incomplete analysis and skipped row positions. Too short for the default anomaly baseline. |
| `sample.pcap` | Thirty TCP packets at one per second, then a ten-packet UDP burst. Defaults flag event-count/protocol changes; packet labels are used. No live capture driver required. |

The timestamp in Unix examples is 2026-10-06 00:00:00 UTC. Use Browse in either detector to choose an example. The bundled build copies these under `_internal/examples/`. The toolkit never edits input files.
