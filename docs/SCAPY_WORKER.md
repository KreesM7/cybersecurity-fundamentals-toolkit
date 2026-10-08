# Independently installed saved-capture worker

DoS and anomaly detectors accept uploaded PCAP/PCAPNG through a separate process.
CSV/log input needs no worker. There is no live capture, network operation, packet
payload logging or saved analysis history. The desktop imports no Scapy and does
not package `worker/` or its environment. Binary release inspection is a later gate.

## Installation and readiness

Build/install the `worker/` Python distribution in an independent Python 3.11/3.12
environment with its pinned requirement `scapy==2.8.0`:

```sh
python3 -m venv /opt/toolkit-scapy
/opt/toolkit-scapy/bin/python -m pip install ./worker
/opt/toolkit-scapy/bin/python -m toolkit_scapy_worker --check
```

Use appropriate administrator permissions only to create/provision `/opt`; analysis
itself needs no elevated privileges. Linux discovers `/opt/toolkit-scapy/bin/python`
by default. `TOOLKIT_SCAPY_PYTHON` can name another absolute independently installed
interpreter on Linux. The override is deployment configuration, never an upload
option. Windows always invokes `/opt/toolkit-scapy/bin/python` through the fixed WSL
distribution `Toolkit-MSF`, with literal argument boundaries and no shell. Install
the worker inside that distribution. It does not require Metasploit or RPC. A failed
readiness check reports setup instructions and leaves CSV/log detectors available.
Readiness is bounded to five seconds/64 KiB and cached for 30 seconds.

The standalone interface accepts either a literal path argument or binary stdin:

```sh
/opt/toolkit-scapy/bin/python -m toolkit_scapy_worker /path/capture.pcapng
/opt/toolkit-scapy/bin/python -m toolkit_scapy_worker < /path/capture.pcap
```

Scapy is GPL-2.0-only. See `worker/THIRD_PARTY_NOTICES.md` and the installed Scapy
license; retain notices and meet applicable source obligations if redistributing
that independent environment. The worker-owned source is MIT.

## JSONL protocol version 1

UTF-8 objects, one LF-terminated line each, go only to stdout. There is exactly one
first `meta`, then zero or more `packet`/`error` records, and one final `end`. Nothing
follows `end`. Unknown versions/properties, primitive coercions, duplicate keys,
noncanonical IPs, nonfinite/out-of-range timestamps, inconsistent counts or exit
status, missing meta/end and truncated/overlong lines cannot become success.

```json
{"v":1,"type":"meta","unit":"packets"}
{"v":1,"type":"packet","index":1,"timestamp":1700000000.125,"source_ip":"192.168.1.10","bytes":60,"protocol":"TCP"}
{"v":1,"type":"error","code":"MALFORMED_CAPTURE","message":"Capture record is truncated or malformed","index":2,"fatal":true}
{"v":1,"type":"end","emitted":1,"ignored_non_ip":0,"malformed":1,"complete":false}
```

`index` is the original one-based packet-record position, strictly increasing;
non-IP records leave gaps. `bytes` is original wire length, with captured length
used when the format lacks a wire length. Protocols retain TCP/UDP/ICMP/IP-number
classification, including IPv6 next-header fallbacks. Timestamps are finite Unix
seconds in Python's supported UTC date range. The worker preserves input order;
the desktop sorts by timestamp before either detector and reports that sorting.
`ignored_non_ip` counts decoded non-IP records; `malformed` counts rejected records.
Accepted events before a later malformed record remain available as incomplete
analysis. No packets are fabricated to repair damaged input.

Error codes are `MALFORMED_CAPTURE`, `INVALID_PACKET`, `INPUT_LIMIT`,
`MISSING_DEPENDENCY`, and `IO_ERROR`. Messages are fixed generic text, bounded to
200 characters; neither library exception contents nor arbitrary worker error
text appear in the GUI. Exit codes: 0 complete, 2 partial, 1 startup/runtime failure,
130 cancelled. A fatal error permits only the final end. A missing/invalid response
with no valid events fails with an actionable generic message.

## Framing, limits and cleanup

Each PCAP record or PCAPNG block is validated before Scapy receives packet bytes.
Declared sizes must fit the verified remaining input before allocation. PCAP
supports both byte orders and microsecond/nanosecond variants. PCAPNG validates
section byte-order magic, version, block alignment and matching trailer lengths,
interfaces, options, captured/wire sizes, timestamp resolution (decimal/binary),
offsets and section resets. Enhanced and legacy packet blocks are supported.
Simple packet blocks lack timestamps and are reported as invalid records; a
timestamp is never fabricated.

Limits: 25 MiB upload/input, 250,000 total packet records including non-IP records,
250,000 IP events, also 250,000 total PCAPNG blocks (including metadata) to bound
interface/option processing, 64 KiB per wire line, 64 KiB stderr, and a compatible total stdout
budget of `250000 * 512 + 65536` bytes. The desktop streams stdout while uploading
stdin in 64 KiB chunks and draining stderr concurrently. The 60-second wall limit
can be reduced (never enlarged) by the internal test interface.

The desktop keeps upload bytes in RAM and writes no capture file. The independent
worker may spool bounded stdin into an owner-only 0600 file in a private 0700
temporary directory, because capture framing requires seeking. It deletes the
spool on ordinary completion, handled cancellation/signals, limits or failure.
Literal path mode reads the specified file without copying it. Worker stderr is
suppressed; desktop stderr drainage never stores or renders captured text.

Cancellation before/during spawn or reads retains ownership of the helper until
its pipes drain and the child is reaped, before the workspace lease can release.
Linux terminates only the owned child. Windows sends cancellation to the worker's
random-capability private Unix socket through a second fixed-distro invocation;
it never terminates a distribution or an unrelated user process. The worker's own
60-second alarm also bounds stdin and decoding. Its private control socket is
removed before completion. No supervisor launches child decoders.
