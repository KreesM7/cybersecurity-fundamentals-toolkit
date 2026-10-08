# Cybersecurity Fundamentals Toolkit

One native desktop application for seven learning and inspection tools. The v2 source uses Python3.11/3.12, PyQt6 and a private authenticated HTTPS backend inside the desktop process. Workspace data is stored locally; entered passwords and automatic analysis results stay in memory. There is no live packet capture or telemetry. The text sidebar stays available while background work runs. The v2 release is still being implemented; the handoff describes remaining features, not a completed release.

## Setup and run

Install **64-bit Python 3.12**. Open PowerShell in this project directory:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m toolkit
```

With the environment activated, the requested commands are:

```text
python -m toolkit
python -m unittest discover -s tests -v
```

On Windows, you can also double-click `Start-Toolkit.cmd` after setup, or run `.\Start-Toolkit.cmd` from PowerShell. It uses this project's environment and sets the correct working directory. Startup errors remain visible in its console.

If `py -3.12` reports **No suitable Python runtime found**, the environment was not created; the following `.venv` commands cannot work yet. Use an explicit path to a Python 3.12 executable instead. On a computer with Codex's bundled Python runtime, this fallback is available:

```powershell
$toolkitPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
if (-not (Test-Path -LiteralPath $toolkitPython)) { throw 'Codex Python runtime not found. Install 64-bit Python 3.12 first.' }
& $toolkitPython --version
& $toolkitPython -m venv .venv
if ($LASTEXITCODE -ne 0) { throw 'Environment creation failed. Resolve the error above before continuing.' }
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Package installation failed. Resolve the error above before continuing.' }
.\Start-Toolkit.cmd
```

The displayed version must be Python 3.12. The Codex cache path may change after an app update; a regular Python installation is the portable setup option.

All direct dependency pins, including the build tool, live in `requirements.txt`. Home reports readiness for each module. Missing Python or native components affect the corresponding module; the shell still opens. Click Home again to refresh readiness after changing setup. Restart after changing DLL paths.

## Use the modules

| Module | Operation and interpretation |
|---|---|
| Caesar Cipher | Encrypt/decrypt ASCII letters using shifts 1–25; all 25 decryption candidates are shown. Case, punctuation, whitespace, and non-ASCII characters survive unchanged. Input is limited to 100,000 characters. This is a teaching cipher, not secure encryption. |
| Password Strength | Masked input; Show and Clear controls. zxcvbn estimates guesses, score, and `log2(guesses)` strength bits. Maximum 72 characters; no silent truncation. Common-list check is case-insensitive against a bundled 1,000-entry attributed sample. Times at 10, 10,000, and 10 billion guesses/sec are illustrations, not measured hardware performance. |
| Network Scanner | Choose **Entered target (system routing)** for a local or public IPv4 address/CIDR, or select a detected private interface to restrict the target to that interface's subnet. Confirm ownership or permission before scanning. Maximum 256 total addresses. Fixed TCP ports: 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443. Open or closed ports prove a response; filtered/absent/timed-out results are inconclusive. Network/broadcast addresses are normally excluded by `IPv4Network.hosts()`; /31 and /32 follow Python's host rules. IPv6 and hostnames are not supported by this scanner. |
| DoS Pattern Detector | Choose a saved access log, request CSV, PCAP, or PCAPNG. Counts strictly above the threshold per source IP per UTC-aligned second are flagged. Default 100; logs/CSV count **requests**, captures count **packets**. A volume spike alone does not prove a DoS attack. |
| SQL Injection Checker | Load ordinary HTML forms from a local or public HTTP/HTTPS URL, using an IP address or hostname; select one and edit its values. Confirm ownership or testing permission. Changing the URL clears loaded forms and permission; late discovery results for a changed URL are discarded. POST starts disabled and must be explicitly enabled for each selected form. Two stable baselines precede three quote-only probes per eligible field. New SQL errors, status changes, or substantial content differences are reported as **possible issues**. At most 12 text fields are probed; hidden/select/check controls retain their values. No JavaScript rendering, authentication sessions, cookie handling, file upload, or multi-select emulation. Even benign GET/POST inputs may change a poorly designed app's data; use a disposable test app. |
| Network Anomaly Detector | Compare bytes, event counts, and protocol proportions with preceding bins. Defaults: one-second bins, 30 preceding bins, absolute z-score strictly greater than 3. The current bin never enters its own baseline. Empty bins count as zero. All baseline bins are required; otherwise "Insufficient baseline data" is reported. A changed value against zero variance is explicitly infinite z; an unchanged value has z=0. |
| File Type Identifier | libmagic reads at most the first 1 MiB and reports MIME, signature description, and extension comparison. Unknown extensions stay unknown. MIME aliases are handled for common archive/image types. Format identification does not establish safety; encrypted, polyglot, or partial files may be ambiguous. Handles are created inside each worker. |

Results and passwords stay in this process's memory. Clear removes visible password/results; Python and Qt do not guarantee secure memory erasure. Closing the app cancels workers and waits for them to finish. Cancellation discards partial task results. The scanner may take up to eight seconds to stop its current host scan; HTTP cancellation can wait for a bounded socket read. File analyses can be cancelled between records/bins. Technical tables show at most 5,000 results, with that limit disclosed in their status.

## Network boundaries

These checks live inside analysis functions, independently of the panels:

- Scanner: custom IPv4 targets can be local or public and use the operating system's routing. The entered address/CIDR must be unambiguous, aligned, and at most 256 addresses. Selecting a detected private interface instead restricts the subnet to that active RFC1918 adapter; attachment is rechecked before each host. Ownership or permission is required inside the analysis function before Nmap starts. Editing the target clears the panel's permission checkbox. Each host is a bounded TCP connect scan; there is no DNS, service detection, or Nmap script execution.
- Web: local/public IPv4/IPv6 unicast addresses and valid hostnames are accepted. `localhost` maps directly to `127.0.0.1`. Mapped/scoped IPv6, unspecified, multicast, link-local, reserved addresses, ambiguous numeric address forms, user-info URLs, and unsupported schemes are rejected. DNS answers receive the same address checks; hostname lookup is cancellable with a three-second deadline and at most two concurrent resolver threads. Each client resolves a hostname once per run, preferring IPv4, then connects to that pinned literal IP while preserving the original Host header and TLS hostname. It does not switch addresses during a run or automatically try other returned addresses. Form actions must retain the original scheme, hostname, and effective port.
- Redirects and proxy use are disabled. HTTPS certificate verification stays enabled; self-signed lab certificates must be trusted through the system's normal certificate configuration. TLS verification is never bypassed.
- One request per second across web workers; at most 40 per test run (two baselines plus at most 36 probes). Discovery is one separate request. Requests are URL encoded and limited to 64 KiB of form data. Connect timeout 3 seconds, read timeout 5 seconds, body-read deadline 10 seconds, maximum response 1 MiB. A 15-second watchdog bounds the whole request, including slow headers, and interrupts active sockets on cancellation. Servers must honor uncompressed responses. Dynamic baselines stop anomaly testing. Content similarity uses at most 1,024 block fingerprints across each response; this bounded heuristic can flag benign changes or miss subtle differences.
- Only `'`, `"`, and `''` probes are used. There are no destructive, stacked-query, extraction, or delay payloads. POST requires both ownership/permission confirmation and explicit enablement before any test request.

Address validation does not prove permission. Use only targets you own or are authorized to assess.

## Saved input formats

Text files use UTF-8. `.csv` identifies CSV, `.pcap`/`.pcapng` identifies captures, and other extensions are treated as Common/Combined access logs. Choose the correct extension. Maximum file size is 25 MiB and maximum accepted events is 250,000. Events are sorted by timestamp before analysis. Malformed rows are excluded, with row/line positions, skipped counts, and an **INCOMPLETE analysis** label; no valid events is an error. Captures receive a framing check so malformed/truncated files do not silently appear complete. Non-IP packets are excluded with a note. Payloads are not retained.

Request CSV requires:

```csv
timestamp,source_ip
2026-10-06T00:00:01Z,10.0.0.8
1791244802.25,10.0.0.9
```

Traffic CSV for anomaly detection requires all four columns:

```csv
timestamp,source_ip,bytes,protocol
2026-10-06T00:00:01+00:00,10.0.0.8,1200,TCP
2026-10-06T00:00:02Z,10.0.0.9,64,UDP
```

Timestamps are finite Unix seconds or timezone-bearing ISO timestamps. Naive dates are rejected. `source_ip` is a literal IPv4/IPv6 address; byte counts are nonnegative integers; protocol labels are normalized to uppercase. Extra CSV columns are ignored. Access logs use their explicit timezone, response byte count, and protocol label `HTTP`; unknown byte counts (`-`) can count as requests but are excluded from byte-volume analysis. PCAP byte volume uses recorded on-wire length, and protocol proportions count IP events, not bytes. These sources measure different things; compare like with like. Anomaly spans are limited to 100,000 bins and 64 distinct protocol labels; increase bin size, group uncommon protocols, or split long inputs. All anomalies are counted, but only the first 5,000 details are retained/displayed.

See [`examples/README.md`](examples/README.md) for reproducible small inputs and expected results.

## Windows native prerequisites

**Nmap:** Install the external executable from [Nmap's Windows instructions](https://nmap.org/book/inst-windows.html). It is discovered through `TOOLKIT_NMAP`, then `PATH`, then the standard `Program Files\Nmap` locations. For a custom install:

```powershell
$env:TOOLKIT_NMAP = 'C:\Program Files (x86)\Nmap\nmap.exe'
python -m toolkit
```

The toolkit uses unprivileged `-sT -Pn -n` connect scans, a fixed port preset, one retry, a five-second host timeout, and an eight-second process timeout per host. It manages the hidden Windows subprocess and uses python-nmap's XML analysis API; its constructor is bypassed to avoid an unbounded version subprocess and extra console windows. It does not install a capture driver. Nmap's own installer may offer Npcap, which this saved-file application does not need. A /24 can take several minutes when hosts do not respond. No live LAN scan is included in automated tests.

**libmagic:** `python-magic` is only a Python wrapper. It needs a matching **x64 DLL, all dependent DLLs, and magic database**. One compatible route is the [MSYS2 UCRT64 file package](https://packages.msys2.org/packages/mingw-w64-ucrt-x86_64-file). In an installed MSYS2 UCRT64 shell:

```text
pacman -S mingw-w64-ucrt-x86_64-file
```

Then start the Python app from PowerShell with:

```powershell
$env:PATH = 'C:\msys64\ucrt64\bin;' + $env:PATH
$env:TOOLKIT_MAGIC_FILE = 'C:\msys64\ucrt64\share\misc\magic.mgc'
python -m toolkit
```

Use one distribution/version for the DLL and database; keep dependent DLLs beside it. The wrapper recognizes `libmagic-1.dll`, among other standard names. Do not mix 32/64-bit files. If setup fails, the module displays instructions while the remaining toolkit opens. See [python-magic's installation notes](https://pypi.org/project/python-magic/). This delivery does not redistribute Nmap, libmagic, or MSYS2 native packages.

## Tests and local packaging

Run the complete unittest command above. Tests use generated inputs and temporary loopback HTTP servers. Public-address and hostname behavior uses controlled DNS/transport fixtures; no real public target is contacted. Qt tests use the offscreen platform and check all panels, custom routing, permission resets, worker delivery on the main thread, responsiveness, cancellation, shutdown, dependency failure isolation, discovery, and resources from another working directory. The real renamed-PNG test skips with a stated reason if external libmagic is absent. Set up libmagic as above to run it. Local socket restrictions in a managed execution environment may need permission for the loopback fixture.

For a **local Windows x64 build**, use the same Python 3.12 environment:

```powershell
python -m PyInstaller --noconfirm --clean toolkit.spec
.\dist\CybersecurityFundamentalsToolkit\CybersecurityFundamentalsToolkit.exe
```

The spec uses windowed mode and one folder, automatically collects discovered modules and bundled resources, and copies examples/notices. New modules are collected on rebuild. External Nmap and libmagic setup is still required. On Windows the spec limits native DLL discovery to the selected Python and Windows system directories, avoiding unrelated DLLs on PATH (in particular incompatible third-party ICU copies). Qt uses Windows' system ICU. `python -m toolkit --self-test` and the corresponding executable `--self-test` return exit code 0 after checking panel creation and bundled-resource access without opening a window. They do not perform active scans or probes.

**Executable distribution is a later release step.** The requested Scapy GPL-2.0-only and python-nmap GPL-3.0 components create an unresolved combined-binary licensing issue. A local successful build does not resolve it. See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) before any redistribution; the MIT license applies only to our source. Signing, installer production, distribution licensing, and native binary inclusion are not part of this delivery.

## Add a module

Create one new `.py` file in `toolkit/modules/` (names starting `_` are ignored). Separate ordinary analysis functions and result dataclasses from lazy Qt panel creation in that file:

```python
from dataclasses import dataclass
from toolkit.core import ModuleSpec

@dataclass
class Result:
    value: str

def analyze(value, task):
    task.check()
    task.report('Analyzing...')
    return Result(value.upper())

def create_panel(context):
    from toolkit.widgets import TaskPanel
    panel = TaskPanel(context, 'Example', 'Description of this local tool.')
    panel.add_footer()
    panel.run_button.clicked.connect(lambda: panel.start(
        lambda task: analyze('example', task),
        lambda result: panel.status.setText(result.value)))
    return panel

MODULE = ModuleSpec('example', 'Example', 80, create_panel)
```

Optionally define `readiness()` returning an actionable message or `''` for ready. Import optional libraries inside analysis/readiness; import Qt panel helpers inside the factory. Missing dependencies and load/factory exceptions are isolated. IDs must be unique lowercase words with hyphens. Factories accept shared `AppContext` and return a Qt widget. `context.run_task(...)` provides cancellation/progress and main-thread callbacks; `context.resource_text(name)` reads bundled UTF-8 resources independent of working directory. Workers receive ordinary data snapshots, never widgets; analysis functions enforce their own target restrictions. Add resources under `toolkit/resources/`, tests under `tests/`, and rebuild the spec to include the new module.

Git history is local and records verified implementation slices. Errors remain local; no Sentry telemetry is configured.

## Metasploit setup (v2)

See [dedicated Toolkit-MSF provisioning and verified TLS connection](docs/MSFRPC_SETUP.md). This setup leaves other WSL distributions untouched.
