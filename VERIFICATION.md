# Delivery verification

Verified locally on 2026-10-06 with Windows 11 x64 (build 26200), Python 3.12.14, and the exact direct dependency versions in `requirements.txt`.

- Complete unittest suite: **41 tests passed**, including the real libmagic renamed-PNG test when configured with matching x64 MSYS2 UCRT64 file 5.48 DLL/database and dependencies. Native components were downloaded into scratch storage and checked against the package publisher's SHA256 values; they are not part of the source deliverable.
- Independent reviewer: approved the network safeguards after fixes for slow HTTP/chunk framing, repetitive-response comparison, and high protocol cardinality. The independent environment passed 40 tests with one explicitly skipped native libmagic test; the primary environment ran that test successfully.
- Controlled loopback fixtures verified GET discovery/probes, POST blocked without explicit permission, enabled POST, the request budget, public-target rejection, redirect blocking, cross-origin exclusions, oversized responses, slow headers/body/chunked-response cancellation, and rejection of an untrusted HTTPS certificate. No public targets or real LAN devices were scanned.
- Scanner verification used controlled process output and the actual python-nmap XML parser, plus interface/target guards. **Real Nmap execution and routing remain unverified here because the external executable is not installed.** Home provides the setup message.
- Qt checks covered navigation through all seven panels, dependency failure isolation, worker results on the main thread, event-loop responsiveness, cancellation, shutdown, password masking/Clear, module discovery, and resources from a different working directory.
- Saved-file checks covered threshold boundaries, out-of-order CSV and access logs, malformed rows, valid and truncated PCAP/PCAPNG, short baselines, explicit zero variance, bounded protocol labels, and bounded retained results. Synthetic examples were checked against their documented expected results.
- `pip check` reported no broken requirements.
- The project's own `.venv` was created with the available Codex Python 3.12.14 runtime and populated from `requirements.txt`. `Start-Toolkit.cmd --self-test` passed from a different directory, and the normal source launch opened the native toolkit window. This also verifies setup without a Python runtime registered with the Windows launcher.
- PyInstaller 6.22.3 produced a windowed one-folder local build. Its `--self-test` exited **0** from a different directory after the recipe isolated native DLL discovery from unrelated PATH entries. The spec collected all seven modules and bundled resources/examples. The test build stays in scratch storage; no executable distribution is delivered.

Application previews are in `toolkit-home.png`, `toolkit-caesar.png`, and `toolkit-anomalies.png`. They show the actual native widgets using synthetic inputs. Offscreen rendering in this managed Windows environment required explicitly loading installed system fonts for the preview process; no fonts are redistributed. The Home preview was taken with scratch libmagic configured and Nmap absent.

See README for operational limits and native setup. The combined-binary license issue involving the retained GPL dependencies remains unresolved for any later executable release.
