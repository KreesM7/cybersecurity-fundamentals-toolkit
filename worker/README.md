# toolkit-scapy-worker

An independently installed Python 3.11/3.12 saved-capture decoder. Install this
directory into a separate Linux environment (Windows uses Toolkit-MSF WSL):

```sh
python3 -m venv /opt/toolkit-scapy
/opt/toolkit-scapy/bin/python -m pip install .
/opt/toolkit-scapy/bin/python -m toolkit_scapy_worker --check
```

`toolkit-scapy-worker capture.pcap` reads a literal path; omit the argument to read
bounded binary stdin. Only version-one UTF-8 JSONL metadata/packet/error/end records
are written to stdout. Scapy 2.8.0 is the sole runtime dependency. The application,
GUI, authentication, database and desktop shared package are not dependencies.
See the repository's `docs/SCAPY_WORKER.md` for the full wire contract and limits.
See `THIRD_PARTY_NOTICES.md` for Scapy's GPL-2.0-only notices.
