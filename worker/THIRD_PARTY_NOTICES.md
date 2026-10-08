# Independent worker dependency

Scapy 2.8.0 is GPL-2.0-only, Copyright Philippe Biondi and contributors.
Upstream source and license: https://github.com/secdev/scapy (v2.8.0).
The installed Scapy distribution supplies its COPYING license. Anyone redistributing
the worker environment must retain that license and meet the GPL source obligations.
The desktop distribution excludes both this worker and Scapy; the worker is a
separately installed process communicating through the documented JSONL protocol.
Worker-owned code is MIT, under the repository LICENSE. This source separation is
not a claim of verification of any future binary release.
