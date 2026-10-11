# Independent release security review

Reviewer: independent Codex review agent `/root/release_security_review`, not the author of the safeguards.

Initial source: `b83fd0ab48555bb977395e3dd3ff713e82537e20`. Signoff withheld for three important cleanup defects: payload pipe pressure could prevent teardown, a failing PTY cancellation helper skipped cleanup, and the desktop's 15-second wait was shorter than service cleanup bounds.

Approved application source: **`a7a1ae650678ff45b648aea2452fad967d9264c1`**. Targeted independent rereview found all three blockers resolved: both helper pipes are drained; PTY EOF/reaping runs despite control-channel errors; Qt remains responsive and retains the backend until actual shutdown. Spawn cancellation also retains payload ownership. Same-size artifact tampering now fails SHA-256 verification. Workspace deletion explicitly warns that external session/job associations are lost while external activity remains running.

Scope: target enforcement, REST/WSS authentication and TLS, RPC/PTY/payload/capture subprocess boundaries, workspace isolation and associations, vault lifecycle, credential handling/redaction, exports and report resource restrictions. No remaining critical/high finding was identified within the inspected scope. Redaction remains pattern based; external framework processes are not stopped by deleting saved records.

Evidence: author-run targeted tests returned **12 passed, 1 skipped in 20.57 seconds**, including pipe saturation, cancellation helper OSError/TimeoutError/ValueError, event processing during shutdown beyond 15 seconds, and artifact tampering. Ruff and strict mypy (113 application files) passed. The reviewer inspected these test cases and their recorded result; they did not independently rerun the successful tests. Earlier reviewer test attempts stalled and were interrupted, and were not counted as passing evidence.

This is a source review, not a penetration-test certification or legal opinion. Pending packaging/documentation were outside the approval scope. Installer/compliance and final CI are separate gates. A subsequent security-relevant application change requires another review.

## 2026-10-10 vault and redaction hardening

Independent reviewer `/root/hardening_review` inspected the five ordered security changes and their follow-up fixes. Review found quadratic secret-name scanning, plaintext unlock tokens in replay storage, and non-string JSON secrets escaping redaction. A second review found quadratic scanning of malformed escaped quotes. All findings were fixed and the final read-only review reported no additional actionable regression. Independent probes processed 64 KiB of underscores in 0.0082 seconds and escaped quotes in 0.0164 seconds. The reviewer inspected migration transactions, cancellation ownership, key wiping and shared WebSocket cleanup; the author ran the full suites.

The full suite ran after every requested item, in order, with the independent Scapy worker configured:

| Checkpoint | Passed | Skipped | Coverage |
| --- | ---: | ---: | ---: |
| 1. Redaction | 275 | 11 | 78.20% |
| 2. Opaque sessions | 276 | 11 | 78.21% |
| 3. Unlock hardening | 282 | 11 | 78.49% |
| 4. Argon2id migration | 288 | 11 | 78.53% |
| 5. Key wiping, audit, WebSockets | 315 | 11 | 78.72% |
| Final reviewed corrections | 328 | 11 | 78.82% |

Each run also passed 50 subtests. The existing Starlette TestClient deprecation warning remains. Final Black, Ruff and strict mypy checks passed; the lock is consistent and contains no python-jose, ecdsa, rsa or pyasn1 distributions. A disposable-profile desktop check passed all 17 screens. `backend/auth.py`, `backend/tls.py`, `backend/bootstrap.py`, `toolkit/security.py`, and `backend/services/module_service.py` are byte-for-byte unchanged from baseline `29219bb`.

Migration verification used copied fixtures, never a user's vault. Actual four-job CI KDF measurements are recorded in VAULT.md. This record covers source changes; the previously published v2.0.0 installer assets have not been replaced.

The first final CI run exposed a race in the existing WebSocket TestClient teardown on Linux 3.11. Repetition reproduced it locally: TestClient cancelled its AnyIO scope while the ASGI route was still gathering cancelled children. The test now explicitly closes the connection and waits for ASGI completion, with a timeout and an empty-subscription assertion, before context exit. Forty consecutive lifecycle repetitions passed. Independent review agreed with fixing test synchronization; production cancellation propagation and all authentication checks remain unchanged.
