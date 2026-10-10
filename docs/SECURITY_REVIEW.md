# Independent release security review

Reviewer: independent Codex review agent `/root/release_security_review`, not the author of the safeguards.

Initial source: `b83fd0ab48555bb977395e3dd3ff713e82537e20`. Signoff withheld for three important cleanup defects: payload pipe pressure could prevent teardown, a failing PTY cancellation helper skipped cleanup, and the desktop's 15-second wait was shorter than service cleanup bounds.

Approved application source: **`a7a1ae650678ff45b648aea2452fad967d9264c1`**. Targeted independent rereview found all three blockers resolved: both helper pipes are drained; PTY EOF/reaping runs despite control-channel errors; Qt remains responsive and retains the backend until actual shutdown. Spawn cancellation also retains payload ownership. Same-size artifact tampering now fails SHA-256 verification. Workspace deletion explicitly warns that external session/job associations are lost while external activity remains running.

Scope: target enforcement, REST/WSS authentication and TLS, RPC/PTY/payload/capture subprocess boundaries, workspace isolation and associations, vault lifecycle, credential handling/redaction, exports and report resource restrictions. No remaining critical/high finding was identified within the inspected scope. Redaction remains pattern based; external framework processes are not stopped by deleting saved records.

Evidence: author-run targeted tests returned **12 passed, 1 skipped in 20.57 seconds**, including pipe saturation, cancellation helper OSError/TimeoutError/ValueError, event processing during shutdown beyond 15 seconds, and artifact tampering. Ruff and strict mypy (113 application files) passed. The reviewer inspected these test cases and their recorded result; they did not independently rerun the successful tests. Earlier reviewer test attempts stalled and were interrupted, and were not counted as passing evidence.

This is a source review, not a penetration-test certification or legal opinion. Pending packaging/documentation were outside the approval scope. Installer/compliance and final CI are separate gates. A subsequent security-relevant application change requires another review.
