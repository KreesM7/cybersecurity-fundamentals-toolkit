# Supply-chain controls

The existing Windows/Linux quality matrix is unchanged. Separate CI jobs audit
the synchronized locked environment, scan all reachable Git refs/history with
Gitleaks, and run default Python CodeQL queries for pushes/PRs targeting main.
Actions and hooks are pinned to commits; scanner downloads are checksum pinned.
Dependabot groups weekly minor/patch updates, leaving majors in individual PRs.

## Vulnerability exception policy

`scripts/audit_dependencies.py` audits exact installed versions after `uv sync
--locked`, including development/build/security tools. Only this editable project's
own source is excluded from the published-package lookup. Unknown packages,
incomplete dependency collection, malformed reports, and audit-service failures
fail closed. Any advisory with a published fix fails the job.

An advisory with an empty upstream `fix_versions` list is a nonblocking exception
requested for this project. It is always reported as a CI warning and in the job
summary. Each run publishes `dependency-audit/audit.json`,
`no-fix-exceptions.json`, `exceptions.md`, and the exact audited package snapshot.
There is no permanent CVE ignore list: a newly available fix automatically makes
the same advisory blocking. Review exceptions weekly with Dependabot changes.

Initial local audit on 2026-10-11: `pymetasploit3==1.0.6`, advisory
`PYSEC-2026-500` (`CVE-2026-5463`, `GHSA-qpc3-8vqg-8g6w`), had no published fixed version.
The advisory concerns command injection through console module options; the
toolkit's existing module-option validation remains enforced. The run artifacts remain the
authoritative, complete exception list; this historical observation is not an
authorization to suppress future findings.

## Provisioning

The provisioner builds the worker with `scripts/build_worker_wheel.py`, a
deterministic standard-library wheel writer. It then installs that wheel and
Scapy with `pip install --require-hashes -r worker/requirements-provision.txt`.
PTY dependencies use `scripts/requirements/pty.txt` in their separate environment.
The committed worker-wheel hash detects source drift; rebuild and review/update
that hash whenever worker source changes. PyPI requirements include upstream
SHA-256 hashes, and pip verifies every downloaded/transitive distribution.
CI tests both installations in fresh virtual environments. Scapy remains outside
the main desktop distribution and lock.

## Historical fixture removal

The old `tests/fixtures/local-key.txt` was publicly documented test material, not
a deployed credential. It and `local-cert.txt` are replaced by an ephemeral pytest
fixture. Deleting the current files does not erase historical commits. A separate
mirror rewrite with git-filter-repo/BFG must remove both paths from all branches
and tags, followed by a fresh-clone full-history Gitleaks scan. Coordinate the
rewrite: commit IDs and tag targets change; collaborators must re-clone instead
of merging old history back. No scanner exception may hide the fixture.

GitHub may retain cached commit views or pull-request refs outside writable Git
refs. Their removal can require GitHub Support; existing clones and previously
downloaded source archives cannot be remotely erased. Keep the history-rewrite
verification evidence with the PR. See GitHub's
[sensitive-data removal guide](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).
