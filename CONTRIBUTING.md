# Contributing

Use Python 3.11 or 3.12 and `uv sync --locked --extra dev --extra build`.
Run Black and Ruff on backend, frontend, shared, toolkit, tests and scripts;
run strict mypy on the four application packages; run `pytest --cov` with the
75% minimum coverage. CI verifies Windows and Ubuntu with both Python versions.

Use controlled fixtures and loopback targets. Do not include real credentials,
captures, payload artifacts, private profiles or native installers in commits.
TLS rejection tests generate disposable certificate/key pairs through pytest's
`local_tls_pair` fixture; never commit even test-only private keys.

Install local gates after cloning:

```sh
uv sync --locked --extra dev --extra build --group security
uv run pre-commit install
uv run pre-commit run --all-files
uv run pre-commit run --hook-stage pre-push --all-files
```

The config installs pre-commit and pre-push hooks. Black/Ruff versions match CI;
Gitleaks checks staged changes before commit and full history before push. Its
downloaded binary is verified against a committed SHA-256 pin on every run.
The first run needs access to the pinned upstream tools. No scanner allowlist is
used. Update the pinned hook versions together with pyproject.toml and uv.lock.

Weekly Dependabot pip/Actions updates group minor/patch versions; majors remain
individual PRs. Regenerate `uv.lock` for pip updates (pip does not maintain uv's
lock), and regenerate provisioning hashes after reviewing a dependency update.
See docs/SUPPLY_CHAIN.md for audit exceptions and history cleanup.

Keep frontend/backend boundaries and independently installed worker interfaces
intact. Document new native prerequisites. Use stable mutation IDs and never
automatically repeat unknown external commands. Add focused regression tests for
logic changes. Security-relevant changes need independent review before release.

Submit small changes with a problem statement, resulting behavior, and actual
verification evidence. Update the lock when dependencies change. Do not fabricate
fixes or history. Our original code contributions are MIT; combined-binary
redistribution must also satisfy the third-party terms described in the notices.
