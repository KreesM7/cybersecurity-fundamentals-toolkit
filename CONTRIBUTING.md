# Contributing

Use Python 3.11 or 3.12 and `uv sync --locked --extra dev --extra build`.
Run Black and Ruff on backend, frontend, shared, toolkit, tests and scripts;
run strict mypy on the four application packages; run `pytest --cov` with the
75% minimum coverage. CI verifies Windows and Ubuntu with both Python versions.

Use controlled fixtures and loopback targets. Do not include real credentials,
captures, payload artifacts, private profiles or native installers in commits.
The intentionally untrusted public TLS key in tests/fixtures is a rejection-test
fixture; it is never application trust material.

Keep frontend/backend boundaries and independently installed worker interfaces
intact. Document new native prerequisites. Use stable mutation IDs and never
automatically repeat unknown external commands. Add focused regression tests for
logic changes. Security-relevant changes need independent review before release.

Submit small changes with a problem statement, resulting behavior, and actual
verification evidence. Update the lock when dependencies change. Do not fabricate
fixes or history. Our original code contributions are MIT; combined-binary
redistribution must also satisfy the third-party terms described in the notices.
