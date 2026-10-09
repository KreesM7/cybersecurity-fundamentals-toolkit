# Verification

Run `python -m unittest discover -s tests -v` for the original fundamentals suite.
The complete v2 suite is `python -m pytest --cov --cov-report=xml`. Its required
coverage floor is 75%; it includes authenticated API, TLS, WebSocket, Qt navigation,
workspace isolation, cancellation, replay protection, vault, report and update tests.

CI runs Windows and Ubuntu 24.04 with Python 3.11 and 3.12. It enforces Black, Ruff,
strict mypy for all application packages, the full test suite, and fresh-profile startup.
Use `python -m pip install uv==0.12.24`, then
`python -m uv sync --locked --extra dev --extra build --python 3.12` to reproduce the
locked environment. `uv.lock` includes transitive versions and distribution hashes.
Pyproject remains the dependency authority; changes require regenerating and testing
the lock. Optional PDF dependencies use `--extra pdf`.

Native Metasploit integration tests require the documented dedicated Toolkit-MSF
installation and `TOOLKIT_MSF_INTEGRATION=1`. They create only controlled loopback
fixtures. General CI does not provision or run exploitation against external targets.
Saved-capture subprocess checks require the independently installed worker; missing
native components are reported as skips, while their unavailable-state tests still run.

Independent security review and installer smoke tests are separate mandatory release
gates. Passing this workflow alone is not release signoff.
