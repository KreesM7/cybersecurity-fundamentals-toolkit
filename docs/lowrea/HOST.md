# LowREA host integration

Host: Python 3.11/3.12, PyQt6 desktop; FastAPI/uvicorn authenticated local backend; setuptools packaging and uv.lock. Tests use pytest/pytest-asyncio/pytest-cov, Black, Ruff and strict mypy. GitHub Verify has Windows/Linux Python 3.11/3.12 lanes, dependency audit, full-history Gitleaks, CodeQL and a non-root container test. Inno Setup/PyInstaller and AppImage releases use detached keyless Sigstore signatures and commit-bound CycloneDX inventories.

Baseline at bc5f417: 383 passed, 8 skipped, 50 subtests passed; coverage 80.98%. No host source was changed before this baseline.

Attach points: toolkit/__main__.py dispatches a lazy `lowrea` namespace;
backend/routers/lowrea.py submits authenticated RAM-only static jobs and
frontend/views/lowrea.py presents their digest-validated results. Job progress
contains generic status only. Artifact evidence uses the job result field,
which is not heuristically redacted or sent to activity history. Existing
authentication, workspace leases and mutation request IDs remain enforced.
backend/platform_utils.py provides bounded subprocess ownership for future runtime work;
that work is not implemented here.

Code lives under toolkit/lowrea/. Capstone and the official MCP SDK are locked
core dependencies for the delivered desktop/CLI/stdio operation. Capstone's native
library is collected by toolkit.spec. Evidence remains independent of Qt and routes.
Use source console Python for MCP; the Windows GUI executable has no stdio contract.

Host wiring edit: toolkit/__main__.py dispatches the explicit lowrea namespace lazily, preserving the default desktop entrypoint. New test: tests/test_lowrea.py. Rollback: remove toolkit/lowrea/, tests/test_lowrea.py and docs/lowrea/; restore toolkit/__main__.py from bc5f417. Existing user-staged Start-Toolkit.ps1 is preserved separately.

Protected network, authentication, TLS, bootstrap and module-option validation code remains unchanged.

README.md: appended a source-only LowREA operation and linked its status/design. Rollback also removes this appended section. No original host documentation was overwritten.
