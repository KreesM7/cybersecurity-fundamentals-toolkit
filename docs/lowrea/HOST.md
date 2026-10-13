# LowREA host integration

Host: Python 3.11/3.12, PyQt6 desktop; FastAPI/uvicorn authenticated local backend; setuptools packaging and uv.lock. Tests use pytest/pytest-asyncio/pytest-cov, Black, Ruff and strict mypy. GitHub Verify has Windows/Linux Python 3.11/3.12 lanes, dependency audit, full-history Gitleaks, CodeQL and a non-root container test. Inno Setup/PyInstaller and AppImage releases use detached keyless Sigstore signatures and commit-bound CycloneDX inventories.

Baseline at bc5f417: 383 passed, 8 skipped, 50 subtests passed; coverage 80.98%. No host source was changed before this baseline.

Attach points: toolkit/__main__.py can dispatch a lazy `lowrea` namespace; backend services/routers and frontend panels are later integration points. No lowrev seed exists. backend/platform_utils.py provides bounded async subprocess execution, literal arguments, timeout and child reaping; descendant ownership must be assessed before runtime use. Existing event and task services use secret redaction, so LowREA artifact evidence must not be routed through them without an explicit sensitivity boundary.

Code lives under toolkit/lowrea/. Optional native/MCP dependencies will be extras, not host core requirements. Evidence remains independent of Qt, routes and providers.

Host wiring edit: toolkit/__main__.py dispatches the explicit lowrea namespace lazily, preserving the default desktop entrypoint. New test: tests/test_lowrea.py. Rollback: remove toolkit/lowrea/, tests/test_lowrea.py and docs/lowrea/; restore toolkit/__main__.py from bc5f417. Existing user-staged Start-Toolkit.ps1 is preserved separately.

Protected network, authentication, TLS, bootstrap and module-option validation code remains unchanged.

README.md: appended a source-only LowREA operation and linked its status/design. Rollback also removes this appended section. No original host documentation was overwritten.
