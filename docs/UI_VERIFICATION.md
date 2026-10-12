# Desktop presentation verification

Validated on Windows x64 with Python 3.12.

- Full pytest suite: 348 passed, 11 skipped, 50 subtests; coverage 80.24% (minimum 75%).
- Black check, Ruff and strict mypy passed; `uv lock --check` passed.
- `python -m toolkit --self-test` passed.
- Thirteen presentation tests cover all 17 pages, input help/accessibility, nine guides,
  keyboard traversal through visible page/tab controls, safe examples, contrast,
  icon sizes, module selection and ownership reset, guided Stop context, and status updates.
- Both-theme screenshots cover every page, plus module configuration/review and guided/advanced console.
  These use a labeled offline fixture; they do not claim a live Metasploit connection.
- A separate reviewer checked the UI changes. Four findings were reproduced and corrected:
  guided module authorization reset, exact saved-module selection, stale guided Stop selection,
  and preservation of dashboard connection state during vault updates. Targeted re-review passed.
- Backend, authentication, TLS, target restrictions, redaction, API transport and ViewModel
  contracts have no changes in this update.

## Reproduce

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
.\.venv\Scripts\python.exe -m pytest --cov -q
.\.venv\Scripts\python.exe -m black --check backend frontend shared toolkit tests scripts
.\.venv\Scripts\python.exe -m ruff check backend frontend shared toolkit tests scripts
.\.venv\Scripts\python.exe -m mypy backend frontend shared toolkit
.\.venv\Scripts\python.exe -m toolkit --self-test
.\.venv\Scripts\python.exe scripts/capture_ui.py
```

Set `TOOLKIT_TEST_WORKER` to the separate worker interpreter for worker integration tests.
The test run retained one existing upstream FastAPI/Starlette deprecation warning.
Windows offscreen captures explicitly load installed system fonts; normal native startup
continues to use platform fonts. The test suite keeps one QApplication for its lifetime.

Console **Save artifact** exports the redacted display as a local text file. It does not
register an artifact in the workspace catalog. Existing packaged releases must be rebuilt
from this source to include the UI update; no release was published during verification.
