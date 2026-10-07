@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo The toolkit's Python environment has not been set up.
    echo Follow "Setup and run" in README.md, then try again.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" -m toolkit %*
if errorlevel 1 (
    echo.
    echo The toolkit could not start. The error is shown above.
    pause
    exit /b 1
)
exit /b 0
