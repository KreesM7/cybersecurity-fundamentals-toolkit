import sys

from backend.bootstrap import prepare_backend


def test_windowed_bootstrap_without_console_streams(tmp_path, monkeypatch):
    # PyInstaller --windowed sets these to None; Uvicorn's default formatter
    # otherwise calls isatty() and prevents the desktop backend from starting.
    with monkeypatch.context() as patch:
        patch.setattr(sys, "stdout", None)
        patch.setattr(sys, "stderr", None)
        instance = prepare_backend(tmp_path)
    instance.listener.close()
    instance.lease.close()
