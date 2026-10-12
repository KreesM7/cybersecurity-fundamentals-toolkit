"""One PyQt6 runtime, authenticated TLS backend bootstrap and orderly ownership."""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication, QLabel

from backend.bootstrap import InstanceLocator
from backend.platform_utils import get_config_dir
from backend.tls import TLSMaterial
from frontend.icons import app_icon
from frontend.main_window import MainWindow
from frontend.runtime import BackendThread, finish_backend
from frontend.theme import SIZE, apply_theme
from frontend.viewmodels.app_vm import AppViewModel
from frontend.views.tools.base import ToolPanel


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cybersecurity Fundamentals Toolkit desktop")
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--self-test-report", type=Path)
    args = parser.parse_args(argv)
    temporary = tempfile.TemporaryDirectory() if args.self_test and args.profile is None else None
    profile = args.profile or (Path(temporary.name) if temporary else get_config_dir())
    if args.self_test:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    application = QApplication(sys.argv[:1])
    application.setApplicationName("Cybersecurity Fundamentals Toolkit")
    apply_theme(application, "dark")
    application.setWindowIcon(app_icon())
    launcher = QLabel("Starting the authenticated local backend…")
    launcher.setWindowTitle("Cybersecurity Fundamentals Toolkit")
    launcher.resize(SIZE["launcher_w"], SIZE["launcher_h"])
    launcher.show()
    backend = BackendThread(profile)
    windows: list[MainWindow] = []
    models: list[AppViewModel] = []
    result = 0

    def failed(message: str) -> None:
        nonlocal result
        result = 2
        launcher.setText(message)
        if args.self_test:
            if args.self_test_report:
                args.self_test_report.write_text(
                    json.dumps({"ok": False, "message": message}), "utf-8"
                )
            application.exit(result)

    def ready(locator: object, material: object, owned: bool) -> None:
        if not isinstance(locator, InstanceLocator) or not isinstance(material, TLSMaterial):
            failed("Invalid backend startup result. Restart the application.")
            return
        model = AppViewModel(
            f"https://127.0.0.1:{locator.port}",
            material.client_context(),
            locator.token.get_secret_value(),
        )
        window = MainWindow(model)
        models.append(model)
        windows.append(window)
        launcher.hide()
        window.show()
        model.refresh_health()
        model.refresh_tools()
        if args.self_test:

            def finish(values: object) -> None:
                if len(window.panels) != 7 or not all(
                    isinstance(panel, ToolPanel) for panel in window.panels.values()
                ):
                    failed("Seven tool panels could not be created.")
                    return
                for index in range(window.stack.count()):
                    window.stack.setCurrentIndex(index)
                if args.self_test_report:
                    args.self_test_report.write_text(
                        json.dumps({"ok": True, "panels": window.stack.count()}), "utf-8"
                    )
                window.close()
                application.exit(0)

            model.tools_changed.connect(finish)

    backend.ready.connect(ready)
    backend.failed.connect(failed)
    backend.start()
    timeout = QTimer()
    if args.self_test:
        timeout.setSingleShot(True)
        timeout.timeout.connect(
            lambda: failed("Desktop startup timed out. Check backend prerequisites.")
        )
        timeout.start(20000)
    try:
        exit_code = application.exec()
        return result or exit_code
    finally:
        for model in models:
            if model.is_running:
                model.close()
        finish_backend(backend, application, launcher)
        if temporary is not None:
            temporary.cleanup()
