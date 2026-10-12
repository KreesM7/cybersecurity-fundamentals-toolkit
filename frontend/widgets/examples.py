"""Safe sample filling; never submits requests or checks ownership."""

import sys
from importlib.resources import files
from pathlib import Path

from PyQt6.QtWidgets import QCheckBox, QLineEdit, QPlainTextEdit, QSpinBox, QWidget


def example_path(name: str) -> Path:
    bundled = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[2])) / "examples"
    return (
        bundled / name
        if (bundled / name).is_file()
        else Path(str(files("frontend").joinpath("resources/examples", name)))
    )


def fill_example(panel: QWidget, key: str) -> None:
    values: dict[str, dict[str, str | int]] = {
        "caesar": {"source": "Hello, World!", "shift": 3},
        "password-strength": {"password": "password"},
        "network-scanner": {"target": "127.0.0.1/32"},
        "sql-checker": {"url": "http://127.0.0.1:8000/"},
        "dos-detector": {"file_path": str(example_path("requests.csv")), "threshold": 100},
        "anomaly-detector": {
            "file_path": str(example_path("traffic.csv")),
            "baseline": 30,
            "interval": 1,
        },
        "file-type": {"file_path": str(example_path("access.log"))},
        "modules": {"query": "scanner/http/title"},
        "payloads": {"search": "linux/x64", "host": "127.0.0.1", "port": 4444},
    }
    for name, value in values[key].items():
        widget = getattr(panel, name, None)
        if isinstance(widget, QLineEdit):
            widget.setText(str(value))
        elif isinstance(widget, QPlainTextEdit):
            widget.setPlainText(str(value))
        elif isinstance(widget, QSpinBox):
            widget.setValue(int(value))
    for name in ("owned", "post"):
        widget = getattr(panel, name, None)
        if isinstance(widget, QCheckBox):
            widget.setChecked(False)
