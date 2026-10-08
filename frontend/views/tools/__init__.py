"""Stable seven-panel factory with isolated import/factory failures."""

from importlib import import_module

from PyQt6.QtWidgets import QPlainTextEdit, QWidget

from frontend.viewmodels.tools_vm import ToolsViewModel

PANELS = (
    ("caesar", "Caesar Cipher"),
    ("password-strength", "Password Strength"),
    ("network-scanner", "Network Scanner"),
    ("dos-detector", "DoS Pattern Detector"),
    ("sql-checker", "SQL Injection Checker"),
    ("anomaly-detector", "Network Anomaly Detector"),
    ("file-type", "File Type Identifier"),
)


def create_panel(tool_id: str, view_model: ToolsViewModel) -> QWidget:
    try:
        module = import_module("frontend.views.tools." + tool_id.replace("-", "_"))
        panel = module.Panel(view_model)
        if not isinstance(panel, QWidget):
            raise TypeError("Panel factory must return a widget")
        return panel
    except Exception:
        missing = QPlainTextEdit(
            "Tool panel unavailable. Check the installed extension and its frontend requirements."
        )
        missing.setReadOnly(True)
        return missing
