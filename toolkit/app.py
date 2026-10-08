"""Compatibility desktop entry; the application uses one PyQt6 runtime."""

from frontend.app import main
from frontend.main_window import MainWindow
from frontend.theme import apply_theme as configure_theme

__all__ = ["MainWindow", "configure_theme", "main"]
