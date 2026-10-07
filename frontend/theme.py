"""CWD-independent flat themes packaged alongside the desktop application."""

from dataclasses import dataclass
from importlib.resources import files
from typing import Literal

import darkdetect
from PyQt6.QtWidgets import QApplication


@dataclass(frozen=True)
class ThemeTokens:
    """Presentation colors shared by custom widgets."""

    background: str
    foreground: str
    accent: str
    border: str


def load_theme(mode: Literal["system", "dark", "light"]) -> tuple[str, ThemeTokens]:
    """Resolve system preference and load a bundled stylesheet from any directory."""
    selected = "dark" if mode == "system" and darkdetect.isDark() else mode
    if selected == "system":
        selected = "light"
    if selected not in {"dark", "light"}:
        raise ValueError("Unknown theme")
    tokens = (
        ThemeTokens("#15191e", "#edf1f5", "#5fa9f0", "#3b4651")
        if selected == "dark"
        else ThemeTokens("#f5f7f9", "#17212b", "#1765ad", "#a9b4c0")
    )
    return files("frontend").joinpath(f"resources/themes/{selected}.qss").read_text("utf-8"), tokens


def apply_theme(
    application: QApplication, mode: Literal["system", "dark", "light"] = "system"
) -> ThemeTokens:
    """Apply the selected stylesheet and return its drawing tokens."""
    stylesheet, tokens = load_theme(mode)
    application.setStyleSheet(stylesheet)
    return tokens
