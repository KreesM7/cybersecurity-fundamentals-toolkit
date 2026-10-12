"""CWD-independent flat themes packaged alongside the desktop application."""

from dataclasses import asdict, dataclass
from importlib.resources import files
from typing import Literal

import darkdetect
from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QApplication

SPACE = {"none": 0, "xs": 4, "sm": 8, "md": 12, "lg": 16, "xl": 24}
SIZE = {
    "window_w": 1360,
    "window_h": 920,
    "sidebar": 244,
    "collapsed": 64,
    "icon": 18,
    "control": 32,
    "description": 96,
    "output": 144,
    "side_list": 220,
    "dialog_w": 480,
    "dialog_h": 420,
    "notes": 100,
    "launcher_w": 600,
    "launcher_h": 120,
}
STYLE = {"font": 13, "title": 22, "small": 12, "line": 1, "focus": 2, "radius": 0}


@dataclass(frozen=True)
class ThemeTokens:
    """Presentation colors shared by custom widgets."""

    background: str
    foreground: str
    accent: str
    border: str
    surface: str
    muted: str
    selection: str
    accent_text: str
    danger: str
    success: str
    warning: str


PALETTES = {
    "dark": ThemeTokens(
        "#15191e",
        "#edf1f5",
        "#79b8f3",
        "#65717e",
        "#1e252d",
        "#b2bdc9",
        "#263b4f",
        "#102133",
        "#ffaaa5",
        "#91d6ac",
        "#f2cf83",
    ),
    "light": ThemeTokens(
        "#f5f7f9",
        "#17212b",
        "#1765ad",
        "#73808e",
        "#ffffff",
        "#495969",
        "#dbeafa",
        "#ffffff",
        "#a32121",
        "#17653b",
        "#775000",
    ),
}


def load_theme(mode: Literal["system", "dark", "light"]) -> tuple[str, ThemeTokens]:
    """Resolve system preference and load a bundled stylesheet from any directory."""
    selected = "dark" if mode == "system" and darkdetect.isDark() else mode
    if selected == "system":
        selected = "light"
    if selected not in {"dark", "light"}:
        raise ValueError("Unknown theme")
    tokens = PALETTES[selected]
    stylesheet = files("frontend").joinpath(f"resources/themes/{selected}.qss").read_text("utf-8")
    values = asdict(tokens) | SPACE | STYLE | {"control": SIZE["control"]}
    for key in sorted(values, key=len, reverse=True):
        stylesheet = stylesheet.replace("@" + key, str(values[key]))
    stylesheet = stylesheet.replace(
        "@check_icon",
        str(files("frontend").joinpath(f"resources/icons/check-{selected}.svg")).replace("\\", "/"),
    )
    return stylesheet, tokens


def apply_theme(
    application: QApplication, mode: Literal["system", "dark", "light"] = "system"
) -> ThemeTokens:
    """Apply the selected stylesheet and return its drawing tokens."""
    stylesheet, tokens = load_theme(mode)
    palette = QPalette()
    for role, color in (
        (QPalette.ColorRole.Window, tokens.background),
        (QPalette.ColorRole.Base, tokens.surface),
        (QPalette.ColorRole.AlternateBase, tokens.background),
        (QPalette.ColorRole.Text, tokens.foreground),
        (QPalette.ColorRole.WindowText, tokens.foreground),
        (QPalette.ColorRole.ButtonText, tokens.foreground),
        (QPalette.ColorRole.Highlight, tokens.selection),
        (QPalette.ColorRole.HighlightedText, tokens.foreground),
        (QPalette.ColorRole.PlaceholderText, tokens.muted),
    ):
        palette.setColor(role, QColor(color))
    application.setPalette(palette)
    application.setStyleSheet(stylesheet)
    application.setProperty("themeMode", mode)
    return tokens
