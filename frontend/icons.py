"""Toolkit Line: an original, consistent two-unit-stroke icon set (MIT)."""

from importlib.resources import files

from PyQt6.QtCore import QByteArray, Qt
from PyQt6.QtGui import QIcon, QPainter, QPalette, QPixmap
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtWidgets import QApplication

from frontend.theme import PALETTES, SIZE

PATHS = {
    "dashboard": "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z",
    "folder": "M3 7V4h6l3 3h9v13H3z",
    "target": "M12 1v6m0 10v6M1 12h6m10 0h6M5 5h14v14H5z",
    "modules": "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z",
    "payload": "m12 2 9 5v10l-9 5-9-5V7zm-9 5 9 5 9-5m-9 5v10",
    "terminal": "M3 4h18v16H3zm4 4 4 4-4 4m7 0h4",
    "cipher": "m3 8 4-4 4 4m-4-4v16m6-4 4 4 4-4m-4 4V4",
    "lock": "M4 10h16v11H4zM8 10V7a4 4 0 0 1 8 0v3m-4 4v3",
    "network": "M9 3h6v6H9zm-7 12h6v6H2zm14 0h6v6h-6zM12 9v3H5v3m7-3h7v3",
    "activity": "M2 12h4l3-8 6 16 3-8h4",
    "database": "M4 5c0-4 16-4 16 0s-16 4-16 0v14c0 4 16 4 16 0V5M4 12c0 4 16 4 16 0",
    "file": "M5 2h9l5 5v15H5zm9 0v6h5M8 13h8m-8 4h8",
    "settings": "M3 6h18M3 12h18M3 18h18M7 3v6m10 0v6M9 15v6",
    "collapse": "M3 3h18v18H3zm5 0v18m9-13-4 4 4 4",
    "help": "M9 8a3 3 0 0 1 6 0c0 2-3 2-3 5m0 3v1",
    "ready": "m5 12 4 4L19 6",
    "running": "M12 3a9 9 0 1 1-9 9 9 9 0 0 1 9-9zm0 3v6l4 2",
    "failed": "m6 6 12 12m0-12L6 18",
    "empty": "M4 4h16v16H4zm4 8h8",
}


def line_icon(name: str) -> QIcon:
    application = QApplication.instance()
    color = (
        application.palette().color(QPalette.ColorRole.WindowText).name()
        if isinstance(application, QApplication)
        else PALETTES["light"].foreground
    )
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
        f'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        f'<path d="{PATHS.get(name, PATHS["file"])}"/></svg>'
    )
    icon = QIcon()
    for size in (SIZE["icon"], SIZE["icon"] * 2):
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        QSvgRenderer(QByteArray(svg.encode())).render(painter)
        painter.end()
        icon.addPixmap(pixmap)
    return icon


def app_icon() -> QIcon:
    return QIcon(str(files("frontend").joinpath("resources/icons/toolkit.svg")))
