"""Export the flat SVG master with Qt; Windows ICO stores lossless PNG images."""

import os
import struct
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def main() -> None:
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QImage, QPainter
    from PyQt6.QtSvg import QSvgRenderer
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    folder = Path(__file__).resolve().parents[1] / "frontend/resources/icons"
    renderer = QSvgRenderer(str(folder / "toolkit.svg"))
    assert renderer.isValid()
    entries = []
    for size in (16, 32, 48, 128, 256, 512):
        image = QImage(size, size, QImage.Format.Format_ARGB32)
        image.fill(Qt.GlobalColor.transparent)
        painter = QPainter(image)
        renderer.render(painter)
        painter.end()
        destination = folder / f"toolkit-{size}.png"
        assert image.save(str(destination))
        if size <= 256:
            entries.append((size, destination.read_bytes()))
    offset = 6 + 16 * len(entries)
    header = struct.pack("<HHH", 0, 1, len(entries))
    data = b""
    for size, png in entries:
        header += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(png), offset)
        data += png
        offset += len(png)
    (folder / "toolkit.ico").write_bytes(header + data)
    print("Exported SVG at 16/32/48/128/256/512 and Windows ICO.")
    del app


if __name__ == "__main__":
    main()
