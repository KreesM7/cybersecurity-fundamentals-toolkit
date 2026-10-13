"""Keyboard-accessible monochrome VT screen; input only follows explicit launch consent."""

from PyQt6.QtCore import QEvent, Qt, pyqtSignal
from PyQt6.QtGui import QFontDatabase, QKeyEvent, QResizeEvent
from PyQt6.QtWidgets import QApplication, QPlainTextEdit


class NativeTerminalView(QPlainTextEdit):
    typed = pyqtSignal(str)
    resized = pyqtSignal(int, int)

    def __init__(self) -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setAccessibleName("Owned native terminal")
        self.setToolTip("Type into the terminal. Close terminal stops its owned processes.")

    def event(self, event: QEvent | None) -> bool:
        if event is not None and event.type() == QEvent.Type.ShortcutOverride and self.isEnabled():
            event.accept()
            return True
        return super().event(event)

    def keyPressEvent(self, event: QKeyEvent | None) -> None:  # noqa: N802
        if event is None:
            return
        control = bool(event.modifiers() & Qt.KeyboardModifier.ControlModifier)
        if event.key() == Qt.Key.Key_Backtab or (control and event.key() == Qt.Key.Key_Tab):
            self.focusNextPrevChild(not bool(event.modifiers() & Qt.KeyboardModifier.ShiftModifier))
            return
        if control and event.key() == Qt.Key.Key_C and self.textCursor().hasSelection():
            self.copy()
            return
        if control and event.key() == Qt.Key.Key_V:
            clipboard = QApplication.clipboard()
            if clipboard and len(clipboard.text()) <= 4096:
                self.typed.emit(clipboard.text())
            return
        sequences: dict[int, str] = {
            Qt.Key.Key_Return: "\r",
            Qt.Key.Key_Enter: "\r",
            Qt.Key.Key_Backspace: "\x08",
            Qt.Key.Key_Tab: "\t",
            Qt.Key.Key_Escape: "\x1b",
            Qt.Key.Key_Up: "\x1b[A",
            Qt.Key.Key_Down: "\x1b[B",
            Qt.Key.Key_Right: "\x1b[C",
            Qt.Key.Key_Left: "\x1b[D",
            Qt.Key.Key_Delete: "\x1b[3~",
            Qt.Key.Key_Home: "\x1b[H",
            Qt.Key.Key_End: "\x1b[F",
        }
        text = sequences.get(event.key(), event.text())
        if control and Qt.Key.Key_A <= event.key() <= Qt.Key.Key_Z:
            text = chr(event.key() - Qt.Key.Key_A + 1)
        if text:
            self.typed.emit(text)
            event.accept()
        else:
            super().keyPressEvent(event)

    def resizeEvent(self, event: QResizeEvent | None) -> None:  # noqa: N802
        super().resizeEvent(event)
        viewport = self.viewport()
        if viewport is None:
            return
        metrics = self.fontMetrics()
        self.resized.emit(
            max(2, min(60, viewport.height() // max(1, metrics.height()))),
            max(10, min(200, viewport.width() // max(1, metrics.horizontalAdvance("M")))),
        )
