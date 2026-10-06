import sys

from PySide6.QtCore import QTimer
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import (
    QApplication, QHBoxLayout, QLabel, QListWidget, QMainWindow,
    QPlainTextEdit, QStackedWidget, QVBoxLayout, QWidget,
)

from toolkit.core import discover_modules
from toolkit.tasks import AppContext
from toolkit.widgets import fill_table, make_table


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Cybersecurity Fundamentals Toolkit')
        self.resize(1200, 800)
        self.setMinimumSize(960, 640)
        self.context = AppContext(self)
        self.entries = discover_modules()
        self.panels = {}
        self.closing = False
        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(220)
        self.sidebar.addItem('Home')
        self.stack = QStackedWidget()
        root = QWidget()
        layout = QHBoxLayout(root)
        layout.addWidget(self.sidebar)
        layout.addWidget(self.stack, 1)
        self.setCentralWidget(root)
        self.home = QWidget()
        home_layout = QVBoxLayout(self.home)
        title = QLabel('Cybersecurity Fundamentals Toolkit')
        title.setObjectName('heading')
        home_layout.addWidget(title)
        text = QLabel('Local learning and inspection tools. Choose a module from the sidebar.\n'
                      'Results are kept only for this session. Active tests are restricted to local targets.')
        text.setWordWrap(True)
        home_layout.addWidget(text)
        self.readiness_table = make_table(['Module', 'Status'])
        home_layout.addWidget(self.readiness_table)
        self.stack.addWidget(self.home)
        for entry in self.entries:
            self.sidebar.addItem(entry.spec.title if entry.spec else entry.name + ' (unavailable)')
        self.refresh_readiness()
        self.sidebar.currentRowChanged.connect(self.select_module)
        self.sidebar.setCurrentRow(0)
        self.statusBar().showMessage('Local session')

    def refresh_readiness(self):
        rows = []
        for entry in self.entries:
            try:
                status = entry.error or entry.readiness() or 'Ready'
            except Exception as exc:
                status = 'Setup needed: ' + str(exc)
            rows.append((entry.spec.title if entry.spec else entry.name, status))
        fill_table(self.readiness_table, rows)

    def select_module(self, row):
        if row <= 0:
            self.refresh_readiness()
            self.stack.setCurrentWidget(self.home)
            return
        entry = self.entries[row - 1]
        if row not in self.panels:
            try:
                if entry.spec is None:
                    raise RuntimeError(entry.error)
                panel = entry.spec.create_panel(self.context)
                if not isinstance(panel, QWidget):
                    raise TypeError('The module factory must return a Qt widget.')
            except Exception as exc:
                panel = QPlainTextEdit('Module unavailable.\n\n' + str(exc))
                panel.setReadOnly(True)
            self.panels[row] = panel
            self.stack.addWidget(panel)
        self.stack.setCurrentWidget(self.panels[row])

    def closeEvent(self, event):
        if self.context.jobs:
            event.ignore()
            self.context.cancel_all()
            self.statusBar().showMessage('Stopping background operations before closing...')
            if not self.closing:
                self.closing = True
                self.close_timer = QTimer(self)
                self.close_timer.timeout.connect(self._close_when_idle)
                self.close_timer.start(100)
        else:
            event.accept()

    def _close_when_idle(self):
        if not self.context.jobs:
            self.close_timer.stop()
            self.close()


def configure_theme(app):
    app.setStyle('Fusion')
    palette = QPalette()
    for role, color in (
        (QPalette.ColorRole.Window, '#202124'),
        (QPalette.ColorRole.WindowText, '#e8eaed'),
        (QPalette.ColorRole.Base, '#17191c'),
        (QPalette.ColorRole.AlternateBase, '#282b30'),
        (QPalette.ColorRole.Text, '#e8eaed'),
        (QPalette.ColorRole.Button, '#30343a'),
        (QPalette.ColorRole.ButtonText, '#e8eaed'),
        (QPalette.ColorRole.Highlight, '#365472'),
        (QPalette.ColorRole.HighlightedText, '#ffffff'),
        (QPalette.ColorRole.ToolTipBase, '#30343a'),
        (QPalette.ColorRole.ToolTipText, '#e8eaed'),
    ):
        palette.setColor(role, QColor(color))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor('#8d939b'))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor('#8d939b'))
    app.setPalette(palette)
    app.setStyleSheet('QLabel#heading { font-size: 20px; font-weight: 600; } '
                     'QPushButton { padding: 5px 12px; border-radius: 0px; } '
                     'QListWidget::item { padding: 9px 6px; }')


def main():
    app = QApplication(sys.argv)
    app.setApplicationName('Cybersecurity Fundamentals Toolkit')
    configure_theme(app)
    window = MainWindow()
    window.show()
    return app.exec()
