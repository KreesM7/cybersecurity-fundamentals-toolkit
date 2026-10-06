from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QAbstractItemView, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)


def technical_font():
    return QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)


def make_table(headers):
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setAlternatingRowColors(True)
    table.setFont(technical_font())
    table.horizontalHeader().setStretchLastSection(True)
    return table


def fill_table(table, rows):
    rows = list(rows)
    table.setSortingEnabled(False)
    table.setRowCount(min(len(rows), 5000))
    for row_index, row in enumerate(rows[:5000]):
        for column, value in enumerate(row):
            table.setItem(row_index, column, QTableWidgetItem(str(value)))
    table.resizeColumnsToContents()


class FileInput(QWidget):
    def __init__(self, filters='All files (*)'):
        super().__init__()
        self.path = QLineEdit()
        self.path.setPlaceholderText('Choose a local file')
        self.path.setFont(technical_font())
        browse = QPushButton('Browse...')
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.path, 1)
        layout.addWidget(browse)
        browse.clicked.connect(lambda: self._choose(filters))

    def _choose(self, filters):
        filename, _ = QFileDialog.getOpenFileName(self, 'Choose file', '', filters)
        if filename:
            self.path.setText(filename)


class TaskPanel(QWidget):
    def __init__(self, context, title, description):
        super().__init__()
        self.context, self.handle = context, None
        self.layout = QVBoxLayout(self)
        self.layout.setSpacing(10)
        heading = QLabel(title)
        heading.setObjectName('heading')
        self.layout.addWidget(heading)
        caption = QLabel(description)
        caption.setWordWrap(True)
        self.layout.addWidget(caption)
        self.actions = QHBoxLayout()
        self.run_button = QPushButton('Analyze')
        self.cancel_button = QPushButton('Cancel')
        self.cancel_button.setEnabled(False)
        self.actions.addWidget(self.run_button)
        self.actions.addWidget(self.cancel_button)
        self.actions.addStretch()
        self.status = QLabel('Ready.')
        self.status.setWordWrap(True)
        self.cancel_button.clicked.connect(self.cancel)

    def add_footer(self):
        self.layout.addLayout(self.actions)
        self.layout.addWidget(self.status)

    def start(self, work, on_result):
        if self.handle:
            return
        self.run_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.status.setText('Working...')
        self.handle = self.context.run_task(
            work, on_result, self.status.setText, self.status.setText, self._finished,
        )

    def _finished(self):
        self.handle = None
        self.run_button.setEnabled(True)
        self.cancel_button.setEnabled(False)

    def cancel(self):
        if self.handle:
            self.handle.cancel()
            self.status.setText('Cancelling; waiting for the current operation to stop...')
