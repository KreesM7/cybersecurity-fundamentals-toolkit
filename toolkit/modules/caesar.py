from toolkit.core import ModuleSpec


def transform(text: str, shift: int, decrypt=False) -> str:
    if type(shift) is not int or not 1 <= shift <= 25:
        raise ValueError('Shift must be an integer between 1 and 25.')
    amount = -shift if decrypt else shift
    output = []
    for character in text:
        if 'a' <= character <= 'z':
            output.append(chr((ord(character) - ord('a') + amount) % 26 + ord('a')))
        elif 'A' <= character <= 'Z':
            output.append(chr((ord(character) - ord('A') + amount) % 26 + ord('A')))
        else:
            output.append(character)
    return ''.join(output)


def brute_force(text):
    return [(shift, transform(text, shift, decrypt=True)) for shift in range(1, 26)]


def create_panel(context):
    from PySide6.QtWidgets import QComboBox, QFormLayout, QPlainTextEdit, QSpinBox, QTabWidget
    from toolkit.widgets import TaskPanel, fill_table, make_table, technical_font

    panel = TaskPanel(context, 'Caesar Cipher',
                      'Shift ASCII letters while preserving case and punctuation. '
                      'This is an exercise cipher and does not protect sensitive information.')
    form = QFormLayout()
    mode, shift = QComboBox(), QSpinBox()
    mode.addItems(['Encrypt', 'Decrypt'])
    shift.setRange(1, 25)
    shift.setValue(3)
    form.addRow('Operation', mode)
    form.addRow('Shift', shift)
    panel.layout.addLayout(form)
    source = QPlainTextEdit()
    source.setPlaceholderText('Enter text')
    source.setFont(technical_font())
    panel.layout.addWidget(source, 1)
    tabs = QTabWidget()
    result = QPlainTextEdit()
    result.setReadOnly(True)
    result.setFont(technical_font())
    candidates = make_table(['Shift', 'Decrypted text'])
    tabs.addTab(result, 'Result')
    tabs.addTab(candidates, 'All decryption shifts')
    panel.layout.addWidget(tabs, 1)
    panel.run_button.setText('Transform')
    panel.add_footer()

    def run():
        text = source.toPlainText()
        if len(text) > 100000:
            panel.status.setText('Limit this exercise to 100,000 characters.')
            return
        result.setPlainText(transform(text, shift.value(), mode.currentIndex() == 1))
        fill_table(candidates, brute_force(text))
        panel.status.setText('Done. The second tab shows all 25 decryption candidates for the input.')

    panel.run_button.clicked.connect(run)
    panel.cancel_button.hide()
    return panel


MODULE = ModuleSpec('caesar', 'Caesar Cipher', 10, create_panel)
