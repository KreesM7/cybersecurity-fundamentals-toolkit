from dataclasses import dataclass
from functools import lru_cache
import math

from toolkit.core import ModuleSpec, resource_text


@dataclass
class PasswordReport:
    score: int
    guesses: float
    bits: float
    common: bool
    times: dict[str, float]
    warning: str
    suggestions: list[str]


@lru_cache(maxsize=1)
def common_passwords():
    return frozenset(line.casefold() for line in resource_text('common_passwords.txt').splitlines() if line)


def analyze_password(password: str) -> PasswordReport:
    if not password:
        raise ValueError('Enter a password to analyze.')
    if len(password) > 72:
        raise ValueError('The estimator supports up to 72 characters. Input is never silently truncated.')
    from zxcvbn import zxcvbn
    estimate = zxcvbn(password)
    guesses = max(1.0, float(estimate['guesses']))
    rates = {'Online (10/s)': 10, 'Offline (10,000/s)': 10000,
             'GPU-style fast hash (10 billion/s)': 10000000000}
    # zxcvbn also returns the plaintext and matched tokens. Neither belongs in the report.
    return PasswordReport(estimate['score'], guesses, math.log2(guesses),
                          password.casefold() in common_passwords(),
                          {label: guesses / rate for label, rate in rates.items()},
                          estimate['feedback']['warning'], estimate['feedback']['suggestions'])


def format_time(seconds):
    if seconds < 1:
        return f'{seconds:.3g} seconds'
    for divisor, unit in ((31557600, 'years'), (86400, 'days'), (3600, 'hours'), (60, 'minutes')):
        if seconds >= divisor:
            return f'{seconds / divisor:.3g} {unit}'
    return f'{seconds:.3g} seconds'


def create_panel(context):
    from PySide6.QtWidgets import QCheckBox, QLineEdit, QPlainTextEdit, QPushButton
    from toolkit.widgets import TaskPanel, technical_font

    panel = TaskPanel(context, 'Password Strength',
                      'Local strength report; no password is transmitted or logged. Maximum 72 characters. '
                      'Estimated strength bits are log2(guesses), not measured Shannon entropy. '
                      'Attack rates are illustrative and do not predict a particular system or GPU.')
    password = QLineEdit()
    password.setEchoMode(QLineEdit.EchoMode.Password)
    password.setPlaceholderText('Enter a practice password')
    password.setFont(technical_font())
    panel.layout.addWidget(password)
    show = QCheckBox('Show password')
    show.toggled.connect(lambda visible: password.setEchoMode(QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password))
    panel.layout.addWidget(show)
    output = QPlainTextEdit()
    output.setReadOnly(True)
    output.setFont(technical_font())
    panel.layout.addWidget(output, 1)
    clear = QPushButton('Clear')
    panel.actions.insertWidget(1, clear)
    panel.add_footer()

    def run():
        text = password.text()
        output.clear()

        def done(report):
            if password.text() != text:
                return
            lines = [f'Estimator score: {report.score}/4',
                     f'Estimated strength: {report.bits:.1f} bits',
                     f'Estimated guesses: {report.guesses:.3g}',
                     'Bundled common-list match: ' + ('yes' if report.common else 'no'),
                     '', 'Illustrative crack-time estimates:']
            lines.extend(f'{label}: {format_time(seconds)}' for label, seconds in report.times.items())
            if report.warning:
                lines.extend(['', report.warning])
            lines.extend(report.suggestions)
            output.setPlainText('\n'.join(lines))
            panel.status.setText('Done. Absence from the common list does not establish strength.')

        panel.start(lambda task: analyze_password(text), done)

    def reset():
        panel.cancel()
        password.clear()
        output.clear()
        show.setChecked(False)
        panel.status.setText('Cleared.')

    panel.run_button.clicked.connect(run)
    clear.clicked.connect(reset)
    return panel


MODULE = ModuleSpec('password-strength', 'Password Strength', 20, create_panel)
