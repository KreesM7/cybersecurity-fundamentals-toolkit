from dataclasses import dataclass
from difflib import SequenceMatcher
import hashlib
import math
import socket
from threading import Event, Lock, Thread
from urllib.parse import quote, urlencode
import re
import time

from toolkit.core import ModuleSpec
from toolkit.security import validate_form_action, validate_url


PROBES = ("'", '"', "''")
SQL_ERRORS = {
    'SQLite': r'sqlite.{0,60}(?:error|exception)|near .{0,50}syntax error',
    'MySQL': r'you have an error in your sql syntax|mysql.{0,40}(?:error|exception)',
    'PostgreSQL': r'postgresql.{0,40}(?:error|exception)|unterminated quoted string|syntax error at or near',
    'SQL Server': r'unclosed quotation mark|sql server.{0,40}(?:error|exception)',
    'Oracle': r'ORA-\d{5}',
}
_request_gate = Lock()
_next_request_at = 0.0
REQUEST_SECONDS = 15


@dataclass
class FormSpec:
    action: str
    method: str
    fields: list[tuple[str, str]]
    probe_indices: tuple[int, ...] | None = None


@dataclass
class Discovery:
    url: str
    forms: list[FormSpec]
    notes: list[str]


@dataclass
class Response:
    status: int
    text: str


@dataclass
class Finding:
    field: str
    probe: str
    status: int
    evidence: str


class LimitedClient:
    def __init__(self, task=None):
        from toolkit.tasks import TaskContext
        self.task = task or TaskContext()
        self.count = 0

    def request(self, url, method='GET', fields=()):
        global _next_request_at
        import urllib3
        target = validate_url(url)
        if method not in ('GET', 'POST'):
            raise ValueError('Only GET and explicitly enabled POST forms are supported.')
        if self.count >= 40:
            raise ValueError('Request budget exhausted (40 requests).')
        encoded = urlencode(fields)
        if len(encoded) > 65536:
            raise ValueError('Form input exceeds the 64 KiB request limit.')
        self.task.check()
        with _request_gate:
            self.task.wait(_next_request_at - time.monotonic())
            _next_request_at = time.monotonic() + 1.0
        self.task.check()
        self.count += 1
        query = target.query
        if method == 'GET' and encoded:
            query = query + '&' + encoded if query else encoded
        path = quote(target.path, safe="/%:@!$&'()*+,;=-._~") + ('?' + query if query else '')
        options = {'host': target.ip, 'port': target.port,
                   'timeout': urllib3.Timeout(connect=3, read=5), 'maxsize': 1}
        if target.scheme == 'https':
            pool = urllib3.HTTPSConnectionPool(**options, server_hostname=target.host,
                                              assert_hostname=target.host, cert_reqs='CERT_REQUIRED')
        else:
            pool = urllib3.HTTPConnectionPool(**options)
        connection = [None]
        deadline = time.monotonic() + REQUEST_SECONDS
        finished, expired = Event(), Event()
        connection_base = pool.ConnectionCls

        class TrackedConnection(connection_base):
            def connect(self):
                super().connect()
                connection[0] = self
                if client_task.event.is_set() or expired.is_set():
                    self.close()
                    client_task.check()
                    raise ValueError('Whole-request time limit exceeded.')

        client_task = self.task
        pool.ConnectionCls = TrackedConnection

        def guard():
            while not finished.wait(0.05):
                cancelled = client_task.event.is_set()
                if cancelled or time.monotonic() >= deadline:
                    if not cancelled:
                        expired.set()
                    active = connection[0]
                    if active is not None and active.sock is not None:
                        try:
                            active.sock.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        active.close()
                    return

        watchdog = Thread(target=guard, daemon=True, name='local-http-deadline')
        headers = {'Host': target.authority, 'Accept-Encoding': 'identity',
                   'User-Agent': 'CybersecurityFundamentalsToolkit/0.1'}
        if method == 'POST':
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        response = None
        watchdog.start()
        try:
            response = pool.urlopen(method, path, body=encoded.encode('utf-8') if method == 'POST' else None,
                                    headers=headers, redirect=False, retries=False,
                                    preload_content=False, assert_same_host=False)
            self.task.check()
            if 300 <= response.status < 400:
                raise ValueError('Redirect blocked. Enter the final local URL directly.')
            if response.headers.get('Content-Encoding', 'identity').lower() not in ('identity', ''):
                raise ValueError('Compressed responses are unsupported; the server must honor Accept-Encoding: identity.')
            chunks, total = [], 0
            body_deadline = min(deadline, time.monotonic() + 10)
            while True:
                self.task.check()
                if expired.is_set() or time.monotonic() > body_deadline:
                    raise ValueError('Response exceeded the 10-second body-read limit.')
                # read1 returns available data instead of waiting to fill 16 KiB.
                # The watchdog also interrupts slow headers and socket cancellation.
                chunk = response.read1(16384, decode_content=False)
                if not chunk:
                    break
                total += len(chunk)
                if total > 1048576:
                    raise ValueError('Response is too large (1 MiB limit); it was not analyzed.')
                chunks.append(chunk)
            if expired.is_set():
                raise ValueError('Whole-request time limit exceeded.')
            return Response(response.status, b''.join(chunks).decode('utf-8', errors='replace'))
        except Exception as exc:
            self.task.check()
            if expired.is_set():
                raise ValueError('Whole-request time limit exceeded.') from exc
            raise
        finally:
            finished.set()
            watchdog.join(timeout=0.2)
            if response is not None:
                response.close()
            pool.close()


def discover_forms(url, task=None):
    from bs4 import BeautifulSoup
    base = validate_url(url)
    reply = LimitedClient(task).request(base.url)
    if reply.status >= 400:
        raise ValueError(f'The page returned HTTP {reply.status}; form discovery stopped.')
    soup = BeautifulSoup(reply.text, 'html.parser')
    forms, notes = [], []
    for number, element in enumerate(soup.find_all('form')[:20], 1):
        try:
            action = validate_form_action(base, element.get('action', ''))
            method = element.get('method', 'GET').upper()
            if method not in ('GET', 'POST'):
                raise ValueError('Unsupported form method.')
            if method == 'POST' and element.get('enctype', 'application/x-www-form-urlencoded').lower() != 'application/x-www-form-urlencoded':
                raise ValueError('Only URL-encoded POST forms are supported.')
            fields, probe_indices = [], []
            for control in element.find_all(['input', 'textarea', 'select']):
                name, kind = control.get('name'), control.get('type', 'text').lower()
                if not name or control.has_attr('disabled') or kind in ('submit', 'button', 'reset', 'image', 'file'):
                    continue
                if kind in ('checkbox', 'radio') and not control.has_attr('checked'):
                    continue
                if control.name == 'textarea':
                    value = control.get_text()
                elif control.name == 'select':
                    option = control.find('option', selected=True) or control.find('option')
                    value = option.get('value', option.get_text()) if option else ''
                else:
                    value = control.get('value', 'on' if kind in ('checkbox', 'radio') else '')
                if len(fields) >= 100:
                    raise ValueError('Form contains too many fields (maximum 100).')
                if kind not in ('hidden', 'checkbox', 'radio') and control.name != 'select':
                    probe_indices.append(len(fields))
                fields.append((name, value))
            if not probe_indices:
                raise ValueError('No supported text fields found.')
            forms.append(FormSpec(action.url, method, fields, tuple(probe_indices)))
        except ValueError as exc:
            notes.append(f'Form {number}: {exc}')
    if len(soup.find_all('form')) > 20:
        notes.append('Only the first 20 forms were inspected.')
    return Discovery(base.url, forms, notes)


def _errors(text):
    return {name for name, pattern in SQL_ERRORS.items() if re.search(pattern, text, re.I | re.S)}


def _normalize(text, values):
    for value in sorted(set(value for value in values if value), key=len, reverse=True):
        text = text.replace(value, '')
    return ' '.join(text.split())


def content_similarity(first, second):
    if first == second:
        return 1.0
    # Bound the matcher's input to 1,024 fingerprints over the entire response.
    # Comparing raw repetitive pages can otherwise require quadratic CPU time.
    width = max(1, math.ceil(max(len(first), len(second)) / 1024))
    def fingerprints(text):
        return [hashlib.blake2s(text[index:index + width].encode('utf-8'), digest_size=8).digest()
                for index in range(0, len(text), width)]
    return SequenceMatcher(None, fingerprints(first), fingerprints(second)).ratio()


def test_form(source_url, form, fields, owned=False, allow_post=False, task=None):
    if not owned:
        raise ValueError('Confirm that you own this test application before sending probes.')
    base = validate_url(source_url)
    target = validate_form_action(base, form.action)
    if form.method == 'POST' and not allow_post:
        raise ValueError('POST testing is disabled. Enable it explicitly for your selected test form.')
    if form.method not in ('GET', 'POST'):
        raise ValueError('Unsupported form method.')
    if not fields or len(fields) > 100:
        raise ValueError('Use a form with 1 to 100 fields.')
    indices = form.probe_indices if form.probe_indices is not None else tuple(range(len(fields)))
    if any(not 0 <= i < len(fields) for i in indices):
        raise ValueError('Form fields changed. Load the form again.')
    if not indices:
        raise ValueError('No testable text fields found.')
    client = LimitedClient(task)
    first = client.request(target.url, form.method, fields)
    second = client.request(target.url, form.method, fields)
    values = [value for _, value in fields]
    a, b = _normalize(first.text, values), _normalize(second.text, values)
    if first.status != second.status or content_similarity(a, b) < 0.98:
        raise ValueError('Baseline responses differ. Anomaly comparison would be unreliable; testing stopped.')
    baseline_errors = _errors(first.text) | _errors(second.text)
    findings = []
    for index in indices[:12]:
        name, _ = fields[index]
        for probe in PROBES:
            client.task.check()
            client.task.report(f'Testing {name}; request {client.count + 1}/40')
            changed = list(fields)
            changed[index] = (name, probe)
            reply = client.request(target.url, form.method, changed)
            new_errors = _errors(reply.text) - baseline_errors
            normal = _normalize(reply.text, values + [probe])
            evidence = []
            if new_errors:
                evidence.append('New SQL error signature: ' + ', '.join(sorted(new_errors)))
            if reply.status != first.status:
                evidence.append(f'HTTP status changed from {first.status} to {reply.status}')
            if content_similarity(a, normal) < 0.8:
                evidence.append('Response content changed substantially')
            if evidence:
                findings.append(Finding(name, probe, reply.status, '; '.join(evidence)))
    return findings


def readiness():
    try:
        import urllib3
        import bs4
    except ImportError as exc:
        return 'Setup needed: install requirements.txt. ' + str(exc)
    return ''


def create_panel(context):
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QCheckBox, QComboBox, QFormLayout, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem
    from toolkit.widgets import TaskPanel, fill_table, make_table, technical_font

    panel = TaskPanel(context, 'SQL Injection Checker',
                      'Run only against your own local test application. Even benign POST inputs can change app data. '
                      'This checks ordinary HTML forms; results are possible issues, not proof of exploitability.')
    panel.discovery = None
    url = QLineEdit('http://localhost:8000/')
    url.setFont(technical_font())
    forms = QComboBox()
    form_layout = QFormLayout()
    form_layout.addRow('Local URL', url)
    form_layout.addRow('Selected form', forms)
    panel.layout.addLayout(form_layout)
    fields_table = QTableWidget(0, 2)
    fields_table.setHorizontalHeaderLabels(['Field', 'Value (editable)'])
    fields_table.horizontalHeader().setStretchLastSection(True)
    fields_table.setFont(technical_font())
    panel.layout.addWidget(fields_table, 1)
    owned = QCheckBox('I own this test application and authorize these probes')
    post = QCheckBox('Enable POST testing for the selected form')
    panel.layout.addWidget(owned)
    panel.layout.addWidget(post)
    results = make_table(['Field', 'Probe', 'HTTP status', 'Possible issue / evidence'])
    panel.layout.addWidget(results, 1)
    panel.run_button.setText('Load forms')
    test_button = QPushButton('Test selected form')
    test_button.setEnabled(False)
    panel.actions.insertWidget(1, test_button)
    panel.add_footer()

    def select(index):
        form = forms.itemData(index)
        fields_table.setRowCount(len(form.fields) if form else 0)
        if form:
            for row, (name, value) in enumerate(form.fields):
                item = QTableWidgetItem(name)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                fields_table.setItem(row, 0, item)
                fields_table.setItem(row, 1, QTableWidgetItem(value))
        post.setChecked(False)

    def loaded(discovery):
        panel.discovery = discovery
        forms.clear()
        for form in discovery.forms:
            forms.addItem(f'{form.method} {form.action}', form)
        panel.status.setText(f'{len(discovery.forms)} supported forms. ' + ' '.join(discovery.notes) +
                             ' Up to 12 text fields are probed per run.')

    def idle():
        test_button.setEnabled(bool(panel.discovery and panel.discovery.forms))

    def load():
        panel.discovery = None
        forms.clear()
        fields_table.setRowCount(0)
        results.setRowCount(0)
        test_button.setEnabled(False)
        target_url = url.text()
        panel.start(lambda task: discover_forms(target_url, task), loaded)
        panel.handle.finished.connect(idle)

    def tested(findings):
        fill_table(results, ((f.field, f.probe, f.status, f.evidence) for f in findings))
        panel.status.setText(f'{len(findings)} anomalous responses. '
                             'Content differences can have other causes; review the local app manually.')

    def run_tests():
        form = forms.currentData()
        if form is None or panel.discovery is None:
            return
        fields = [(fields_table.item(row, 0).text(), fields_table.item(row, 1).text())
                  for row in range(fields_table.rowCount())]
        source_url, permitted, post_enabled = panel.discovery.url, owned.isChecked(), post.isChecked()
        test_button.setEnabled(False)
        results.setRowCount(0)
        panel.start(lambda task: test_form(source_url, form, fields, permitted, post_enabled, task), tested)
        panel.handle.finished.connect(idle)

    forms.currentIndexChanged.connect(select)
    panel.run_button.clicked.connect(load)
    test_button.clicked.connect(run_tests)
    return panel


MODULE = ModuleSpec('sql-checker', 'SQL Injection Checker', 50, create_panel)
