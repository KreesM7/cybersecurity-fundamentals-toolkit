import hashlib
import math
import re
import socket
import time
from dataclasses import dataclass, replace
from difflib import SequenceMatcher
from importlib import import_module
from threading import Event, Lock, Thread
from urllib.parse import quote, urlencode

from toolkit.core import ModuleSpec
from toolkit.security import resolve_web_target, validate_form_action, validate_url

PROBES = ("'", '"', "''")
SQL_ERRORS = {
    "SQLite": r"sqlite.{0,60}(?:error|exception)|near .{0,50}syntax error",
    "MySQL": r"you have an error in your sql syntax|mysql.{0,40}(?:error|exception)",
    "PostgreSQL": (
        r"postgresql.{0,40}(?:error|exception)|unterminated quoted string|syntax error at or near"
    ),
    "SQL Server": r"unclosed quotation mark|sql server.{0,40}(?:error|exception)",
    "Oracle": r"ORA-\d{5}",
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
        from toolkit.task_context import TaskContext

        self.task = task or TaskContext()
        self.count = 0
        self.resolved_ips = {}

    def request(self, url, method="GET", fields=()):
        global _next_request_at
        import urllib3

        target = validate_url(url)
        if method not in ("GET", "POST"):
            raise ValueError("Only GET and explicitly enabled POST forms are supported.")
        if self.count >= 40:
            raise ValueError("Request budget exhausted (40 requests).")
        encoded = urlencode(fields)
        if len(encoded) > 65536:
            raise ValueError("Form input exceeds the 64 KiB request limit.")
        self.task.check()
        key = (target.host, target.port)
        if target.ip is None:
            if key not in self.resolved_ips:
                self.resolved_ips[key] = resolve_web_target(target, self.task).ip
            target = replace(target, ip=self.resolved_ips[key])
        with _request_gate:
            self.task.wait(_next_request_at - time.monotonic())
            _next_request_at = time.monotonic() + 1.0
        self.task.check()
        self.count += 1
        query = target.query
        if method == "GET" and encoded:
            query = query + "&" + encoded if query else encoded
        path = quote(target.path, safe="/%:@!$&'()*+,;=-._~") + ("?" + query if query else "")
        options = {
            "host": target.ip,
            "port": target.port,
            "timeout": urllib3.Timeout(connect=3, read=5),
            "maxsize": 1,
        }
        if target.scheme == "https":
            pool = urllib3.HTTPSConnectionPool(
                **options,
                server_hostname=target.host,
                assert_hostname=target.host,
                cert_reqs="CERT_REQUIRED",
            )
        else:
            pool = urllib3.HTTPConnectionPool(**options)
        transport = [None]
        deadline = time.monotonic() + REQUEST_SECONDS
        io_deadline = [deadline]
        finished, expired = Event(), Event()
        connection_base = pool.ConnectionCls

        class TrackedConnection(connection_base):
            def connect(self):
                super().connect()
                # http.client may clear connection.sock for Connection: close
                # while its response retains a buffered file on this socket.
                transport[0] = self.sock
                if client_task.event.is_set() or expired.is_set():
                    self.close()
                    client_task.check()
                    raise ValueError("Whole-request time limit exceeded.")

        client_task = self.task
        pool.ConnectionCls = TrackedConnection

        def guard():
            while not finished.wait(0.05):
                cancelled = client_task.event.is_set()
                if cancelled or time.monotonic() >= io_deadline[0]:
                    if not cancelled:
                        expired.set()
                    active = transport[0]
                    if active is not None:
                        try:
                            active.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        active.close()
                    return

        watchdog = Thread(target=guard, daemon=True, name="toolkit-http-deadline")
        headers = {
            "Host": target.authority,
            "Accept-Encoding": "identity",
            "User-Agent": "CybersecurityFundamentalsToolkit/0.1",
        }
        if method == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        response = None
        body_deadline = None
        watchdog.start()
        try:
            response = pool.urlopen(
                method,
                path,
                body=encoded.encode("utf-8") if method == "POST" else None,
                headers=headers,
                redirect=False,
                retries=False,
                preload_content=False,
                assert_same_host=False,
            )
            self.task.check()
            if 300 <= response.status < 400:
                raise ValueError("Redirect blocked. Enter the final URL directly.")
            if response.headers.get("Content-Encoding", "identity").lower() not in ("identity", ""):
                raise ValueError(
                    "Compressed responses are unsupported; "
                    "the server must honor Accept-Encoding: identity."
                )
            chunks, total = [], 0
            body_deadline = min(deadline, time.monotonic() + 10)
            io_deadline[0] = body_deadline
            while True:
                self.task.check()
                if expired.is_set() or time.monotonic() > body_deadline:
                    raise ValueError("Response exceeded the 10-second body-read limit.")
                # read1 returns available data instead of waiting to fill 16 KiB.
                # The watchdog also interrupts slow headers and socket cancellation.
                chunk = response.read1(16384, decode_content=False)
                if not chunk:
                    break
                total += len(chunk)
                if total > 1048576:
                    raise ValueError("Response is too large (1 MiB limit); it was not analyzed.")
                chunks.append(chunk)
            if expired.is_set():
                raise ValueError("Whole-request time limit exceeded.")
            return Response(response.status, b"".join(chunks).decode("utf-8", errors="replace"))
        except Exception as exc:
            self.task.check()
            if expired.is_set() or time.monotonic() >= io_deadline[0]:
                raise ValueError("Whole-request time limit exceeded.") from exc
            if body_deadline is not None and time.monotonic() >= body_deadline:
                raise ValueError("Response exceeded the 10-second body-read limit.") from exc
            raise
        finally:
            finished.set()
            watchdog.join(timeout=0.2)
            if response is not None:
                response.close()
            pool.close()


def discover_forms(url, task=None):

    base = validate_url(url)
    reply = LimitedClient(task).request(base.url)
    if reply.status >= 400:
        raise ValueError(f"The page returned HTTP {reply.status}; form discovery stopped.")
    return parse_forms(base.url, reply.text)


def parse_forms(url: str, text: str) -> Discovery:
    from bs4 import BeautifulSoup

    base = validate_url(url)
    soup = BeautifulSoup(text, "html.parser")
    forms, notes = [], []
    for number, element in enumerate(soup.find_all("form")[:20], 1):
        try:
            action = validate_form_action(base, element.get("action", ""))
            method = element.get("method", "GET").upper()
            if method not in ("GET", "POST"):
                raise ValueError("Unsupported form method.")
            if (
                method == "POST"
                and element.get("enctype", "application/x-www-form-urlencoded").lower()
                != "application/x-www-form-urlencoded"
            ):
                raise ValueError("Only URL-encoded POST forms are supported.")
            fields, probe_indices = [], []
            for control in element.find_all(["input", "textarea", "select"]):
                name, kind = control.get("name"), control.get("type", "text").lower()
                if (
                    not name
                    or control.has_attr("disabled")
                    or kind in ("submit", "button", "reset", "image", "file")
                ):
                    continue
                if kind in ("checkbox", "radio") and not control.has_attr("checked"):
                    continue
                if control.name == "textarea":
                    value = control.get_text()
                elif control.name == "select":
                    option = control.find("option", selected=True) or control.find("option")
                    value = option.get("value", option.get_text()) if option else ""
                else:
                    value = control.get("value", "on" if kind in ("checkbox", "radio") else "")
                if len(fields) >= 100:
                    raise ValueError("Form contains too many fields (maximum 100).")
                if kind not in ("hidden", "checkbox", "radio") and control.name != "select":
                    probe_indices.append(len(fields))
                fields.append((name, value))
            if not probe_indices:
                raise ValueError("No supported text fields found.")
            forms.append(FormSpec(action.url, method, fields, tuple(probe_indices)))
        except ValueError as exc:
            notes.append(f"Form {number}: {exc}")
    if len(soup.find_all("form")) > 20:
        notes.append("Only the first 20 forms were inspected.")
    return Discovery(base.url, forms, notes)


def _errors(text: str) -> set[str]:
    return {name for name, pattern in SQL_ERRORS.items() if re.search(pattern, text, re.I | re.S)}


def _normalize(text: str, values: list[str]) -> str:
    for value in sorted(set(value for value in values if value), key=len, reverse=True):
        text = text.replace(value, "")
    return " ".join(text.split())


def content_similarity(first: str, second: str) -> float:
    if first == second:
        return 1.0
    # Bound the matcher's input to 1,024 fingerprints over the entire response.
    # Comparing raw repetitive pages can otherwise require quadratic CPU time.
    width = max(1, math.ceil(max(len(first), len(second)) / 1024))

    def fingerprints(text):
        return [
            hashlib.blake2s(text[index : index + width].encode("utf-8"), digest_size=8).digest()
            for index in range(0, len(text), width)
        ]

    return SequenceMatcher(None, fingerprints(first), fingerprints(second)).ratio()


def test_form(source_url, form, fields, owned=False, allow_post=False, task=None):
    if not owned:
        raise ValueError(
            "Confirm ownership or permission to test this application before sending probes."
        )
    base = validate_url(source_url)
    target = validate_form_action(base, form.action)
    if form.method == "POST" and not allow_post:
        raise ValueError(
            "POST testing is disabled. Enable it explicitly for your selected test form."
        )
    if form.method not in ("GET", "POST"):
        raise ValueError("Unsupported form method.")
    if not fields or len(fields) > 100:
        raise ValueError("Use a form with 1 to 100 fields.")
    indices = form.probe_indices if form.probe_indices is not None else tuple(range(len(fields)))
    if any(not 0 <= i < len(fields) for i in indices):
        raise ValueError("Form fields changed. Load the form again.")
    if not indices:
        raise ValueError("No testable text fields found.")
    client = LimitedClient(task)
    first = client.request(target.url, form.method, fields)
    second = client.request(target.url, form.method, fields)
    values = [value for _, value in fields]
    a, b = _normalize(first.text, values), _normalize(second.text, values)
    if first.status != second.status or content_similarity(a, b) < 0.98:
        raise ValueError(
            "Baseline responses differ. Anomaly comparison would be unreliable; testing stopped."
        )
    baseline_errors = _errors(first.text) | _errors(second.text)
    findings = []
    for index in indices[:12]:
        name, _ = fields[index]
        for probe in PROBES:
            client.task.check()
            client.task.report(f"Testing {name}; request {client.count + 1}/40")
            changed = list(fields)
            changed[index] = (name, probe)
            reply = client.request(target.url, form.method, changed)
            new_errors = _errors(reply.text) - baseline_errors
            normal = _normalize(reply.text, values + [probe])
            evidence = []
            if new_errors:
                evidence.append("New SQL error signature: " + ", ".join(sorted(new_errors)))
            if reply.status != first.status:
                evidence.append(f"HTTP status changed from {first.status} to {reply.status}")
            if content_similarity(a, normal) < 0.8:
                evidence.append("Response content changed substantially")
            if evidence:
                findings.append(Finding(name, probe, reply.status, "; ".join(evidence)))
    return findings


def readiness() -> str:
    try:
        import_module("bs4")
        import_module("urllib3")
    except ImportError as exc:
        return "Setup needed: install requirements.txt. " + str(exc)
    return ""


def create_panel(context):
    from frontend.views.tools import create_panel as factory

    return factory(MODULE.id, context)


MODULE = ModuleSpec("sql-checker", "SQL Injection Checker", 50, create_panel)
