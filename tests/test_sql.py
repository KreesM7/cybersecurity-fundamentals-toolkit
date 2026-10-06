import importlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from threading import Event, Timer
import time
from urllib.parse import parse_qs, urlsplit
import unittest


class LabHandler(BaseHTTPRequestHandler):
    requests = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).requests.append(('GET', self.path))
        parsed = urlsplit(self.path)
        if parsed.path == '/slow-chunks':
            try:
                self.wfile.write(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n')
                self.wfile.flush()
                for byte in b'1;' + b'x' * 60 + b'\r\nx\r\n0\r\n\r\n':
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.05)
            except OSError:
                pass
            return
        if parsed.path == '/slow-headers':
            try:
                for byte in b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx':
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.08)
            except OSError:
                pass
            return
        if parsed.path == '/slow-body':
            self.send_response(200)
            self.send_header('Content-Length', '100')
            self.end_headers()
            try:
                for _ in range(100):
                    self.wfile.write(b'x')
                    self.wfile.flush()
                    time.sleep(0.08)
            except OSError:
                pass
            return
        if parsed.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', 'http://8.8.8.8/')
            self.end_headers()
            return
        if parsed.path == '/large':
            body = b'x' * (1048576 + 1)
        elif parsed.path == '/form':
            body = b'<form action="/search"><input name="q" value="hello"></form>'
        elif parsed.path == '/foreign':
            body = b'<form action="http://192.168.1.7/search"><input name="q"></form>'
        else:
            value = parse_qs(parsed.query).get('q', [''])[0]
            body = b'SQLite syntax error near input' if "'" in value or '"' in value else b'Stable search result'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        type(self).requests.append(('POST', self.path))
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Stable post result')


class SQLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), LabHandler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def module(self):
        try:
            return importlib.import_module('toolkit.modules.sql_checker')
        except ModuleNotFoundError:
            self.fail('The local form checker has not been implemented.')

    def test_discovery_and_probes_find_new_error_evidence(self):
        module = self.module()
        discovery = module.discover_forms(self.base + '/form')
        self.assertEqual(discovery.forms[0].fields, [('q', 'hello')])
        findings = module.test_form(discovery.url, discovery.forms[0], [('q', 'hello')], owned=True)
        self.assertTrue(any('SQL error' in finding.evidence for finding in findings))

    def test_redirect_is_not_followed(self):
        module = self.module()
        before = len(LabHandler.requests)
        with self.assertRaisesRegex(ValueError, 'redirect|Redirect'):
            module.discover_forms(self.base + '/redirect')
        self.assertEqual(len(LabHandler.requests) - before, 1)

    def test_response_limit_and_cross_origin_form(self):
        module = self.module()
        with self.assertRaisesRegex(ValueError, 'limit|large'):
            module.discover_forms(self.base + '/large')
        discovery = module.discover_forms(self.base + '/foreign')
        self.assertEqual(discovery.forms, [])
        self.assertTrue(discovery.notes)

    def test_post_and_ownership_guards_precede_requests(self):
        module = self.module()
        form = module.FormSpec(self.base + '/search', 'POST', [('q', 'hello')])
        before = len(LabHandler.requests)
        with self.assertRaisesRegex(ValueError, 'POST'):
            module.test_form(self.base + '/form', form, form.fields, owned=True)
        with self.assertRaisesRegex(ValueError, 'own'):
            module.test_form(self.base + '/form', form, form.fields, allow_post=True)
        self.assertEqual(len(LabHandler.requests), before)

    def test_public_target_blocked_without_requests(self):
        module = self.module()
        with self.assertRaises(ValueError):
            module.discover_forms('http://8.8.8.8/')

    def test_slow_headers_and_body_obey_whole_request_deadline(self):
        from unittest.mock import patch
        module = self.module()
        with patch.object(module, 'REQUEST_SECONDS', 0.3, create=True):
            for path in ('/slow-headers', '/slow-body', '/slow-chunks'):
                start = time.monotonic()
                with self.assertRaisesRegex(ValueError, 'deadline|time limit'):
                    module.LimitedClient().request(self.base + path)
                self.assertLess(time.monotonic() - start, 2)

    def test_cancel_interrupts_slow_body(self):
        module = self.module()
        from toolkit.tasks import TaskContext, Cancelled
        for path in ('/slow-body', '/slow-chunks'):
            event = Event()
            # Allow the global request gate to release before testing cancellation of I/O.
            time.sleep(1.01)
            timer = Timer(0.3, event.set)
            timer.start()
            start = time.monotonic()
            try:
                with self.assertRaises(Cancelled):
                    module.LimitedClient(TaskContext(event)).request(self.base + path)
                self.assertLess(time.monotonic() - start, 2)
            finally:
                timer.cancel()

    def test_repetitive_response_comparison_has_bounded_work(self):
        module = self.module()
        a = ''.join(chr(0x2000 + i) for i in range(128)) * 2730
        b = a[1:] + 'x'
        start = time.monotonic()
        self.assertLessEqual(module.content_similarity(a, b), 1)
        self.assertEqual(module.content_similarity(a, a), 1)
        self.assertLess(time.monotonic() - start, 1)

    def test_explicit_post_and_request_budget(self):
        module = self.module()
        form = module.FormSpec(self.base + '/search', 'POST', [('q', 'hello')])
        before = len(LabHandler.requests)
        module.test_form(self.base + '/form', form, form.fields, owned=True, allow_post=True)
        self.assertEqual([method for method, _ in LabHandler.requests[before:]], ['POST'] * 5)
        client = module.LimitedClient()
        client.count = 40
        before = len(LabHandler.requests)
        with self.assertRaisesRegex(ValueError, 'budget'):
            client.request(self.base + '/search')
        self.assertEqual(len(LabHandler.requests), before)


if __name__ == '__main__':
    unittest.main()
