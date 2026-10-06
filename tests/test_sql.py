import importlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit
import unittest


class LabHandler(BaseHTTPRequestHandler):
    requests = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).requests.append(('GET', self.path))
        parsed = urlsplit(self.path)
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


if __name__ == '__main__':
    unittest.main()
