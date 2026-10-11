import importlib
import socket
import ssl
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Thread, Timer
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest


class LabHandler(BaseHTTPRequestHandler):
    requests = []
    hosts = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).requests.append(("GET", self.path))
        type(self).hosts.append(self.headers.get("Host"))
        parsed = urlsplit(self.path)
        if parsed.path == "/slow-chunks":
            try:
                self.wfile.write(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                )
                self.wfile.flush()
                for byte in b"1;" + b"x" * 60 + b"\r\nx\r\n0\r\n\r\n":
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.05)
            except OSError:
                pass
            return
        if parsed.path == "/slow-headers":
            try:
                for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx":
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.08)
            except OSError:
                pass
            return
        if parsed.path == "/slow-body":
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            try:
                for _ in range(100):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.08)
            except OSError:
                pass
            return
        if parsed.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://8.8.8.8/")
            self.end_headers()
            return
        if parsed.path == "/large":
            body = b"x" * (1048576 + 1)
        elif parsed.path == "/form":
            body = b'<form action="/search"><input name="q" value="hello"></form>'
        elif parsed.path == "/foreign":
            body = b'<form action="http://192.168.1.7/search"><input name="q"></form>'
        else:
            value = parse_qs(parsed.query).get("q", [""])[0]
            body = (
                b"SQLite syntax error near input"
                if "'" in value or '"' in value
                else b"Stable search result"
            )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        type(self).requests.append(("POST", self.path))
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Stable post result")


class SQLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def module(self):
        try:
            return importlib.import_module("toolkit.modules.sql_checker")
        except ModuleNotFoundError:
            self.fail("The local form checker has not been implemented.")

    def test_discovery_and_probes_find_new_error_evidence(self):
        module = self.module()
        discovery = module.discover_forms(self.base + "/form")
        self.assertEqual(discovery.forms[0].fields, [("q", "hello")])
        findings = module.test_form(discovery.url, discovery.forms[0], [("q", "hello")], owned=True)
        self.assertTrue(any("SQL error" in finding.evidence for finding in findings))

    def test_redirect_is_not_followed(self):
        module = self.module()
        before = len(LabHandler.requests)
        with self.assertRaisesRegex(ValueError, "redirect|Redirect"):
            module.discover_forms(self.base + "/redirect")
        self.assertEqual(len(LabHandler.requests) - before, 1)

    def test_response_limit_and_cross_origin_form(self):
        module = self.module()
        with self.assertRaisesRegex(ValueError, "limit|large"):
            module.discover_forms(self.base + "/large")
        discovery = module.discover_forms(self.base + "/foreign")
        self.assertEqual(discovery.forms, [])
        self.assertTrue(discovery.notes)

    def test_post_and_ownership_guards_precede_requests(self):
        module = self.module()
        form = module.FormSpec(self.base + "/search", "POST", [("q", "hello")])
        before = len(LabHandler.requests)
        with self.assertRaisesRegex(ValueError, "POST"):
            module.test_form(self.base + "/form", form, form.fields, owned=True)
        with self.assertRaisesRegex(ValueError, "own"):
            module.test_form(self.base + "/form", form, form.fields, allow_post=True)
        self.assertEqual(len(LabHandler.requests), before)

    def test_public_literal_target_is_accepted_using_controlled_transport(self):
        module = self.module()
        original_lookup = socket.getaddrinfo

        def controlled_lookup(host, port, *args, **kwargs):
            if host == "93.184.216.34":
                host = "127.0.0.1"
            return original_lookup(host, port, *args, **kwargs)

        with patch("socket.getaddrinfo", side_effect=controlled_lookup):
            reply = module.LimitedClient().request(
                f"http://93.184.216.34:{self.server.server_port}/form"
            )
        self.assertIn("<form", reply.text)
        self.assertEqual(LabHandler.hosts[-1], f"93.184.216.34:{self.server.server_port}")

    def test_hostname_is_pinned_per_run_and_preserves_host_header(self):
        module = self.module()
        original_lookup = socket.getaddrinfo
        lookups = []

        def controlled_lookup(host, port, *args, **kwargs):
            if host == "lab.test":
                lookups.append(host)
                if len(lookups) > 1:
                    raise AssertionError("The hostname must be resolved once per client")
                host = "127.0.0.1"
            return original_lookup(host, port, *args, **kwargs)

        with patch("socket.getaddrinfo", side_effect=controlled_lookup):
            client = module.LimitedClient()
            for _ in range(2):
                reply = client.request(f"http://lab.test:{self.server.server_port}/form")
                self.assertIn("<form", reply.text)
        self.assertEqual(len(lookups), 1)
        self.assertEqual(LabHandler.hosts[-2:], [f"lab.test:{self.server.server_port}"] * 2)

    def test_unsupported_dns_answer_is_rejected_before_http(self):
        module = self.module()
        answers = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("169.254.169.254", self.server.server_port),
            )
        ]
        before = len(LabHandler.requests)
        with patch("socket.getaddrinfo", return_value=answers):
            with self.assertRaisesRegex(ValueError, "address|DNS"):
                module.LimitedClient().request(f"http://lab.test:{self.server.server_port}/form")
        self.assertEqual(len(LabHandler.requests), before)

    def test_dns_resolution_is_bounded_and_cancellable(self):
        from toolkit import security
        from toolkit.tasks import Cancelled, TaskContext

        module = self.module()
        for cancel in (False, True):
            release, cancelled = Event(), Event()

            def slow_lookup(*args, **kwargs):
                if cancel:
                    Timer(0.05, cancelled.set).start()
                release.wait(2)
                return []

            start = time.monotonic()
            try:
                with (
                    patch("socket.getaddrinfo", side_effect=slow_lookup),
                    patch.object(security, "DNS_SECONDS", 0.15, create=True),
                ):
                    error = Cancelled if cancel else ValueError
                    with self.assertRaisesRegex(error, "DNS|Cancelled"):
                        module.LimitedClient(TaskContext(cancelled)).request("http://lab.test/")
                self.assertLess(time.monotonic() - start, 1)
            finally:
                release.set()

    def test_slow_headers_and_body_obey_whole_request_deadline(self):
        from unittest.mock import patch

        module = self.module()
        with patch.object(module, "REQUEST_SECONDS", 0.3, create=True):
            for path in ("/slow-headers", "/slow-body", "/slow-chunks"):
                start = time.monotonic()
                with self.assertRaisesRegex(ValueError, "deadline|time limit"):
                    module.LimitedClient().request(self.base + path)
                self.assertLess(time.monotonic() - start, 2)

    def test_cancel_interrupts_slow_body(self):
        module = self.module()
        from toolkit.tasks import Cancelled, TaskContext

        for path in ("/slow-body", "/slow-chunks"):
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
        a = "".join(chr(0x2000 + i) for i in range(128)) * 2730
        b = a[1:] + "x"
        start = time.monotonic()
        self.assertLessEqual(module.content_similarity(a, b), 1)
        self.assertEqual(module.content_similarity(a, a), 1)
        self.assertLess(time.monotonic() - start, 1)

    def test_explicit_post_and_request_budget(self):
        module = self.module()
        form = module.FormSpec(self.base + "/search", "POST", [("q", "hello")])
        before = len(LabHandler.requests)
        module.test_form(self.base + "/form", form, form.fields, owned=True, allow_post=True)
        self.assertEqual([method for method, _ in LabHandler.requests[before:]], ["POST"] * 5)
        client = module.LimitedClient()
        client.count = 40
        before = len(LabHandler.requests)
        with self.assertRaisesRegex(ValueError, "budget"):
            client.request(self.base + "/search")
        self.assertEqual(len(LabHandler.requests), before)


def test_untrusted_https_certificate_is_rejected(local_tls_pair):
    import urllib3

    module = importlib.import_module("toolkit.modules.sql_checker")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*local_tls_pair)
    server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    before = len(LabHandler.requests)
    try:
        with pytest.raises(urllib3.exceptions.SSLError):
            module.LimitedClient().request(f"https://127.0.0.1:{server.server_port}/form")
        assert len(LabHandler.requests) == before
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    unittest.main()
