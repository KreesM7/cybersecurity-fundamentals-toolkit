"""Actual loopback HTTP fixtures for async SQL request and discovery boundaries."""

import asyncio
import socket
import time
from pathlib import Path
from threading import Event
from urllib.parse import parse_qsl, urlsplit
from uuid import UUID, uuid4

import pytest

from backend.events import EventHub
from backend.jobs import JobContext
from backend.main import create_app
from backend.services.async_sql import SQLClient
from backend.services.request_gate import RequestGate
from shared.tools import SQLField, SQLOptions

TOKEN = "d" * 64


@pytest.fixture
async def lab():
    requests = []
    tasks = set()
    unstable_count = 0

    async def handle(reader, writer):
        nonlocal unstable_count
        task = asyncio.current_task()
        tasks.add(task)
        try:
            line = await reader.readline()
            if not line:
                return
            method, path, _ = line.decode().strip().split(" ", 2)
            headers = {}
            while line := await reader.readline():
                if line == b"\r\n":
                    break
                name, value = line.decode().split(":", 1)
                headers[name.lower()] = value.strip()
            body = await reader.readexactly(int(headers.get("content-length", "0")))
            requests.append((method, path, body, headers, time.monotonic()))
            route = urlsplit(path).path
            status = 200
            extra = ""
            if route == "/forms":
                content = (
                    b'<form action="/search"><input name="q" value="hello">'
                    b'<input type="hidden" name="q" value="nonce"></form>'
                    b'<form action="/search" method="POST"><input name="q" value="hello"></form>'
                )
            elif route == "/foreign":
                content = b'<form action="http://127.0.0.2/search"><input name="q"></form>'
            elif route == "/redirect":
                status, content = 302, b""
                extra = "Location: http://127.0.0.2/search\r\n"
            elif route == "/large":
                content = b"x" * (1048576 + 1)
            elif route == "/unstable":
                unstable_count += 1
                content = (b"x" if unstable_count % 2 else b"z") * 3000
            elif route == "/slow":
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
                await writer.drain()
                for _ in range(100):
                    writer.write(b"x")
                    await writer.drain()
                    await asyncio.sleep(0.2)
                return
            else:
                fields = (
                    parse_qsl(urlsplit(path).query) if method == "GET" else parse_qsl(body.decode())
                )
                value = next((value for name, value in fields if name == "q"), "")
                content = (
                    b"SQLite error near input"
                    if "'" in value or '"' in value
                    else b"Stable search result"
                )
            writer.write(
                (
                    f"HTTP/1.1 {status} OK\r\nContent-Length: {len(content)}\r\n"
                    f"Connection: close\r\n{extra}\r\n"
                ).encode()
                + content
            )
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            tasks.discard(task)

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    base = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
    try:
        yield base, requests
    finally:
        server.close()
        await server.wait_closed()
        for task in tuple(tasks):
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def client(base, gate=None):
    context = JobContext(Event(), EventHub(), uuid4(), uuid4())
    return SQLClient(gate or RequestGate(), context, base)


async def test_async_quote_only_probes_preserve_duplicate_hidden_fields_and_global_pacing(
    tmp_path: Path, lab
):
    base, requests = lab
    app = create_app(TOKEN, "sql", tmp_path)
    async with app.router.lifespan_context(app):
        options = SQLOptions(url=base + "/forms", owned=True, generation=7)
        discovery_job = await app.state.tools.submit("sql-checker", options)
        await app.state.jobs.wait_idle()
        discovery = app.state.jobs.get(discovery_job.id, discovery_job.workspace_id).result
        assert discovery["forms"][0]["probe_indices"] == [0]
        fields = [SQLField(name="q", value="edited"), SQLField(name="q", value="nonce")]
        test_options = SQLOptions(
            operation="test",
            url=base + "/forms",
            owned=True,
            generation=7,
            discovery_id=UUID(discovery["discovery_id"]),
            fields=fields,
        )
        job = await app.state.tools.submit("sql-checker", test_options)
        await app.state.jobs.wait_idle()
        result = app.state.jobs.get(job.id, job.workspace_id).result
        assert result["requests"] == 5 and len(result["findings"]) == 3
        assert [parse_qsl(urlsplit(row[1]).query) for row in requests[1:]] == [
            [("q", "edited"), ("q", "nonce")]
        ] * 2 + [[("q", quote), ("q", "nonce")] for quote in ("'", '"', "''")]
        assert all(after[4] - before[4] >= 0.95 for before, after in zip(requests, requests[1:]))
        before = len(requests)
        for changed in (
            test_options.model_copy(update={"generation": 9}),
            test_options.model_copy(update={"fields": [SQLField(name="other", value="x")]}),
            test_options.model_copy(
                update={"form_index": 1, "fields": [SQLField(name="q", value="hello")]}
            ),
        ):
            with pytest.raises(ValueError):
                await app.state.tools.submit("sql-checker", changed)
        assert len(requests) == before


async def test_redirect_large_response_and_cross_origin_guard(lab):
    base, requests = lab
    for path, match in (("/redirect", "Redirect"), ("/large", "1 MiB")):
        with pytest.raises(ValueError, match=match):
            await client(base).request(base + path)
    before = len(requests)
    with pytest.raises(ValueError, match="original"):
        await client(base).request("http://127.0.0.2/search")
    assert len(requests) == before


async def test_discovery_needs_no_ack_and_cross_origin_form_is_not_testable(tmp_path: Path, lab):
    base, requests = lab
    app = create_app(TOKEN, "sql-guard", tmp_path)
    async with app.router.lifespan_context(app):
        discovery = await app.state.tools.submit("sql-checker", SQLOptions(url=base + "/forms"))
        await app.state.jobs.wait_idle()
        assert app.state.jobs.get(discovery.id, discovery.workspace_id).status == "succeeded"
        assert requests
        job = await app.state.tools.submit(
            "sql-checker", SQLOptions(url=base + "/foreign", owned=True)
        )
        await app.state.jobs.wait_idle()
        result = app.state.jobs.get(job.id, job.workspace_id).result
        assert result["forms"] == [] and result["notes"]


async def test_dns_is_pinned_once_and_supplied_host_header_preserved(lab, monkeypatch):
    base, requests = lab
    port = urlsplit(base).port
    original = socket.getaddrinfo
    resolutions = []

    def controlled_lookup(host, requested_port, *args, **kwargs):
        if host == "fixture.invalid":
            resolutions.append(host)
            host = "127.0.0.1"
        return original(host, requested_port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", controlled_lookup)
    supplied = f"http://fixture.invalid:{port}"
    sql = client(supplied)
    await sql.request(supplied + "/forms")
    await sql.request(supplied + "/search")
    assert resolutions == ["fixture.invalid"]
    assert all(row[3]["host"] == f"fixture.invalid:{port}" for row in requests)


async def test_global_gate_applies_to_concurrent_clients_and_request_budget(lab):
    base, requests = lab
    gate = RequestGate()
    first, second = client(base, gate), client(base, gate)
    await asyncio.gather(first.request(base + "/search"), second.request(base + "/search"))
    assert requests[1][4] - requests[0][4] >= 0.95
    first.count = 40
    with pytest.raises(ValueError, match="40 requests"):
        await first.request(base + "/search")
    with pytest.raises(ValueError, match="64 KiB"):
        await second.request(base + "/search", fields=[SQLField(name="q", value="é" * 20000)])
    assert len(requests) == 2


async def test_body_deadline_and_cancel_are_bounded(lab):
    base, requests = lab
    sql = client(base)
    started = time.monotonic()
    with pytest.raises(ValueError, match="10 seconds"):
        await sql.request(base + "/slow")
    assert 9.8 <= time.monotonic() - started < 12
    task = asyncio.create_task(client(base).request(base + "/slow"))
    while len(requests) < 2:
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 1)


@pytest.mark.parametrize(
    "url",
    [
        "http://0x7f000001/",
        "http://2130706433/",
        "http://127.1/",
        "http://[::ffff:127.0.0.1]/",
        "http://user:secret@127.0.0.1/",
        "http://127.0.0.1:99999/",
        "http://127.0.0.1/\n",
    ],
)
def test_malformed_urls_rejected_before_network(url):
    with pytest.raises(ValueError):
        client(url)


async def test_https_pinning_preserves_host_and_sni_with_verified_fixture_ca(
    tmp_path: Path, monkeypatch
):
    import ssl

    import backend.services.async_sql as sql_module
    from backend.tls import ensure_tls

    material = ensure_tls(tmp_path)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(material.server_cert, material.server_key)
    names, hosts = [], []
    server_context.set_servername_callback(lambda _sock, name, _context: names.append(name))

    async def serve(reader, writer):
        await reader.readline()
        while line := await reader.readline():
            if line == b"\r\n":
                break
            if line.lower().startswith(b"host:"):
                hosts.append(line.decode().strip())
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=server_context)
    port = server.sockets[0].getsockname()[1]
    original_client = sql_module.httpx.AsyncClient
    try:
        with pytest.raises(ValueError, match="verified TLS"):
            await client(f"https://localhost:{port}").request(f"https://localhost:{port}/")

        def trusted_fixture(**kwargs):
            assert kwargs["verify"] is True
            kwargs["verify"] = material.client_context()
            return original_client(**kwargs)

        monkeypatch.setattr(sql_module.httpx, "AsyncClient", trusted_fixture)
        reply = await client(f"https://localhost:{port}").request(f"https://localhost:{port}/")
        assert reply.text == "ok"
        assert names[-1] == "localhost"
        assert hosts == [f"Host: localhost:{port}"]
    finally:
        server.close()
        await server.wait_closed()
