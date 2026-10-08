"""Async quote-only SQL checks with origin, DNS, rate and size boundaries."""

import asyncio
from dataclasses import replace
from urllib.parse import urlencode

import httpx

from backend.jobs import JobContext
from backend.services.request_gate import RequestGate
from shared.tools import SQLField, SQLForm
from toolkit.modules.sql_checker import PROBES, Response, _errors, _normalize, content_similarity
from toolkit.security import WebTarget, resolve_web_target, validate_form_action, validate_url
from toolkit.task_context import TaskContext


class SQLClient:
    def __init__(self, gate: RequestGate, context: JobContext, source: str) -> None:
        self.gate, self.context = gate, context
        self.source = validate_url(source)
        self.pinned: str | None = None
        self.count = 0

    async def resolve(self, target: WebTarget) -> str:
        if self.pinned is not None:
            return self.pinned
        if target.ip is not None:
            self.pinned = target.ip
            return target.ip
        try:
            resolved = await self.context.run_sync(
                lambda: resolve_web_target(target, TaskContext(self.context.cancel_event))
            )
        except ValueError as exc:
            raise ValueError(
                "DNS resolution failed or exceeded 3 seconds. Check the hostname."
            ) from exc
        if resolved.ip is None:
            raise ValueError("DNS did not return an ordinary unicast address.")
        self.pinned = resolved.ip
        return self.pinned

    async def request(
        self, url: str, method: str = "GET", fields: list[SQLField] | None = None
    ) -> Response:
        target = validate_form_action(self.source, url)
        if method not in ("GET", "POST"):
            raise ValueError("Only GET and explicitly enabled form POST are supported.")
        if self.count >= 40:
            raise ValueError("Request budget exhausted (40 requests).")
        encoded = urlencode([(field.name, field.value) for field in fields or []]).encode()
        if len(encoded) > 65536:
            raise ValueError("Form input exceeds the 64 KiB request limit.")
        self.context.check()
        pinned = await self.resolve(target)
        transport_target = replace(target, host=pinned, ip=pinned)
        url_object = httpx.URL(transport_target.url)
        if method == "GET" and encoded:
            query = target.query.encode() + (b"&" if target.query else b"") + encoded
            url_object = url_object.copy_with(query=query)
        await self.gate.wait()
        self.context.check()
        self.count += 1
        headers = {
            "Host": target.authority,
            "Accept-Encoding": "identity",
            "User-Agent": "CybersecurityFundamentalsToolkit/2",
        }
        if method == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            async with asyncio.timeout(15):
                async with httpx.AsyncClient(
                    trust_env=False,
                    follow_redirects=False,
                    verify=True,
                    timeout=httpx.Timeout(5, connect=3),
                ) as client:
                    async with client.stream(
                        method,
                        url_object,
                        content=encoded if method == "POST" else None,
                        headers=headers,
                        extensions={"sni_hostname": target.host},
                    ) as response:
                        if 300 <= response.status_code < 400:
                            raise ValueError("Redirect blocked. Enter the final URL directly.")
                        if response.headers.get("Content-Encoding", "identity").lower() not in (
                            "",
                            "identity",
                        ):
                            raise ValueError(
                                "Compressed responses are unsupported; use identity encoding."
                            )
                        chunks, total = [], 0
                        async with asyncio.timeout(10):
                            async for chunk in response.aiter_raw():
                                self.context.check()
                                total += len(chunk)
                                if total > 1048576:
                                    raise ValueError("Response exceeds the 1 MiB analysis limit.")
                                chunks.append(chunk)
                        return Response(
                            response.status_code, b"".join(chunks).decode("utf-8", errors="replace")
                        )
        except TimeoutError as exc:
            raise ValueError(
                "Request exceeded the body (10 seconds) or whole-request (15 seconds) limit."
            ) from exc
        except httpx.HTTPError as exc:
            raise ValueError(
                "HTTP request failed. Check routing, verified TLS and server readiness."
            ) from exc


async def probe(client: SQLClient, form: SQLForm, fields: list[SQLField]) -> object:
    first = await client.request(form.action, form.method, fields)
    second = await client.request(form.action, form.method, fields)
    values = [field.value for field in fields]

    def baseline() -> tuple[str, set[str]]:
        a, b = _normalize(first.text, values), _normalize(second.text, values)
        if first.status != second.status or content_similarity(a, b) < 0.98:
            raise ValueError(
                "Baseline responses differ; testing stopped because comparison is unreliable."
            )
        return a, _errors(first.text) | _errors(second.text)

    a, baseline_errors = await client.context.run_sync(baseline)
    findings = []
    for index in form.probe_indices[:12]:
        for quote in PROBES:
            client.context.check()
            await client.context.progress(
                f"Testing form field {index + 1}; request {client.count + 1}/40"
            )
            changed = list(fields)
            changed[index] = SQLField(name=fields[index].name, value=quote)
            reply = await client.request(form.action, form.method, changed)

            def compare() -> list[str]:
                evidence = []
                new_errors = _errors(reply.text) - baseline_errors
                if new_errors:
                    evidence.append("New SQL error signature: " + ", ".join(sorted(new_errors)))
                if reply.status != first.status:
                    evidence.append(f"HTTP status changed from {first.status} to {reply.status}")
                if content_similarity(a, _normalize(reply.text, values + [quote])) < 0.8:
                    evidence.append("Response content changed substantially")
                return evidence

            evidence = await client.context.run_sync(compare)
            if evidence:
                findings.append(
                    {
                        "field": fields[index].name,
                        "probe": quote,
                        "status": reply.status,
                        "evidence": "; ".join(evidence),
                    }
                )
    return {"findings": findings, "requests": client.count}
