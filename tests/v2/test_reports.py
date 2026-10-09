import asyncio
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from backend.main import create_app
from backend.models import Notes, Report
from backend.services.report_service import render_report
from shared.reports import ReportRequest


def snapshot():
    return dict(
        title='<img src="https://example.org">',
        workspace="test",
        created="now",
        sections=[("Targets", [["<script>alert(1)</script>"]])],
        notes=None,
    )


def test_escape_and_missing_pdf_fallback(monkeypatch):
    def missing(name):
        raise ImportError("missing optional renderer")

    monkeypatch.setattr("backend.services.report_service.import_module", missing)
    content, extension, message = render_report(snapshot(), True)
    assert extension == "html" and "unavailable" in message
    assert b"<script>" not in content and b"&lt;script&gt;" in content
    assert b"<img" not in content and b"default-src 'none'" in content


def test_real_pdf_and_no_resources():
    pytest.importorskip("weasyprint")
    from weasyprint.urls import URLFetcher

    fetcher = URLFetcher(allowed_protocols=(), allow_redirects=False, fail_on_errors=True)
    for url in ("file:///etc/passwd", "http://127.0.0.1/", "data:text/plain,secret"):
        with pytest.raises(ValueError):
            fetcher.fetch(url)
    content, extension, _ = render_report(snapshot(), True)
    assert extension == "pdf" and content.startswith(b"%PDF-")


async def test_report_job_scope_redaction_and_replay(tmp_path):
    app = create_app("a" * 64, "reports", tmp_path)
    async with app.router.lifespan_context(app):
        scope = app.state.workspaces.active_id
        async with await app.state.workspaces.lease(scope) as lease:
            async with lease.sessions.begin() as session:
                row = await session.get(Notes, 1)
                if row:
                    row.text = "password=fixture-secret"
                else:
                    session.add(Notes(id=1, text="password=fixture-secret"))
        request = ReportRequest(workspace_id=scope, title="Assessment")
        identifier = uuid4()
        job = await app.state.reports.generate(request, identifier)
        again = await app.state.reports.generate(request, identifier)
        assert again.id == job.id
        for _ in range(100):
            job = app.state.jobs.get(job.id, scope)
            if job.status not in {"queued", "running"}:
                break
            await asyncio.sleep(0.02)
        assert job.status == "succeeded", job.error
        content = await app.state.artifacts.read(scope, UUID(job.result["artifact_id"]))
        assert b"fixture-secret" not in content and b"Explicitly included notes" not in content
        request.include_notes = True
        job = await app.state.reports.generate(request, uuid4())
        for _ in range(100):
            job = app.state.jobs.get(job.id, scope)
            if job.status not in {"queued", "running"}:
                break
            await asyncio.sleep(0.02)
        assert job.status == "succeeded", job.error
        content = await app.state.artifacts.read(scope, UUID(job.result["artifact_id"]))
        assert b"fixture-secret" not in content and b"[REDACTED]" in content
        async with await app.state.workspaces.lease(scope) as lease:
            async with lease.sessions() as session:
                assert len(list(await session.scalars(select(Report)))) == 2
