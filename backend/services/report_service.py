"""Escaped summaries without credentials, raw command output or remote resources."""

import json
from datetime import UTC, datetime
from importlib import import_module
from uuid import UUID, uuid4

from jinja2 import Environment, StrictUndefined
from sqlalchemy import select

from backend.jobs import JobContext, JobManager, JobSnapshot
from backend.models import JobAssociation, Notes, RemoteSession, Report, SecDeskFinding, Target
from backend.mutations import MutationCoordinator
from backend.services.artifact_service import ArtifactService
from backend.services.workspace_service import WorkspaceService
from shared.reports import ReportRequest

TEMPLATE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>{{ title }}</title><style>body{font:14px sans-serif;color:#17212b;margin:32px}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #aaa;padding:6px;text-align:left}
pre{white-space:pre-wrap;overflow-wrap:anywhere}h2{break-after:avoid}</style></head><body>
<h1>{{ title }}</h1><p>Workspace {{ workspace }} · {{ created }}</p>
<p>Historical summary, not a live assessment. Each section is limited to 500 records;
additional rows are omitted. Credentials, command arguments and raw outputs are excluded.</p>
{% for heading, rows in sections %}<h2>{{ heading }}</h2><table>
{% for row in rows %}<tr>{% for cell in row %}<td>{{ cell }}</td>{% endfor %}</tr>
{% else %}<tr><td>No records</td></tr>{% endfor %}</table>{% endfor %}
{% if notes is not none %}<h2>Explicitly included notes</h2><pre>{{ notes }}</pre>{% endif %}
</body></html>"""


def render_report(data: dict[str, object], pdf: bool) -> tuple[bytes, str, str]:
    html = (
        Environment(autoescape=True, undefined=StrictUndefined).from_string(TEMPLATE).render(data)
    )
    if pdf:
        try:
            # Optional dependency. Fixed templates contain no resource references; deny all
            # protocols as a second boundary, including file:, data:, HTTP and redirects.
            renderer = import_module("weasyprint")
            urls = import_module("weasyprint.urls")
            fetcher = urls.URLFetcher(
                allowed_protocols=(), allow_redirects=False, fail_on_errors=True
            )
            content: bytes = renderer.HTML(string=html, url_fetcher=fetcher).write_pdf()
            return content, "pdf", "PDF created."
        except (ImportError, OSError, RuntimeError, ValueError):
            return html.encode(), "html", "PDF renderer unavailable; an HTML report was saved."
    return html.encode(), "html", "HTML created."


class ReportService:
    def __init__(
        self,
        workspaces: WorkspaceService,
        artifacts: ArtifactService,
        jobs: JobManager,
        mutations: MutationCoordinator,
    ) -> None:
        self.workspaces, self.artifacts = workspaces, artifacts
        self.jobs, self.mutations = jobs, mutations

    async def generate(self, request: ReportRequest, request_id: UUID) -> JobSnapshot:
        async def action() -> JobSnapshot:
            lease = await self.workspaces.lease(request.workspace_id)

            async def work(context: JobContext) -> object:
                clean = self.jobs.hub.redactor.text
                await context.progress("Collecting a bounded workspace summary…")
                async with lease.sessions() as session:
                    targets = await session.scalars(
                        select(Target).order_by(Target.address).limit(500)
                    )
                    sections = [
                        (
                            "Targets",
                            [[row.address, clean(row.hostname), row.status] for row in targets],
                        )
                    ]
                    launches = await session.scalars(
                        select(JobAssociation).order_by(JobAssociation.created_at.desc()).limit(500)
                    )
                    sections.append(
                        (
                            "Recorded framework launches",
                            [
                                [clean(row.module_id), row.status, str(row.created_at)]
                                for row in launches
                            ],
                        )
                    )
                    sessions = await session.scalars(select(RemoteSession).limit(500))
                    sections.append(
                        (
                            "Recorded sessions",
                            [[clean(row.remote_id), str(row.framework_id)] for row in sessions],
                        )
                    )
                    sections.append(
                        (
                            "Local analyses (current application session)",
                            [
                                [clean(row.tool_id), row.status, str(row.created_at)]
                                for row in self.jobs.list(request.workspace_id)[:500]
                            ],
                        )
                    )
                    findings = await session.scalars(
                        select(SecDeskFinding).order_by(SecDeskFinding.created_at.desc()).limit(500)
                    )
                    sections.append(
                        (
                            "Explicit SecDesk findings",
                            [
                                [
                                    clean(row.tool_id),
                                    clean(row.severity),
                                    clean(row.target),
                                    clean(row.title),
                                ]
                                for row in findings
                            ],
                        )
                    )
                    notes = await session.get(Notes, 1) if request.include_notes else None
                    snapshot: dict[str, object] = {
                        "title": clean(request.title),
                        "workspace": str(request.workspace_id),
                        "created": datetime.now(UTC).isoformat(),
                        "sections": sections,
                        "notes": clean(notes.text) if notes else None,
                    }
                content, extension, message = await context.run_sync(
                    lambda: render_report(snapshot, request.format == "pdf")
                )
                context.check()
                identifier = uuid4()
                async with lease.sessions.begin() as session:
                    session.add(
                        Report(
                            id=str(identifier),
                            title=clean(request.title),
                            created_at=datetime.now(UTC),
                        )
                    )
                try:
                    artifact = await self.artifacts.create(
                        request.workspace_id,
                        "report." + extension,
                        content,
                        "application/pdf" if extension == "pdf" else "text/html",
                        identifier,
                    )
                except BaseException:
                    async with lease.sessions.begin() as session:
                        row = await session.get(Report, str(identifier))
                        if row:
                            await session.delete(row)
                    raise
                return {
                    "artifact_id": str(artifact.id),
                    "name": artifact.name,
                    "message": message,
                    "sha256": artifact.sha256,
                }

            try:
                return await self.jobs.submit(
                    "report", request.workspace_id, work, cleanup=lease.release
                )
            except BaseException:
                await lease.release()
                raise

        result = await self.mutations.execute(
            request.workspace_id,
            request_id,
            "report.generate",
            request.model_dump(mode="json"),
            action,
        )
        return JobSnapshot.model_validate_json(json.dumps(result))
