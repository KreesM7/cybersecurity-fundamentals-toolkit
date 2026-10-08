"""Memory-only tool dispatch, capturing a real workspace lease for every job."""

from __future__ import annotations

import asyncio
import builtins
import math
import time
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Literal, cast
from uuid import UUID, uuid4

from backend.jobs import JobContext, JobManager, JobSnapshot
from backend.services.request_gate import RequestGate
from backend.services.workspace_service import WorkspaceService
from backend.tools import discover_tools
from shared.tools import (
    AnomalyOptions,
    CaesarOptions,
    DoSOptions,
    FileOptions,
    InterfaceView,
    PasswordOptions,
    ScannerOptions,
    SQLField,
    SQLForm,
    SQLOptions,
    ToolOptions,
    ToolView,
)
from toolkit.security import validate_form_action, validate_url
from toolkit.task_context import TaskContext

MAX_FILE_BYTES = 25 * 1024 * 1024


@dataclass(frozen=True)
class CapturedDiscovery:
    workspace_id: UUID
    source_url: str
    generation: int
    forms: tuple[SQLForm, ...]
    pinned: str | None
    created: float


class ToolService:
    def __init__(self, workspaces: WorkspaceService, jobs: JobManager) -> None:
        self.workspaces, self.jobs = workspaces, jobs
        self.specs, self.loader_failures = discover_tools()
        self.discoveries: dict[UUID, CapturedDiscovery] = {}
        self.gate = RequestGate()

    async def list(self) -> list[ToolView]:
        rows = list(self.loader_failures)
        for spec in self.specs.values():
            try:
                reason = await asyncio.to_thread(spec.readiness)
            except Exception:
                reason = (
                    "Dependency unavailable. Check native setup and installed tool requirements."
                )
            rows.append(
                ToolView(
                    id=spec.id,
                    title=spec.title,
                    order=spec.order,
                    available=not bool(reason),
                    reason=reason or spec.note,
                )
            )
        return sorted(rows, key=lambda row: (row.order, row.id))

    async def interfaces(self) -> builtins.list[InterfaceView]:
        from toolkit.modules.network_scanner import list_interfaces

        return [
            InterfaceView(**asdict(value)) for value in await asyncio.to_thread(list_interfaces)
        ]

    def _sql_form(
        self, options: SQLOptions, workspace_id: UUID
    ) -> tuple[CapturedDiscovery, SQLForm]:
        capture = self.discoveries.get(options.discovery_id) if options.discovery_id else None
        if capture is None or time.monotonic() - capture.created > 1800:
            raise ValueError("Discovery expired or unavailable. Load forms for the current URL.")
        if (
            capture.workspace_id != workspace_id
            or capture.source_url != validate_url(options.url).url
            or capture.generation != options.generation
        ):
            raise ValueError("Target or workspace changed. Load forms again before testing.")
        if options.form_index >= len(capture.forms):
            raise ValueError("Selected form is unavailable. Load forms again.")
        form = capture.forms[options.form_index]
        if [field.name for field in options.fields] != [field.name for field in form.fields]:
            raise ValueError("Form field names changed. Load forms again.")
        validate_form_action(validate_url(capture.source_url), form.action)
        if form.method == "POST" and not options.allow_post:
            raise ValueError(
                "POST testing is disabled. Enable it for the selected form explicitly."
            )
        return capture, form

    async def submit(
        self,
        tool_id: str,
        options: ToolOptions,
        upload: bytes | None = None,
        filename: str = "",
        *,
        workspace_id: UUID | None = None,
    ) -> JobSnapshot:
        spec = self.specs.get(tool_id)
        if spec is None or options.kind != tool_id:
            raise ValueError("Choose a registered tool and matching input fields.")
        workspace_id = workspace_id or self.workspaces.active_id
        if isinstance(options, ScannerOptions):
            from backend.services.async_scanner import validate_scan

            # Ownership precedes interface inspection, Nmap discovery and every network action.
            validate_scan(options)
        if isinstance(options, SQLOptions):
            if not options.owned:
                raise ValueError("Confirm ownership or permission before loading forms or testing.")
            validate_url(options.url)
            if options.operation == "test":
                self._sql_form(options, workspace_id)
        needs_file = isinstance(options, (DoSOptions, AnomalyOptions, FileOptions))
        if needs_file != (upload is not None):
            raise ValueError(
                "This tool requires an uploaded file."
                if needs_file
                else "This tool accepts fields, not a file."
            )
        if upload is not None and len(upload) > MAX_FILE_BYTES:
            raise ValueError("Input exceeds the 25 MiB upload limit.")
        safe_filename = PurePosixPath(filename.replace("\\", "/")).name[:255]
        lease = await self.workspaces.lease(workspace_id)

        # JobManager clears the work closure on every outcome; no input enters storage/events.
        async def work(context: JobContext) -> object:
            try:
                return await spec.run(self, options, upload, safe_filename, context)
            except (ValueError, RuntimeError) as exc:
                return {"error": {"code": "invalid_input_or_readiness", "message": str(exc)}}

        try:
            return await self.jobs.submit(tool_id, lease.workspace_id, work, cleanup=lease.release)
        except BaseException:
            await lease.release()
            raise

    async def analyze(
        self,
        tool_id: str,
        options: ToolOptions,
        content: bytes | None,
        filename: str,
        context: JobContext,
    ) -> object:
        if isinstance(options, ScannerOptions):
            from backend.services.async_scanner import scan

            return await scan(options, context)
        if isinstance(options, SQLOptions):
            from backend.services.async_sql import SQLClient, probe
            from toolkit.modules.sql_checker import parse_forms

            client = SQLClient(self.gate, context, options.url)
            if options.operation == "test":
                capture, form = self._sql_form(options, context.workspace_id)
                client.pinned = capture.pinned
                return await probe(client, form, options.fields)
            reply = await client.request(options.url)
            if reply.status >= 400:
                raise ValueError(f"Page returned HTTP {reply.status}; form discovery stopped.")
            discovery = await context.run_sync(lambda: parse_forms(options.url, reply.text))
            forms = tuple(
                SQLForm(
                    action=form.action,
                    method=cast(Literal["GET", "POST"], form.method),
                    fields=[SQLField(name=name, value=value) for name, value in form.fields],
                    probe_indices=list(form.probe_indices or ()),
                )
                for form in discovery.forms
            )
            if len(self.discoveries) >= 1000:
                self.discoveries.pop(next(iter(self.discoveries)))
            identifier = uuid4()
            self.discoveries[identifier] = CapturedDiscovery(
                context.workspace_id,
                discovery.url,
                options.generation,
                forms,
                client.pinned,
                time.monotonic(),
            )
            return {
                "discovery_id": str(identifier),
                "source_url": discovery.url,
                "generation": options.generation,
                "forms": [form.model_dump(mode="json") for form in forms],
                "notes": discovery.notes,
            }
        task = TaskContext(context.cancel_event)
        return await context.run_sync(lambda: self._cpu(options, content, filename, task))

    @staticmethod
    def _cpu(
        options: ToolOptions, content: bytes | None, filename: str, task: TaskContext
    ) -> object:
        task.check()
        if isinstance(options, CaesarOptions):
            from toolkit.modules.caesar import brute_force, transform

            return {
                "text": transform(options.text, options.shift, options.decrypt),
                "candidates": [list(row) for row in brute_force(options.text)],
            }
        if isinstance(options, PasswordOptions):
            from toolkit.modules.password_strength import analyze_password

            return asdict(analyze_password(options.password.get_secret_value()))
        if isinstance(options, FileOptions):
            from toolkit.modules.file_type import identify_bytes

            assert content is not None
            return asdict(identify_bytes(content, filename, task))
        if isinstance(options, (DoSOptions, AnomalyOptions)):
            from toolkit.traffic import read_traffic_bytes

            assert content is not None
            data = read_traffic_bytes(
                content, filename, require_volume=isinstance(options, AnomalyOptions), task=task
            )
            metadata = {
                "events": len(data.events),
                "unit": data.unit,
                "complete": data.complete,
                "skipped": data.skipped,
                "warnings": data.warnings,
            }
            if isinstance(options, DoSOptions):
                from toolkit.modules.dos_detector import detect_spikes

                findings = detect_spikes(data.events, options.threshold, task)
                return {
                    **metadata,
                    "total": len(findings),
                    "spikes": [asdict(row) for row in findings[:5000]],
                }
            from toolkit.modules.anomaly_detector import detect_anomalies

            report = detect_anomalies(
                data.events,
                options.bin_seconds,
                options.baseline_bins,
                options.threshold,
                task=task,
            )
            rows = []
            for row in report.anomalies:
                score = row.zscore
                rows.append(
                    {
                        **asdict(row),
                        "zscore": score if math.isfinite(score) else None,
                        "score_kind": (
                            "finite"
                            if math.isfinite(score)
                            else "positive_infinity" if score > 0 else "negative_infinity"
                        ),
                    }
                )
            return {
                **metadata,
                "sufficient": report.sufficient,
                "status": "analyzed" if report.sufficient else "insufficient_baseline",
                "examined": report.examined,
                "total": report.total,
                "anomalies": rows,
            }
        raise ValueError("Unsupported tool inputs.")

    async def close(self) -> None:
        self.discoveries.clear()
