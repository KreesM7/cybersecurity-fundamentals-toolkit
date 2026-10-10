"""Bounded, cancellable generation through an independently owned fixed-argument helper."""

import asyncio
import base64
import binascii
import json
from ipaddress import ip_address
from uuid import UUID

from backend.jobs import JobContext, JobManager, JobSnapshot, _drain
from backend.mutations import MutationConflictError, MutationCoordinator
from backend.platform_utils import hidden_process_options, payload_host_argv
from backend.services.artifact_service import MAX_ARTIFACT, ArtifactService
from backend.services.module_service import ModuleService
from shared.payloads import PayloadCatalog, PayloadRequest


async def run_generator(data: dict[str, object], context: JobContext) -> bytes:
    spawn = asyncio.create_task(
        asyncio.create_subprocess_exec(
            *payload_host_argv(),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=65536,
            **hidden_process_options(),
        )
    )
    try:
        process = await asyncio.shield(spawn)
    except asyncio.CancelledError:
        context.cancel_event.set()
        process = await _drain(spawn)
    assert process.stdin and process.stdout and process.stderr

    async def diagnostics() -> None:
        assert process.stderr
        used = 0
        while chunk := await process.stderr.read(4096):
            used += len(chunk)
            if used > 65536:
                raise ValueError("Generator diagnostic limit reached")
            # Diagnostics may contain OS details or option values; do not persist or echo them.

    stderr = asyncio.create_task(diagnostics())
    output = bytearray()
    complete = False
    records = 0
    try:
        context.check()
        process.stdin.write(json.dumps(data, allow_nan=False).encode() + b"\n")
        await process.stdin.drain()
        async with asyncio.timeout(100):
            while line := await process.stdout.readline():
                context.check()
                records += 1
                if len(line) > 65536 or records > 20000 or complete:
                    raise ValueError("Generator protocol limit reached")
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("Invalid generator record")
                kind = value.get("type")
                if kind == "data":
                    output.extend(base64.b64decode(value["base64"], validate=True))
                    if len(output) > MAX_ARTIFACT:
                        raise ValueError("Generated artifact exceeds eight MiB")
                elif kind == "progress":
                    await context.progress(str(value.get("message", ""))[:1000])
                elif kind == "end" and value.get("ok") is True:
                    complete = True
                else:
                    raise ValueError("Generation failed or returned invalid records")
            await stderr
            if await process.wait() != 0 or not complete or not output:
                raise ValueError("Generation incomplete; no artifact was saved")
        return bytes(output)
    except (json.JSONDecodeError, binascii.Error, KeyError) as exc:
        raise ValueError("Invalid generator output") from exc
    finally:
        process.stdin.close()

        async def reap() -> None:
            stderr.cancel()
            await asyncio.gather(stderr, return_exceptions=True)

            async def discard(stream: asyncio.StreamReader) -> None:
                while await stream.read(65536):
                    pass

            # A helper blocked writing a full pipe cannot observe stdin EOF or
            # its watchdog. Drain both streams without retaining sensitive data.
            drains = [
                asyncio.create_task(discard(stream))
                for stream in (process.stdout, process.stderr)
                if stream is not None
            ]
            try:
                # EOF reaches the supervisor, which kills and reaps its own msfvenom group.
                await asyncio.wait_for(process.wait(), 10)
            except TimeoutError:
                # The independent supervisor has its own 90s watchdog; retain ownership until exit.
                await asyncio.wait_for(process.wait(), 95)
            finally:
                await asyncio.gather(*drains)

        await _drain(asyncio.create_task(reap()))


class PayloadService:
    def __init__(
        self,
        modules: ModuleService,
        artifacts: ArtifactService,
        jobs: JobManager,
        mutations: MutationCoordinator,
    ) -> None:
        self.modules, self.artifacts, self.jobs, self.mutations = (
            modules,
            artifacts,
            jobs,
            mutations,
        )

    async def catalog(self) -> PayloadCatalog:
        formats = (await self.modules.framework.call("module.encode_formats")).get("formats")
        encoders = (await self.modules.framework.call("module.encoders")).get("modules")
        if (
            not isinstance(formats, list)
            or not isinstance(encoders, list)
            or len(formats) > 1000
            or len(encoders) > 10000
        ):
            raise ValueError("Invalid generator metadata")
        return PayloadCatalog(
            formats=[str(x) for x in formats], encoders=[str(x) for x in encoders]
        )

    async def generate(self, data: PayloadRequest, request_id: UUID) -> JobSnapshot:
        if not data.confirmed or self.modules.identity() != str(data.framework_id):
            raise MutationConflictError(
                "Confirm permission and refresh the current framework metadata."
            )
        catalog = await self.catalog()
        if data.format not in catalog.formats or (
            data.encoder and data.encoder not in catalog.encoders
        ):
            raise ValueError("Choose an advertised format and encoder")
        detail = await self.modules.detail("payload/" + data.payload)
        values: dict[str, str | int | float | bool] = {}
        names = {item.name for item in detail.options}
        if "LHOST" in names:
            values["LHOST"] = data.lhost
        if "LPORT" in names:
            values["LPORT"] = data.lport
        await self.modules.validate_options(detail, values)
        host = ip_address(data.lhost)
        if host.is_unspecified or host.is_multicast or "%" in data.lhost:
            raise ValueError("Choose a literal unicast listener")

        async def action() -> JobSnapshot:
            lease = await self.modules.workspaces.lease(data.workspace_id)

            async def work(context: JobContext) -> object:
                await context.progress("Generating payload with the dedicated installed msfvenom…")
                content = await run_generator(
                    {
                        "payload": data.payload,
                        "format": data.format,
                        "encoder": data.encoder,
                        "iterations": data.iterations,
                        "lhost": str(host),
                        "lport": data.lport,
                    },
                    context,
                )
                context.check()
                artifact = await self.artifacts.create(
                    data.workspace_id, "payload." + data.format, content
                )
                return {
                    "artifact_id": str(artifact.id),
                    "size_bytes": artifact.size_bytes,
                    "sha256": artifact.sha256,
                }

            try:
                return await self.jobs.submit(
                    "payload-generator", data.workspace_id, work, cleanup=lease.release
                )
            except BaseException:
                await lease.release()
                raise

        return JobSnapshot.model_validate_json(
            json.dumps(
                await self.mutations.execute_external(
                    data.workspace_id,
                    request_id,
                    "payload.generate",
                    data.model_dump(mode="json"),
                    action,
                )
            )
        )
