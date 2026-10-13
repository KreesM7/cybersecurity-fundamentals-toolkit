"""Bounded metadata cache, workspace library, and durable one-shot module launch."""

from __future__ import annotations

import asyncio
import re
import time
from collections import OrderedDict
from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import UUID, uuid4

from pydantic import JsonValue
from sqlalchemy import delete, select

from backend.events import EventHub
from backend.models import FrameworkInstance, JobAssociation, ModuleFavorite, ModuleRecent, Target
from backend.mutations import MutationConflictError, MutationCoordinator
from backend.services.metasploit_service import MetasploitService, module_parts
from backend.services.rpc_transport import RpcFailure
from backend.services.workspace_service import WorkspaceService
from shared.modules import (
    FavoriteChange,
    ModuleDetail,
    ModuleLaunch,
    ModuleLibrary,
    ModuleRun,
    ModuleSearch,
    ModuleSummary,
    OptionSpec,
)
from shared.workspaces import TargetBulk


class ModuleService:
    def __init__(
        self,
        workspaces: WorkspaceService,
        framework: MetasploitService,
        events: EventHub,
        mutations: MutationCoordinator,
    ) -> None:
        self.workspaces, self.framework = workspaces, framework
        self.events, self.mutations = events, mutations
        self._search: OrderedDict[tuple[str, str], tuple[float, ModuleSearch]] = OrderedDict()
        self._metadata: OrderedDict[tuple[str, str], ModuleDetail] = OrderedDict()
        self._cache_lock = asyncio.Lock()

    def identity(self) -> str:
        status = self.framework.status()
        if status.state == "Offline" or not status.instance_id:
            raise RpcFailure("Connect to Metasploit in Settings before browsing modules.")
        return str(UUID(status.instance_id))

    async def search(self, query: str, kind: str, rank: str, platform: str) -> ModuleSearch:
        identity = self.identity()
        text = " ".join(
            part
            for part in (
                query,
                f"type:{kind}" if kind else "",
                f"rank:{rank}" if rank else "",
                f"platform:{platform}" if platform else "",
            )
            if part
        )
        key = identity, text
        async with self._cache_lock:
            cached = self._search.get(key)
            if cached and time.monotonic() - cached[0] < 60:
                return cached[1].model_copy(deep=True)
            reply = await self.framework.call("module.search", [text])
            rows = reply.get("modules")
            if not isinstance(rows, list) or len(rows) > 30000:
                raise RpcFailure("Framework returned an invalid or oversized module catalog.")
            result = []
            for row in rows[:2000]:
                if not isinstance(row, dict):
                    raise RpcFailure("Framework returned invalid search metadata.")
                path = row.get("fullname")
                if not isinstance(path, str):
                    raise RpcFailure("Framework returned invalid module identity.")
                module_type, _ = module_parts(path)
                result.append(
                    ModuleSummary.model_validate(
                        {
                            "path": path,
                            "kind": module_type,
                            "name": row.get("name", path),
                            "rank": row.get("rank", ""),
                        }
                    )
                )
            value = ModuleSearch(modules=result, truncated=len(rows) > 2000)
            self._search[key] = time.monotonic(), value
            while len(self._search) > 32:
                self._search.popitem(last=False)
            return value.model_copy(deep=True)

    async def detail(self, path: str) -> ModuleDetail:
        kind, name = module_parts(path)
        identity = self.identity()
        key = identity, path
        async with self._cache_lock:
            if key in self._metadata:
                return self._metadata[key].model_copy(deep=True)
            raw = await self.framework.get_module_info(path)
            info, options = raw.get("info"), raw.get("options")
            if not isinstance(info, dict) or not isinstance(options, dict) or len(options) > 200:
                raise RpcFailure("Framework returned invalid option metadata.")
            fields = []
            for field, item in options.items():
                if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", field) or not isinstance(item, dict):
                    raise RpcFailure("Framework returned invalid option metadata.")
                default = item.get("default")
                if item.get("type") == "bool" and isinstance(default, str):
                    if default.lower() in {"true", "false"}:
                        default = default.lower() == "true"
                choices = item.get("enums", [])
                fields.append(
                    OptionSpec(
                        name=field,
                        kind=str(item.get("type", "string")),
                        required=item.get("required") is True,
                        description=str(item.get("desc", ""))[:4000],
                        default=default if isinstance(default, (str, int, float, bool)) else None,
                        choices=[str(x) for x in choices] if isinstance(choices, list) else [],
                        secret=bool(
                            re.search(r"password|passwd|secret|token|credential", field, re.I)
                        ),
                    )
                )
            payloads: list[str] = []
            if kind == "exploit":
                targets = info.get("targets")
                if isinstance(targets, dict) and targets:
                    fields.append(
                        OptionSpec(
                            name="TARGET",
                            kind="integer",
                            required=True,
                            description="Framework target index: " + str(targets)[:4000],
                            default=str(info.get("default_target", next(iter(targets)))),
                            choices=list(targets),
                        )
                    )
                compatible = (await self.framework.call("module.compatible_payloads", [name])).get(
                    "payloads", []
                )
                if (
                    not isinstance(compatible, list)
                    or len(compatible) > 10000
                    or not all(isinstance(x, str) for x in compatible)
                ):
                    raise RpcFailure("Framework returned invalid payload metadata.")
                payloads = [str(x) for x in compatible]
            value = ModuleDetail(
                path=path,
                framework_id=UUID(identity),
                name=str(info.get("name", path))[:1000],
                description=str(info.get("description", ""))[:32000],
                options=fields,
                payloads=payloads,
            )
            self._metadata[key] = value
            while len(self._metadata) > 128:
                self._metadata.popitem(last=False)
            return value.model_copy(deep=True)

    async def library(self, workspace_id: UUID) -> ModuleLibrary:
        async with await self.workspaces.lease(workspace_id) as lease:
            async with lease.sessions() as session:
                favorites = list(
                    await session.scalars(
                        select(ModuleFavorite.module_id).order_by(ModuleFavorite.module_id)
                    )
                )
                recent = list(
                    await session.scalars(
                        select(ModuleRecent.module_id)
                        .order_by(ModuleRecent.used_at.desc())
                        .limit(50)
                    )
                )
                return ModuleLibrary(favorites=favorites, recent=list(dict.fromkeys(recent)))

    async def favorite(self, workspace_id: UUID, change: FavoriteChange) -> ModuleLibrary:
        module_parts(change.path)
        async with await self.workspaces.lease(workspace_id) as lease:
            async with lease.sessions.begin() as session:
                row = await session.get(ModuleFavorite, change.path)
                if change.enabled and row is None:
                    count = len(list(await session.scalars(select(ModuleFavorite.module_id))))
                    if count >= 2000:
                        raise ValueError("Favorite limit reached")
                    session.add(ModuleFavorite(module_id=change.path, created_at=datetime.now(UTC)))
                elif not change.enabled and row is not None:
                    await session.delete(row)
        return await self.library(workspace_id)

    async def validate_options(
        self, detail: ModuleDetail, values: dict[str, str | int | float | bool]
    ) -> dict[str, JsonValue]:
        fields = {item.name: item for item in detail.options}
        payload = values.get("PAYLOAD")
        if payload is not None:
            if not isinstance(payload, str) or payload not in detail.payloads:
                raise ValueError("Choose a compatible payload")
            fields.update(
                {item.name: item for item in (await self.detail("payload/" + payload)).options}
            )
            fields["PAYLOAD"] = OptionSpec(name="PAYLOAD", choices=detail.payloads)
        if set(values) - fields.keys():
            raise ValueError("Unknown module option")
        result: dict[str, JsonValue] = {}
        for name, field in fields.items():
            value = values.get(name, field.default)
            if value is None or value == "":
                if field.required:
                    raise ValueError("Required option is missing")
                continue
            if isinstance(value, str) and (
                len(value) > 4096 or "\x00" in value or "\n" in value or "\r" in value
            ):
                raise ValueError("Invalid option value")
            if field.kind == "bool" and not isinstance(value, bool):
                raise ValueError("Expected a boolean option")
            if field.kind in {"integer", "int", "port"}:
                if (
                    isinstance(value, bool)
                    or not isinstance(value, (str, int))
                    or not re.fullmatch(r"-?[0-9]{1,10}", str(value))
                ):
                    raise ValueError("Expected an integer option")
                value = int(value)
                if field.kind == "port" and not 1 <= value <= 65535:
                    raise ValueError("Invalid port")
            if field.choices and str(value) not in field.choices:
                raise ValueError("Choose an advertised option")
            if name in {"RHOST", "RHOSTS"}:
                # No file:, URL, framework range expansion, DNS, or unbounded CIDR at this boundary.
                value = TargetBulk(cidr=str(value)).cidr
            if name == "LHOST":
                address = ip_address(str(value))
                if address.is_unspecified or address.is_multicast or "%" in str(value):
                    raise ValueError("Choose a literal unicast listener address")
                value = str(address)
            result[name] = value
        return result

    async def launch(self, data: ModuleRun, request_id: UUID) -> ModuleLaunch:
        async def action() -> ModuleLaunch:
            if module_parts(data.path)[0] not in {"auxiliary", "exploit", "post", "evasion"}:
                raise ValueError(
                    "This module type is metadata-only here; use Payloads for generation"
                )
            if self.identity() != str(data.framework_id):
                raise MutationConflictError(
                    "Framework changed; refresh module metadata before launching."
                )
            detail = await self.detail(data.path)
            options = await self.validate_options(detail, data.options)
            async with await self.workspaces.lease(data.workspace_id) as lease:
                if data.target_id:
                    async with lease.sessions() as session:
                        if await session.get(Target, str(data.target_id)) is None:
                            raise KeyError("Target not in workspace")
                identifier = uuid4()
                await self.events.publish(
                    "module-launch",
                    {"id": str(identifier), "path": data.path, "status": "launching"},
                    workspace_id=data.workspace_id,
                )
                # Prevent disconnect/swap between the identity check and dispatch.
                async with self.framework._connection_lock:
                    if self.identity() != str(data.framework_id):
                        raise MutationConflictError("Framework changed before launch.")
                    reply = await self.framework.run_module(data.path, options, owned=True)
                remote = reply.get("job_id")
                execution = reply.get("uuid")
                if remote is not None and (
                    isinstance(remote, bool) or not re.fullmatch(r"[0-9]{1,20}", str(remote))
                ):
                    raise RpcFailure(
                        "Framework launch outcome is uncertain; reconcile its job list."
                    )
                if execution is not None and not re.fullmatch(
                    r"[A-Za-z0-9_-]{1,64}", str(execution)
                ):
                    raise RpcFailure("Framework execution identity is invalid; reconcile its jobs.")
                result = ModuleLaunch(
                    id=identifier,
                    workspace_id=data.workspace_id,
                    framework_id=data.framework_id,
                    path=data.path,
                    remote_job_id=str(remote) if remote is not None else None,
                    execution_id=str(execution) if execution else None,
                    status="launched",
                )
                async with lease.sessions.begin() as session:
                    framework = await session.get(FrameworkInstance, str(data.framework_id))
                    if framework is None:
                        session.add(
                            FrameworkInstance(
                                id=str(data.framework_id),
                                identity=str(data.framework_id),
                                endpoint=self.framework.status().endpoint,
                                created_at=datetime.now(UTC),
                            )
                        )
                        await session.flush()
                    session.add(
                        JobAssociation(
                            id=str(identifier),
                            target_id=str(data.target_id) if data.target_id else None,
                            remote_job_id=result.remote_job_id,
                            execution_id=result.execution_id,
                            framework_id=str(data.framework_id),
                            module_id=data.path,
                            status="launched",
                            created_at=datetime.now(UTC),
                        )
                    )
                    session.add(
                        ModuleRecent(
                            id=str(uuid4()), module_id=data.path, used_at=datetime.now(UTC)
                        )
                    )
                    await session.flush()
                    old = list(
                        await session.scalars(
                            select(ModuleRecent.id).order_by(ModuleRecent.used_at.desc()).offset(50)
                        )
                    )
                    if old:
                        await session.execute(delete(ModuleRecent).where(ModuleRecent.id.in_(old)))
                await self.events.publish(
                    "module-launch", result.model_dump(mode="json"), workspace_id=data.workspace_id
                )
                return result

        result = await self.mutations.execute_external(
            data.workspace_id, request_id, "module.run", data.model_dump(mode="json"), action
        )
        return ModuleLaunch.model_validate(result)
