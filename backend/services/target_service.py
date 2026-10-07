"""Workspace-local targets, bounded atomic imports and secret-free escaped exports."""

from __future__ import annotations

import builtins
import csv
import io
import json
from datetime import UTC, datetime
from ipaddress import IPv4Network
from uuid import UUID, uuid4
from xml.etree import ElementTree as ET

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from backend.models import Target
from backend.services.workspace_service import (
    WorkspaceConflictError,
    WorkspaceNotFoundError,
    WorkspaceService,
)
from shared.workspaces import (
    OpenPort,
    TargetBulk,
    TargetCreate,
    TargetStatus,
    TargetUpdate,
    TargetView,
)

MAX_XML_BYTES = 25 * 1024 * 1024
MAX_IMPORT_TARGETS = 4096


class TargetService:
    """Each operation uses a captured workspace UUID and its leased session factory."""

    def __init__(self, workspaces: WorkspaceService, workspace_id: UUID) -> None:
        self.workspaces = workspaces
        self.workspace_id = workspace_id

    def _view(self, row: Target) -> TargetView:
        return TargetView(
            id=UUID(row.id),
            workspace_id=self.workspace_id,
            address=TargetCreate.ordinary_ipv4(row.address),
            hostname=row.hostname,
            ports=[OpenPort.model_validate(port) for port in row.ports],
            status=TargetStatus(row.status),
            notes=row.notes,
            created_at=row.created_at.replace(tzinfo=UTC),
            updated_at=row.updated_at.replace(tzinfo=UTC),
        )

    @staticmethod
    def _row(data: TargetCreate) -> Target:
        now = datetime.now(UTC)
        return Target(
            id=str(uuid4()),
            address=str(data.address),
            hostname=data.hostname,
            ports=[port.model_dump(mode="json") for port in data.ports],
            status=data.status.value,
            notes=data.notes,
            created_at=now,
            updated_at=now,
        )

    async def list(
        self, status: TargetStatus | None = None, query: str = ""
    ) -> builtins.list[TargetView]:
        async with await self.workspaces.lease(self.workspace_id) as lease:
            async with lease.sessions() as session:
                statement = select(Target).order_by(Target.address, Target.id)
                if status is not None:
                    statement = statement.where(Target.status == status.value)
                if query:
                    statement = statement.where(
                        Target.address.contains(query, autoescape=True)
                        | Target.hostname.contains(query, autoescape=True)
                    )
                return [self._view(row) for row in (await session.scalars(statement)).all()]

    async def get(self, identifier: UUID) -> TargetView:
        async with await self.workspaces.lease(self.workspace_id) as lease:
            async with lease.sessions() as session:
                row = await session.get(Target, str(identifier))
                if row is None:
                    raise WorkspaceNotFoundError("Target UUID does not exist in this workspace")
                return self._view(row)

    async def add_many(self, records: builtins.list[TargetCreate]) -> builtins.list[TargetView]:
        if not 1 <= len(records) <= MAX_IMPORT_TARGETS:
            raise ValueError("Import requires 1 to 4096 IPv4 targets")
        rows = [self._row(record) for record in records]
        async with await self.workspaces.lease(self.workspace_id) as lease:
            try:
                async with lease.sessions.begin() as session:
                    session.add_all(rows)
                    await session.flush()
                return [self._view(row) for row in rows]
            except IntegrityError as exc:
                raise WorkspaceConflictError(
                    "An IPv4 target already exists; the entire import was rolled back"
                ) from exc

    async def create(self, data: TargetCreate) -> TargetView:
        return (await self.add_many([data]))[0]

    async def update(self, identifier: UUID, data: TargetUpdate) -> TargetView:
        async with await self.workspaces.lease(self.workspace_id) as lease:
            try:
                async with lease.sessions.begin() as session:
                    row = await session.get(Target, str(identifier))
                    if row is None:
                        raise WorkspaceNotFoundError("Target UUID does not exist in this workspace")
                    for key, value in data.model_dump(mode="json", exclude_unset=True).items():
                        setattr(row, key, value)
                    row.updated_at = datetime.now(UTC)
                    await session.flush()
                return self._view(row)
            except IntegrityError as exc:
                raise WorkspaceConflictError("An IPv4 target already exists") from exc

    async def delete(self, identifier: UUID) -> None:
        async with await self.workspaces.lease(self.workspace_id) as lease:
            async with lease.sessions.begin() as session:
                row = await session.get(Target, str(identifier))
                if row is None:
                    raise WorkspaceNotFoundError("Target UUID does not exist in this workspace")
                await session.delete(row)

    async def bulk(self, data: TargetBulk) -> builtins.list[TargetView]:
        return await self.add_many(
            [TargetCreate(address=address) for address in IPv4Network(data.cidr).hosts()]
        )

    @staticmethod
    def parse_nmap(data: bytes) -> builtins.list[TargetCreate]:
        if len(data) > MAX_XML_BYTES:
            raise ValueError("Nmap XML exceeds 25 MiB")
        # Reject UTF-16/32 and every DTD/entity declaration before XML parsing. Nmap
        # emits UTF-8; accepting alternate encodings could bypass an ASCII guard.
        if b"\x00" in data or b"<!doctype" in data.lower() or b"<!entity" in data.lower():
            raise ValueError("Nmap XML DTD/entities and non-UTF-8 encodings are not accepted")
        try:
            text = data.decode("utf-8-sig")
            root = ET.fromstring(text)
        except (UnicodeError, ET.ParseError) as exc:
            raise ValueError("Malformed UTF-8 Nmap XML") from exc
        if root.tag != "nmaprun":
            raise ValueError("Expected an Nmap nmaprun document")
        hosts = root.findall("host")
        if not 1 <= len(hosts) <= MAX_IMPORT_TARGETS:
            raise ValueError("Nmap import requires 1 to 4096 IPv4 hosts")
        records = []
        for host in hosts:
            addresses = [
                element for element in host.findall("address") if element.get("addrtype") == "ipv4"
            ]
            if len(addresses) != 1:
                raise ValueError("Every Nmap host must contain exactly one IPv4 address")
            ports = []
            entries = host.findall("ports/port")
            if len(entries) > 1024:
                raise ValueError("A host exceeds 1024 port records")
            for entry in entries:
                state = entry.find("state")
                if state is None or state.get("state") is None:
                    raise ValueError("Nmap port is missing its state")
                service = entry.find("service")
                try:
                    port = OpenPort.model_validate(
                        {
                            "port": int(entry.attrib["portid"]),
                            "protocol": entry.attrib["protocol"],
                            "service": service.get("name", "") if service is not None else "",
                        }
                    )
                except (KeyError, ValueError) as exc:
                    raise ValueError("Malformed Nmap port record") from exc
                if state.get("state") == "open":
                    ports.append(port)
            hostname = host.find("hostnames/hostname")
            records.append(
                TargetCreate(
                    address=TargetCreate.ordinary_ipv4(addresses[0].get("addr")),
                    hostname=hostname.get("name", "") if hostname is not None else "",
                    ports=ports,
                    status=TargetStatus.OPEN if ports else TargetStatus.NOT_SCANNED,
                )
            )
        return records

    async def import_nmap(self, data: bytes) -> builtins.list[TargetView]:
        return await self.add_many(self.parse_nmap(data))

    async def export(self, format: str) -> tuple[str, str]:
        rows = await self.list()
        if format == "json":
            return json.dumps([row.model_dump(mode="json") for row in rows]), "application/json"
        if format == "csv":
            output = io.StringIO(newline="")
            writer = csv.writer(output)
            writer.writerow(("address", "hostname", "status", "notes", "ports"))
            for row in rows:
                values = [
                    str(row.address),
                    row.hostname,
                    row.status.value,
                    row.notes,
                    json.dumps([port.model_dump(mode="json") for port in row.ports]),
                ]
                # Escaping formulas keeps a CSV opened in spreadsheet software inert.
                writer.writerow(
                    [
                        "'" + value if value.startswith(("=", "+", "-", "@", "\t", "\r")) else value
                        for value in values
                    ]
                )
            return output.getvalue(), "text/csv"
        if format == "nmap":
            root = ET.Element("nmaprun")
            for row in rows:
                host = ET.SubElement(root, "host")
                ET.SubElement(host, "address", addr=str(row.address), addrtype="ipv4")
                if row.hostname:
                    ET.SubElement(ET.SubElement(host, "hostnames"), "hostname", name=row.hostname)
                ports = ET.SubElement(host, "ports")
                for record in row.ports:
                    port = ET.SubElement(
                        ports, "port", protocol=record.protocol, portid=str(record.port)
                    )
                    ET.SubElement(port, "state", state="open")
                    ET.SubElement(port, "service", name=record.service)
            return ET.tostring(root, encoding="unicode"), "application/xml"
        raise ValueError("Export format must be json, csv or nmap")
