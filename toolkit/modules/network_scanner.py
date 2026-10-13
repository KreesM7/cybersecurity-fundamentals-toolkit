from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget

    from frontend.viewmodels.tools_vm import ToolsViewModel

import socket
import subprocess
from dataclasses import dataclass
from importlib import import_module
from ipaddress import ip_interface
from typing import Any

from toolkit.core import ModuleSpec
from toolkit.security import is_private_v4, validate_subnet
from toolkit.task_context import TaskContext

COMMON_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5432,5900,8080,8443"


@dataclass(frozen=True)
class NetworkInterface:
    name: str
    ip: str
    netmask: str


@dataclass
class HostResult:
    ip: str
    status: str
    open_ports: list[str]


def list_interfaces() -> list[NetworkInterface]:
    import psutil

    stats = psutil.net_if_stats()
    interfaces = []
    for name, addresses in psutil.net_if_addrs().items():
        if name not in stats or not stats[name].isup:
            continue
        for address in addresses:
            if address.family == socket.AF_INET and address.netmask:
                try:
                    interface = ip_interface(f"{address.address}/{address.netmask}")
                    if is_private_v4(interface.ip):
                        interfaces.append(NetworkInterface(name, address.address, address.netmask))
                except ValueError:
                    continue
    return interfaces


def nmap_path() -> str:
    from backend.platform_utils import find_nmap_binary

    try:
        found = find_nmap_binary()
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    if found is None:
        raise RuntimeError("Install Nmap, then add it to PATH or set TOOLKIT_NMAP to nmap.exe.")
    return str(found)


def readiness() -> str:
    try:
        import_module("nmap")
        import_module("psutil")

        nmap_path()
        return ""
    except (ImportError, RuntimeError) as exc:
        return "Setup needed: " + str(exc)


def interpret_host(ip: str, response: dict[str, Any]) -> HostResult:
    host = response.get("scan", {}).get(ip, {})
    tcp = host.get("tcp", {})
    ports = [
        f'{port}/tcp ({data.get("name", "unknown")})'
        for port, data in sorted(tcp.items())
        if data.get("state") == "open"
    ]
    responded = any(data.get("state") in ("open", "closed") for data in tcp.values())
    return HostResult(ip, "Responded" if responded else "Inconclusive", ports)


def scan_subnet(
    subnet: str,
    interface: NetworkInterface | None = None,
    task: TaskContext | None = None,
    *,
    authorized: bool = False,
) -> list[HostResult]:

    task = task or TaskContext()
    if interface is not None and interface not in list_interfaces():
        raise ValueError(
            "Selected interface changed or is unavailable. Refresh the interface list."
        )
    network = (
        validate_subnet(subnet, interface.ip, interface.netmask)
        if interface is not None
        else validate_subnet(subnet)
    )
    task.check()
    import nmap  # type: ignore[import-untyped]

    executable = nmap_path()
    # Use python-nmap's XML analysis API without its constructor/scan subprocesses,
    # which open console windows on Windows and do not bound version discovery.
    scanner = nmap.PortScanner.__new__(nmap.PortScanner)
    addresses = list(network.hosts())
    results = []
    # One host at a time makes cancellation bounded without killing unrelated processes.
    for index, address in enumerate(addresses):
        task.check()
        if interface is not None and interface not in list_interfaces():
            raise ValueError("Selected interface changed during the scan; results were discarded.")
        task.report(f"Scanning {address} ({index + 1}/{len(addresses)})")
        args = [
            executable,
            "-oX",
            "-",
            str(address),
            "-p",
            COMMON_PORTS,
            "-sT",
            "-Pn",
            "-n",
            "--max-retries",
            "1",
            "--host-timeout",
            "5s",
            "--max-rate",
            "100",
        ]
        try:
            process = subprocess.run(
                args,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=8,
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired:
            results.append(HostResult(str(address), "Inconclusive: timeout", []))
            continue
        if process.returncode:
            raise RuntimeError(
                "Nmap failed: " + process.stderr.decode("utf-8", errors="replace")[:1000]
            )
        task.check()
        reply = scanner.analyse_nmap_xml_scan(process.stdout)
        results.append(interpret_host(str(address), reply))
    task.check()
    return results


def create_panel(context: ToolsViewModel) -> QWidget:
    from frontend.views.tools import create_panel as factory

    return factory(MODULE.id, context)


MODULE = ModuleSpec("network-scanner", "Network Scanner", 30, create_panel)
