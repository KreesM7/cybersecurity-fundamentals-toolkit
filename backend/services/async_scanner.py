"""Sequential bounded native Nmap TCP-connect scans."""

from dataclasses import asdict
from importlib import import_module
from typing import Any, cast

from backend.jobs import JobContext
from backend.platform_utils import run_process
from shared.tools import ScannerOptions
from toolkit.modules.network_scanner import (
    COMMON_PORTS,
    NetworkInterface,
    list_interfaces,
    nmap_path,
)
from toolkit.security import validate_subnet


def validate_scan(options: ScannerOptions) -> None:
    if not options.authorized:
        raise ValueError("Confirm ownership or permission to scan the target.")
    interface = options.interface
    if interface is not None:
        selected = NetworkInterface(interface.name, interface.ip, interface.netmask)
        if selected not in list_interfaces():
            raise ValueError("Selected interface changed or is unavailable. Refresh interfaces.")
        validate_subnet(options.target, interface.ip, interface.netmask)
    else:
        validate_subnet(options.target)


async def scan(options: ScannerOptions, context: JobContext) -> object:
    validate_scan(options)
    executable = nmap_path()
    network = validate_subnet(options.target)
    # python-nmap is used only for its XML analyzer, never its process constructor.
    nmap: Any = import_module("nmap")
    analyzer = nmap.PortScanner.__new__(nmap.PortScanner)
    addresses = list(network.hosts())
    results: list[dict[str, object]] = []
    for index, address in enumerate(addresses):
        context.check()
        validate_scan(options)
        await context.progress(f"Scanning {address} ({index + 1}/{len(addresses)})")
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
            process = await run_process(args, timeout=8, max_output_bytes=1048576)
        except TimeoutError:
            results.append(
                {"ip": str(address), "status": "Inconclusive: timeout", "open_ports": []}
            )
            continue
        if process.returncode:
            raise ValueError("Nmap failed. Check native Nmap readiness and target routing.")
        reply = cast(
            dict[str, Any],
            await context.run_sync(lambda: analyzer.analyse_nmap_xml_scan(process.stdout)),
        )
        from toolkit.modules.network_scanner import interpret_host

        results.append(asdict(interpret_host(str(address), reply)))
    return results
