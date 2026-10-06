from dataclasses import dataclass
from ipaddress import ip_interface, ip_network
from pathlib import Path
import os
import shutil
import socket

from toolkit.core import ModuleSpec
from toolkit.security import is_private_v4, validate_subnet


COMMON_PORTS = '21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5432,5900,8080,8443'


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


def list_interfaces():
    import psutil
    stats = psutil.net_if_stats()
    interfaces = []
    for name, addresses in psutil.net_if_addrs().items():
        if name not in stats or not stats[name].isup:
            continue
        for address in addresses:
            if address.family == socket.AF_INET and address.netmask:
                try:
                    interface = ip_interface(f'{address.address}/{address.netmask}')
                    if is_private_v4(interface.ip):
                        interfaces.append(NetworkInterface(name, address.address, address.netmask))
                except ValueError:
                    continue
    return interfaces


def nmap_path():
    explicit = os.environ.get('TOOLKIT_NMAP')
    if explicit:
        if Path(explicit).is_file():
            return str(Path(explicit).resolve())
        raise RuntimeError('TOOLKIT_NMAP does not point to an existing nmap.exe.')
    found = shutil.which('nmap')
    if found:
        return found
    for variable in ('ProgramFiles', 'ProgramFiles(x86)'):
        path = Path(os.environ.get(variable, 'C:/Program Files')) / 'Nmap' / 'nmap.exe'
        if path.is_file():
            return str(path)
    raise RuntimeError('Install Nmap, then add it to PATH or set TOOLKIT_NMAP to nmap.exe.')


def readiness():
    try:
        import nmap
        import psutil
        nmap_path()
        return '' if list_interfaces() else 'No active RFC1918 IPv4 interface found.'
    except (ImportError, RuntimeError) as exc:
        return 'Setup needed: ' + str(exc)


def interpret_host(ip, response):
    host = response.get('scan', {}).get(ip, {})
    tcp = host.get('tcp', {})
    ports = [f'{port}/tcp ({data.get("name", "unknown")})'
             for port, data in sorted(tcp.items()) if data.get('state') == 'open']
    responded = any(data.get('state') in ('open', 'closed') for data in tcp.values())
    return HostResult(ip, 'Responded' if responded else 'Inconclusive', ports)


def scan_subnet(subnet, interface, task=None):
    from toolkit.tasks import TaskContext
    task = task or TaskContext()
    if interface not in list_interfaces():
        raise ValueError('Selected interface changed or is unavailable. Refresh the interface list.')
    network = validate_subnet(subnet, interface.ip, interface.netmask)
    task.check()
    import nmap
    scanner = nmap.PortScanner(nmap_search_path=(nmap_path(),))
    addresses = list(network.hosts())
    results = []
    # One host at a time makes cancellation bounded without killing unrelated processes.
    for index, address in enumerate(addresses):
        task.check()
        task.report(f'Scanning {address} ({index + 1}/{len(addresses)})')
        reply = scanner.scan(str(address), COMMON_PORTS,
                             arguments='-sT -Pn -n --max-retries 1 --host-timeout 5s --max-rate 100',
                             timeout=8)
        results.append(interpret_host(str(address), reply))
    task.check()
    return results


def create_panel(context):
    from PySide6.QtWidgets import QComboBox, QFormLayout, QLineEdit, QPushButton
    from toolkit.widgets import TaskPanel, fill_table, make_table, technical_font

    panel = TaskPanel(context, 'Local Network Scanner',
                      'TCP connect scans on the selected interface. Maximum 256 addresses. '
                      'Only scan a network you own or administer. A filtered result cannot establish host presence.')
    form = QFormLayout()
    adapters = QComboBox()
    subnet = QLineEdit()
    subnet.setFont(technical_font())
    refresh = QPushButton('Refresh interfaces')
    form.addRow('Interface', adapters)
    form.addRow('Subnet', subnet)
    form.addRow('', refresh)
    panel.layout.addLayout(form)
    table = make_table(['IP', 'Response', 'Open common ports'])
    panel.layout.addWidget(table)
    panel.run_button.setText('Scan subnet')
    panel.add_footer()

    def choose(index):
        interface = adapters.itemData(index)
        if interface:
            parent = ip_interface(f'{interface.ip}/{interface.netmask}').network
            prefix = max(24, parent.prefixlen)
            subnet.setText(str(ip_network(f'{interface.ip}/{prefix}', strict=False)))

    def reload():
        adapters.clear()
        try:
            for interface in list_interfaces():
                adapters.addItem(f'{interface.name}: {interface.ip}', interface)
            choose(adapters.currentIndex())
            panel.status.setText(readiness() or 'Ready. Some hosts may take up to 8 seconds each.')
        except Exception as exc:
            panel.status.setText(str(exc))

    def done(results):
        fill_table(table, ((r.ip, r.status, ', '.join(r.open_ports) or '-') for r in results))
        responded = sum(r.status == 'Responded' for r in results)
        panel.status.setText(f'{responded} responding hosts; {len(results) - responded} inconclusive. '
                             'Only the listed common TCP ports were tested.')

    def run():
        interface, target = adapters.currentData(), subnet.text()
        if interface is None:
            panel.status.setText('Select an active private interface first.')
            return
        table.setRowCount(0)
        panel.start(lambda task: scan_subnet(target, interface, task), done)

    adapters.currentIndexChanged.connect(choose)
    refresh.clicked.connect(reload)
    panel.run_button.clicked.connect(run)
    reload()
    return panel


MODULE = ModuleSpec('network-scanner', 'Local Network Scanner', 30, create_panel)
