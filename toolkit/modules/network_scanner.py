from dataclasses import dataclass
from ipaddress import ip_interface, ip_network
from pathlib import Path
import os
import shutil
import socket
import subprocess

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
        return ''
    except (ImportError, RuntimeError) as exc:
        return 'Setup needed: ' + str(exc)


def interpret_host(ip, response):
    host = response.get('scan', {}).get(ip, {})
    tcp = host.get('tcp', {})
    ports = [f'{port}/tcp ({data.get("name", "unknown")})'
             for port, data in sorted(tcp.items()) if data.get('state') == 'open']
    responded = any(data.get('state') in ('open', 'closed') for data in tcp.values())
    return HostResult(ip, 'Responded' if responded else 'Inconclusive', ports)


def scan_subnet(subnet, interface=None, task=None, *, authorized=False):
    from toolkit.tasks import TaskContext
    task = task or TaskContext()
    if not authorized:
        raise ValueError('Confirm ownership or permission to scan the target.')
    if interface is not None and interface not in list_interfaces():
        raise ValueError('Selected interface changed or is unavailable. Refresh the interface list.')
    network = validate_subnet(subnet, interface.ip, interface.netmask) if interface is not None else validate_subnet(subnet)
    task.check()
    import nmap
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
            raise ValueError('Selected interface changed during the scan; results were discarded.')
        task.report(f'Scanning {address} ({index + 1}/{len(addresses)})')
        args = [executable, '-oX', '-', str(address), '-p', COMMON_PORTS,
                '-sT', '-Pn', '-n', '--max-retries', '1', '--host-timeout', '5s', '--max-rate', '100']
        try:
            process = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, timeout=8, shell=False,
                                     creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except subprocess.TimeoutExpired:
            results.append(HostResult(str(address), 'Inconclusive: timeout', []))
            continue
        if process.returncode:
            raise RuntimeError('Nmap failed: ' + process.stderr.decode('utf-8', errors='replace')[:1000])
        task.check()
        reply = scanner.analyse_nmap_xml_scan(process.stdout)
        results.append(interpret_host(str(address), reply))
    task.check()
    return results


def create_panel(context):
    from PySide6.QtWidgets import QCheckBox, QComboBox, QFormLayout, QLineEdit, QPushButton
    from toolkit.widgets import TaskPanel, fill_table, make_table, technical_font

    panel = TaskPanel(context, 'Network Scanner',
                      'Local or public IPv4 TCP connect scans. Maximum 256 addresses. '
                      'Only scan targets you own or have permission to assess. '
                      'A filtered result cannot establish host presence.')
    form = QFormLayout()
    adapters = QComboBox()
    subnet = QLineEdit()
    subnet.setPlaceholderText('Your authorized IPv4 address or CIDR')
    subnet.setFont(technical_font())
    refresh = QPushButton('Refresh interfaces')
    form.addRow('Target routing', adapters)
    form.addRow('IPv4 address / subnet', subnet)
    form.addRow('', refresh)
    panel.layout.addLayout(form)
    owned = QCheckBox('I own this target or have permission to scan it')
    panel.layout.addWidget(owned)
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
        adapters.addItem('Entered target (system routing)', None)
        try:
            for interface in list_interfaces():
                adapters.addItem(f'Local subnet — {interface.name}: {interface.ip}', interface)
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
        if not owned.isChecked():
            panel.status.setText('Confirm ownership or permission before scanning.')
            return
        table.setRowCount(0)
        permitted = owned.isChecked()
        panel.start(lambda task: scan_subnet(target, interface, task, authorized=permitted), done)

    adapters.currentIndexChanged.connect(choose)
    subnet.textChanged.connect(lambda _text: owned.setChecked(False))
    refresh.clicked.connect(reload)
    panel.run_button.clicked.connect(run)
    reload()
    return panel


MODULE = ModuleSpec('network-scanner', 'Network Scanner', 30, create_panel)
