"""Saved-file readers. No live capture, payload retention, or network activity."""
import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import math
from pathlib import Path
import re
import struct

from toolkit.tasks import Cancelled, TaskContext

MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_EVENTS = 250_000
LOG_LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "[^"\r\n]*" \d{3} (\d+|-)(?:\s.*)?$')
MONTHS = {name: index for index, name in enumerate(
    ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'), 1)}


@dataclass(frozen=True)
class TrafficEvent:
    timestamp: float
    source_ip: str
    bytes: int
    protocol: str


@dataclass
class TrafficData:
    events: list[TrafficEvent] = field(default_factory=list)
    unit: str = 'requests'
    warnings: list[str] = field(default_factory=list)
    skipped: int = 0
    complete: bool = True

    def bad(self, position, reason):
        self.skipped += 1
        self.complete = False
        if len(self.warnings) < 10:
            self.warnings.append(f'{position}: {reason}')


def parse_timestamp(value):
    text = str(value).strip()
    try:
        timestamp = float(text)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(text.replace('Z', '+00:00'))
        except ValueError as exc:
            raise ValueError('expected Unix seconds or a timezone-bearing ISO timestamp') from exc
        if parsed.tzinfo is None:
            raise ValueError('ISO timestamps must include a timezone')
        timestamp = parsed.timestamp()
    if not math.isfinite(timestamp):
        raise ValueError('timestamp must be finite')
    # Keep later UTC formatting within Python's supported datetime range.
    try:
        datetime.fromtimestamp(timestamp, timezone.utc)
    except (ValueError, OverflowError, OSError) as exc:
        raise ValueError('timestamp is outside the supported date range') from exc
    return timestamp


def _log_timestamp(text):
    # English log month names are independent of the computer's locale.
    match = re.fullmatch(r'(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})', text)
    if not match or match[2] not in MONTHS:
        raise ValueError('invalid access-log timestamp')
    day, month, year, hour, minute, second, zone = match.groups()
    iso = f'{year}-{MONTHS[month]:02d}-{day}T{hour}:{minute}:{second}{zone[:3]}:{zone[3:]}'
    return parse_timestamp(iso)


def _source(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError('source_ip must be a literal IPv4 or IPv6 address') from exc


def _bytes(value):
    try:
        count = int(value)
    except (ValueError, TypeError) as exc:
        raise ValueError('bytes must be a nonnegative integer') from exc
    if count < 0:
        raise ValueError('bytes must be a nonnegative integer')
    return count


def _text_rows(path, data, require_volume, task):
    with path.open('r', encoding='utf-8-sig', errors='strict', newline='') as source:
        if path.suffix.lower() == '.csv':
            reader = csv.DictReader(source)
            required = {'timestamp', 'source_ip'} | ({'bytes', 'protocol'} if require_volume else set())
            if not required.issubset(reader.fieldnames or []):
                raise ValueError('CSV requires columns: ' + ','.join(sorted(required)))
            for index, row in enumerate(reader, 2):
                task.check()
                try:
                    if None in row or any(row.get(key) is None for key in required):
                        raise ValueError('wrong number of CSV fields')
                    protocol = (row.get('protocol') or 'HTTP').strip().upper()
                    if not protocol or len(protocol) > 32 or not re.fullmatch(r'[A-Z0-9_./-]+', protocol):
                        raise ValueError('invalid protocol label')
                    event = TrafficEvent(parse_timestamp(row['timestamp']), _source(row['source_ip']),
                                         _bytes(row.get('bytes') or '0'), protocol)
                    data.events.append(event)
                except (ValueError, TypeError) as exc:
                    data.bad(f'Row {index}', str(exc))
                if index % 1000 == 0:
                    task.report(f'Reading CSV row {index}...')
                if len(data.events) >= MAX_EVENTS:
                    data.complete = False
                    data.warnings.append(f'Stopped at {MAX_EVENTS:,} events; remaining rows were not read.')
                    break
        else:
            for index, line in enumerate(source, 1):
                task.check()
                if not line.strip():
                    continue
                match = LOG_LINE.fullmatch(line.rstrip('\r\n'))
                try:
                    if not match:
                        raise ValueError('expected Common or Combined access-log format')
                    source_ip, timestamp, size = match.groups()
                    if size == '-' and require_volume:
                        raise ValueError('response byte count is unavailable; excluded from volume analysis')
                    data.events.append(TrafficEvent(_log_timestamp(timestamp), _source(source_ip),
                                                    _bytes('0' if size == '-' else size), 'HTTP'))
                except ValueError as exc:
                    data.bad(f'Line {index}', str(exc))
                if index % 1000 == 0:
                    task.report(f'Reading log line {index}...')
                if len(data.events) >= MAX_EVENTS:
                    data.complete = False
                    data.warnings.append(f'Stopped at {MAX_EVENTS:,} events; remaining lines were not read.')
                    break


def _validate_capture(source, task):
    """Validate record framing before Scapy's permissive EOF handling/allocation."""
    length = source.seek(0, 2)
    source.seek(0)
    magic = source.read(4)
    byte_orders = {b'\xd4\xc3\xb2\xa1': '<', b'\x4d\x3c\xb2\xa1': '<',
                   b'\xa1\xb2\xc3\xd4': '>', b'\xa1\xb2\x3c\x4d': '>'}
    if magic in byte_orders:
        endian = byte_orders[magic]
        if len(source.read(20)) != 20:
            raise ValueError('Malformed PCAP: incomplete file header.')
        while source.tell() < length:
            task.check()
            header = source.read(16)
            if len(header) != 16:
                raise ValueError('Malformed PCAP: incomplete packet header.')
            _, _, captured, wire = struct.unpack(endian + 'IIII', header)
            if captured > wire or captured > length - source.tell():
                raise ValueError('Malformed PCAP: truncated or invalid packet length.')
            source.seek(captured, 1)
    elif magic == b'\x0a\x0d\x0d\x0a':
        source.seek(0)
        endian = None
        while source.tell() < length:
            task.check()
            start = source.tell()
            header = source.read(12)
            if len(header) != 12:
                raise ValueError('Malformed PCAPNG: incomplete block header.')
            section = header[:4] == magic
            if section:
                endian = {b'\x4d\x3c\x2b\x1a': '<', b'\x1a\x2b\x3c\x4d': '>'}.get(header[8:12])
            if endian is None:
                raise ValueError('Malformed PCAPNG: invalid byte order.')
            block_length = struct.unpack(endian + 'I', header[4:8])[0]
            if block_length < (28 if section else 12) or block_length % 4 or block_length > length - start:
                raise ValueError('Malformed PCAPNG: truncated or invalid block length.')
            source.seek(start + block_length - 4)
            if struct.unpack(endian + 'I', source.read(4))[0] != block_length:
                raise ValueError('Malformed PCAPNG: block lengths disagree.')
    else:
        raise ValueError('Not a recognized PCAP or PCAPNG capture.')
    source.seek(0)


def _pcap_rows(path, data, task):
    from scapy.utils import PcapReader
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    data.unit = 'packets'
    ignored = 0
    try:
        # Owning the stream also closes it if PcapReader construction fails.
        with path.open('rb') as source:
            _validate_capture(source, task)
            reader = PcapReader(source)
            for index, packet in enumerate(reader, 1):
                task.check()
                if IP in packet:
                    source_ip = packet[IP].src
                    fallback = str(packet[IP].proto)
                elif IPv6 in packet:
                    source_ip = packet[IPv6].src
                    fallback = str(packet[IPv6].nh)
                else:
                    ignored += 1
                    continue
                protocol = 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'ICMP' if ICMP in packet else 'IP-' + fallback
                data.events.append(TrafficEvent(parse_timestamp(packet.time), _source(source_ip),
                                                getattr(packet, 'wirelen', None) or len(bytes(packet)), protocol))
                if index % 1000 == 0:
                    task.report(f'Reading packet {index}...')
                if len(data.events) >= MAX_EVENTS:
                    data.complete = False
                    data.warnings.append(f'Stopped at {MAX_EVENTS:,} IP packets; capture is incomplete.')
                    break
    except Cancelled:
        raise
    except Exception as exc:
        if not data.events:
            raise ValueError('Cannot read this capture. Use an intact PCAP or PCAPNG file. ' + str(exc)) from exc
        data.bad('Capture', 'reading stopped because the capture is malformed: ' + str(exc))
    if ignored:
        data.warnings.append(f'{ignored:,} non-IP packets excluded. Only IP traffic is analyzed.')


def read_traffic(filename, require_volume=False, task=None):
    task = task or TaskContext()
    task.check()
    path = Path(filename)
    if not path.is_file():
        raise ValueError('Choose a readable local file.')
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError('Input exceeds the 25 MiB limit. Split the saved file before analysis.')
    data = TrafficData()
    if path.suffix.lower() in ('.pcap', '.pcapng'):
        _pcap_rows(path, data, task)
    else:
        try:
            _text_rows(path, data, require_volume, task)
        except UnicodeError as exc:
            raise ValueError('Text logs must use UTF-8; use a .pcap/.pcapng extension for captures.') from exc
    if not data.events:
        detail = '; '.join(data.warnings[:3])
        raise ValueError('No valid events were found. ' + detail)
    data.events.sort(key=lambda event: event.timestamp)
    task.check()
    return data


def utc_label(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def input_summary(data):
    state = 'Complete input' if data.complete else 'INCOMPLETE analysis'
    return f'{state}: {len(data.events):,} {data.unit}; {data.skipped:,} malformed/unusable records skipped.' + (
        '\n' + '\n'.join(data.warnings) if data.warnings else '')
