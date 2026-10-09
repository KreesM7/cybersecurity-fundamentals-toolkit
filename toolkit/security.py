import re
import socket
import time
from collections.abc import Sequence
from dataclasses import dataclass, replace
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    ip_address,
    ip_interface,
    ip_network,
)
from queue import Empty, Queue
from threading import BoundedSemaphore, Thread
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from toolkit.task_context import TaskContext

PRIVATE_V4 = tuple(
    IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
UNSPECIFIED_V4 = ip_network("0.0.0.0/8")
DNS_SECONDS = 3
_dns_slots = BoundedSemaphore(2)


def is_private_v4(address: IPv4Address | IPv6Address) -> bool:
    return isinstance(address, IPv4Address) and any(address in network for network in PRIVATE_V4)


def is_target_address(address: IPv4Address | IPv6Address) -> bool:
    if address.version == 6 and address.ipv4_mapped is not None:
        return False
    if address.is_loopback:
        return True
    if isinstance(address, IPv4Address) and address in UNSPECIFIED_V4:
        return False
    return not (
        address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or address.is_reserved
    )


@dataclass(frozen=True)
class WebTarget:
    scheme: str
    host: str
    ip: str | None
    port: int
    path: str
    query: str

    @property
    def origin(self) -> tuple[str, str, int]:
        return self.scheme, self.host, self.port

    @property
    def authority(self) -> str:
        host = "[" + self.host + "]" if ":" in self.host else self.host
        default = 443 if self.scheme == "https" else 80
        return host if self.port == default else f"{host}:{self.port}"

    @property
    def url(self) -> str:
        return urlunsplit((self.scheme, self.authority, self.path, self.query, ""))


def validate_url(value: str) -> WebTarget:
    if (
        not isinstance(value, str)
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
        or "\\" in value
    ):
        raise ValueError("Invalid URL: control characters and backslashes are not accepted.")
    parsed = urlsplit(value.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Use an http:// or https:// URL with an IP address or hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials in URLs are not accepted.")
    host = parsed.hostname.lower()
    address = None
    if host == "localhost":
        # Do not resolve a name and then let the HTTP library resolve it a second time.
        address = ip_address("127.0.0.1")
    else:
        if "%" in host:
            raise ValueError("Scoped or percent-encoded addresses are not accepted.")
        try:
            address = ip_address(host)
        except ValueError as exc:
            # Never let a resolver reinterpret legacy decimal/octal/hex IP forms.
            if ":" in host:
                raise ValueError("Use a standard IP address or a valid hostname.") from exc
            try:
                host = host.encode("idna").decode("ascii").removesuffix(".")
            except UnicodeError as exc:
                raise ValueError("Invalid hostname.") from exc
            if re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*", host):
                raise ValueError("Use a standard IP address or a valid hostname.")
            labels = host.split(".")
            if len(host) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
            ):
                raise ValueError("Invalid hostname.")
            if host == "localhost":
                address = ip_address("127.0.0.1")
        if address is not None and str(address) != host and host != "localhost":
            host = str(address)
    if address is not None and not is_target_address(address):
        raise ValueError("Unsupported address: use an ordinary unicast or loopback target.")
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    return WebTarget(
        parsed.scheme,
        host,
        str(address) if address is not None else None,
        port,
        parsed.path or "/",
        parsed.query,
    )


def resolve_web_target(target: WebTarget, task: TaskContext) -> WebTarget:
    if target.ip is not None:
        return target
    task.check()
    if not _dns_slots.acquire(blocking=False):
        raise ValueError("DNS resolver is still busy. Wait briefly before retrying.")
    # getaddrinfo exposes platform-dependent socket address tuples.
    result: Queue[tuple[Sequence[tuple[int, int, int, str, Any]] | None, Exception | None]] = Queue(
        maxsize=1
    )

    def lookup() -> None:
        try:
            try:
                answers = socket.getaddrinfo(target.host, target.port, type=socket.SOCK_STREAM)
                result.put((answers, None))
            except Exception as exc:
                result.put((None, exc))
        finally:
            _dns_slots.release()

    worker = Thread(target=lookup, daemon=True, name="toolkit-dns")
    try:
        worker.start()
    except Exception:
        _dns_slots.release()
        raise
    deadline = time.monotonic() + DNS_SECONDS
    while True:
        task.check()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("DNS resolution exceeded its time limit.")
        try:
            answers, error = result.get(timeout=min(0.05, remaining))
            break
        except Empty:
            continue
    task.check()
    if error is not None:
        raise ValueError("DNS resolution failed: " + str(error)) from error
    if answers is None:
        raise ValueError("DNS returned no result.")
    addresses = []
    for family, _, _, _, sockaddr in answers:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        address = ip_address(sockaddr[0])
        if "%" in sockaddr[0] or not is_target_address(address):
            raise ValueError("DNS returned an unsupported address.")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError("DNS did not return a usable IPv4 or IPv6 address.")
    addresses.sort(key=lambda address: address.version)
    return replace(target, ip=str(addresses[0]))


def validate_form_action(base: WebTarget, action: str) -> WebTarget:
    target = validate_url(urljoin(base.url, action))
    if target.origin != base.origin:
        raise ValueError(
            "Form blocked: its action must stay on the original scheme, host, and port."
        )
    return target


def validate_subnet(
    value: str, interface_ip: str | None = None, netmask: str | None = None
) -> IPv4Network:
    network = ip_network(value.strip(), strict=True)
    if not isinstance(network, IPv4Network):
        raise ValueError("The network scanner supports IPv4 targets only.")
    if network.num_addresses > 256:
        raise ValueError("Limit the subnet to 256 addresses or fewer (/24 or smaller).")
    if not all(
        is_target_address(address)
        for address in (network.network_address, network.broadcast_address)
    ):
        raise ValueError("Unsupported subnet: use an ordinary unicast or loopback IPv4 target.")
    if interface_ip is None and netmask is None:
        return network
    if interface_ip is None or netmask is None:
        raise ValueError("Provide both an interface address and its netmask.")
    interface = ip_interface(f"{interface_ip}/{netmask}")
    if not isinstance(interface, IPv4Interface) or not is_private_v4(interface.ip):
        raise ValueError("Select an interface with an RFC1918 IPv4 address.")
    if not any(network.subnet_of(private) for private in PRIVATE_V4):
        raise ValueError("Only RFC1918 IPv4 subnets can be scanned.")
    if not network.subnet_of(interface.network):
        raise ValueError("The subnet must be inside the selected interface network.")
    return network
