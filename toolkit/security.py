from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_interface, ip_network
from urllib.parse import urljoin, urlsplit, urlunsplit


PRIVATE_V4 = tuple(ip_network(value) for value in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
LOOPBACK_V4 = ip_network('127.0.0.0/8')
PRIVATE_V6 = ip_network('fc00::/7')


def is_private_v4(address):
    return isinstance(address, IPv4Address) and any(address in network for network in PRIVATE_V4)


@dataclass(frozen=True)
class WebTarget:
    scheme: str
    host: str
    ip: str
    port: int
    path: str
    query: str

    @property
    def origin(self):
        return self.scheme, self.host, self.port

    @property
    def authority(self):
        host = '[' + self.host + ']' if ':' in self.host else self.host
        default = 443 if self.scheme == 'https' else 80
        return host if self.port == default else f'{host}:{self.port}'

    @property
    def url(self):
        return urlunsplit((self.scheme, self.authority, self.path, self.query, ''))


def validate_url(value: str) -> WebTarget:
    if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value) or '\\' in value:
        raise ValueError('Invalid URL: control characters and backslashes are not accepted.')
    parsed = urlsplit(value.strip())
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('Use an http:// or https:// URL with a local address.')
    if parsed.username is not None or parsed.password is not None:
        raise ValueError('Credentials in URLs are not accepted.')
    host = parsed.hostname.lower()
    if host == 'localhost':
        # Do not resolve a name and then let the HTTP library resolve it a second time.
        address = ip_address('127.0.0.1')
    else:
        if '%' in host:
            raise ValueError('Scoped or percent-encoded addresses are not accepted.')
        try:
            address = ip_address(host)
        except ValueError as exc:
            raise ValueError('Use localhost or a literal private IP address; other hostnames are blocked.') from exc
        if str(address) != host:
            host = str(address)
    allowed = (is_private_v4(address) or
               (isinstance(address, IPv4Address) and address in LOOPBACK_V4) or
               (address.version == 6 and (str(address) == '::1' or address in PRIVATE_V6)))
    if not allowed:
        raise ValueError('Target blocked: only private and loopback addresses are allowed.')
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == 'https' else 80)
    if not 1 <= port <= 65535:
        raise ValueError('Port must be between 1 and 65535.')
    return WebTarget(parsed.scheme, host, str(address), port, parsed.path or '/', parsed.query)


def validate_form_action(base: WebTarget, action: str) -> WebTarget:
    target = validate_url(urljoin(base.url, action))
    if target.origin != base.origin:
        raise ValueError('Form blocked: its action must stay on the original scheme, host, and port.')
    return target


def validate_subnet(value: str, interface_ip: str, netmask: str) -> IPv4Network:
    network = ip_network(value.strip(), strict=True)
    interface = ip_interface(f'{interface_ip}/{netmask}')
    if not isinstance(network, IPv4Network) or not is_private_v4(interface.ip):
        raise ValueError('Select an interface with an RFC1918 IPv4 address.')
    if not any(network.subnet_of(private) for private in PRIVATE_V4):
        raise ValueError('Only RFC1918 IPv4 subnets can be scanned.')
    if not network.subnet_of(interface.network):
        raise ValueError('The subnet must be inside the selected interface network.')
    if network.num_addresses > 256:
        raise ValueError('Limit the subnet to 256 addresses or fewer (/24 or smaller).')
    return network
