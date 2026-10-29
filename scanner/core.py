"""Small, dependency-free TCP connect scanner for authorized targets."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import ipaddress
import socket
import time

COMMON_PORTS = {21:'FTP',22:'SSH',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',143:'IMAP',443:'HTTPS',445:'SMB',587:'SMTP Submission',993:'IMAPS',995:'POP3S',1433:'MSSQL',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',6379:'Redis',8080:'HTTP Alternate',8443:'HTTPS Alternate'}
DEFAULT_PORTS = '21,22,25,53,80,110,143,443,445,587,993,995,1433,3306,3389,5432,6379,8080,8443'


def parse_ports(spec):
    """Parse comma-separated ports and ranges, with a maximum of 1024 unique ports."""
    result = set()
    for segment in spec.split(','):
        segment = segment.strip()
        if not segment:
            raise ValueError('Empty port entry')
        pieces = segment.split('-')
        if len(pieces) == 1:
            start = end = int(pieces[0])
        elif len(pieces) == 2:
            start, end = map(int, pieces)
        else:
            raise ValueError(f'Invalid port range: {segment}')
        if not (1 <= start <= end <= 65535):
            raise ValueError(f'Invalid port or range: {segment}')
        if end - start > 1023:
            raise ValueError('Select at most 1024 ports per scan')
        result.update(range(start, end + 1))
        if len(result) > 1024:
            raise ValueError('Select at most 1024 ports per scan')
    return sorted(result)


def resolve_target(target, allow_public=False):
    """Resolve a single IPv4 target; public addresses require explicit opt-in."""
    records = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
    addresses = sorted({entry[4][0] for entry in records})
    if len(addresses) != 1:
        raise ValueError('Target must resolve to exactly one IPv4 address; use an IP address instead')
    address = ipaddress.ip_address(addresses[0])
    if address.is_multicast or address.is_unspecified or address.is_reserved:
        raise ValueError('Unsupported target address')
    if not allow_public and not (address.is_private or address.is_loopback or address.is_link_local):
        raise ValueError('Public targets are blocked by default; use --allow-public only with authorization')
    return str(address)


def scan_port(address, port, timeout):
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return {'port': port, 'service': COMMON_PORTS.get(port, 'Unknown'), 'status': 'open'}
    except (OSError, TimeoutError):
        return None


def scan(target, ports, timeout=0.5, workers=32, allow_public=False):
    address = resolve_target(target, allow_public=allow_public)
    started = time.monotonic()
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(scan_port, address, port, timeout) for port in ports]
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    return {
        'target': target, 'resolved_ip': address,
        'scanned_at_utc': datetime.now(timezone.utc).isoformat(),
        'ports_checked': len(ports), 'open_ports': sorted(open_ports, key=lambda p: p['port']),
        'duration_seconds': round(time.monotonic() - started, 2),
        'notes': 'TCP connect results only. Service names are inferred from port numbers, not verified. An open port is not proof of a vulnerability.'
    }
