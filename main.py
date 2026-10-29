"""CLI entry point for Network Security Scanner."""
import argparse
import json
from pathlib import Path
from scanner.core import DEFAULT_PORTS, parse_ports, scan
from scanner.reports import write_html, write_json


def main():
    parser = argparse.ArgumentParser(description='Scan TCP ports on one authorized IPv4 host')
    parser.add_argument('target', help='One authorized IPv4 address or hostname (try 127.0.0.1)')
    parser.add_argument('--ports', default=DEFAULT_PORTS, help='Comma-separated TCP ports/ranges, e.g. 22,80,443,8000-8010 (max 1024)')
    parser.add_argument('--timeout', type=float, default=0.5, help='Connection timeout in seconds (0.1–5)')
    parser.add_argument('--workers', type=int, default=32, help='Concurrent workers (1–64)')
    parser.add_argument('--output', default='reports', help='Report output directory')
    parser.add_argument('--allow-public', action='store_true', help='Permit scanning public IPs you are authorized to test')
    args = parser.parse_args()
    if not 0.1 <= args.timeout <= 5:
        parser.error('--timeout must be between 0.1 and 5 seconds')
    if not 1 <= args.workers <= 64:
        parser.error('--workers must be between 1 and 64')
    try:
        ports = parse_ports(args.ports)
        report = scan(args.target, ports, args.timeout, args.workers, args.allow_public)
        output = Path(args.output)
        output.mkdir(parents=True, exist_ok=True)
        write_json(report, output / 'scan-report.json')
        write_html(report, output / 'scan-report.html')
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))
    print(f'\nReports saved to: {output.resolve()}')


if __name__ == '__main__':
    main()
