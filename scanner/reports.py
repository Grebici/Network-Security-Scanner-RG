"""Report generators. All external values are HTML-escaped."""
import html
import json
from pathlib import Path


def write_json(report, path):
    Path(path).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')


def write_html(report, path):
    rows = '\n'.join(
        f'<tr><td>{int(item["port"])}</td><td>{html.escape(item["service"])}</td><td>Open</td></tr>'
        for item in report['open_ports']
    ) or '<tr><td colspan="3">No open ports detected among those checked</td></tr>'
    target = html.escape(str(report['target']))
    ip = html.escape(str(report['resolved_ip']))
    timestamp = html.escape(str(report['scanned_at_utc']))
    notes = html.escape(str(report['notes']))
    document = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Security Scan Report</title><style>
body{{font-family:system-ui,Arial,sans-serif;background:#0b1220;color:#e5edf7;max-width:860px;margin:40px auto;padding:0 20px}}
h1{{color:#7dd3fc}}.card{{background:#172337;border:1px solid #31425b;border-radius:14px;padding:22px;margin:18px 0}}
table{{border-collapse:collapse;width:100%}}th,td{{padding:12px;text-align:left;border-bottom:1px solid #31425b}}th{{color:#93c5fd}}
small{{color:#b8c5d6}}
</style></head><body><h1>🛡️ Network Security Scan</h1>
<div class="card"><p><b>Target:</b> {target}</p><p><b>Resolved IP:</b> {ip}</p><p><b>UTC time:</b> {timestamp}</p>
<p><b>Ports checked:</b> {int(report['ports_checked'])}</p><p><b>Open ports:</b> {len(report['open_ports'])}</p></div>
<div class="card"><h2>Open TCP Ports</h2><table><thead><tr><th>Port</th><th>Likely service</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table></div>
<small>{notes}</small></body></html>'''
    Path(path).write_text(document, encoding='utf-8')
