import socket
import tempfile
import unittest
from pathlib import Path
from scanner.core import parse_ports, scan_port
from scanner.reports import write_html, write_json


class ScannerTests(unittest.TestCase):
    def test_parse_ports(self):
        self.assertEqual(parse_ports('443,80,8000-8002,80'), [80,443,8000,8001,8002])

    def test_invalid_ports(self):
        for value in ('0', '65536', '20-10', '1-2000', '80,'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_ports(value)

    def test_local_open_port(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            port = server.getsockname()[1]
            result = scan_port('127.0.0.1', port, 0.5)
            self.assertIsNotNone(result)
            self.assertEqual(result['status'], 'open')

    def test_reports_escape_html(self):
        report = {'target':'<script>', 'resolved_ip':'127.0.0.1', 'scanned_at_utc':'now', 'ports_checked':1,
                  'open_ports':[{'port':80,'service':'<b>','status':'open'}], 'notes':'safe'}
        with tempfile.TemporaryDirectory() as folder:
            html_file = Path(folder) / 'test.html'
            json_file = Path(folder) / 'test.json'
            write_html(report, html_file)
            write_json(report, json_file)
            self.assertIn('&lt;script&gt;', html_file.read_text())
            self.assertIn('&lt;b&gt;', html_file.read_text())
            self.assertTrue(json_file.exists())


if __name__ == '__main__':
    unittest.main()
