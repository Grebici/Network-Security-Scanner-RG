# 🛡️ Network Security Scanner

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white) ![License](https://img.shields.io/badge/License-MIT-green) ![Focus](https://img.shields.io/badge/Focus-Network%20Security-0ea5e9)

A lightweight, dependency-free **Python TCP port scanner** for learning network security and auditing **systems you own or have permission to test**.

## ✨ Features

- Scan a single authorized IPv4 host using TCP connections
- Select common ports, individual ports, or port ranges
- Concurrent scanning with adjustable timeout and worker limits
- Display likely services based on common port numbers
- Export clean **JSON** and styled **HTML** reports
- Built-in validation, safety checks, and automated tests
- Blocks public targets by default unless explicitly opted in

## 🧰 Tech stack

**Python 3.9+**, `socket`, `ipaddress`, `concurrent.futures`, `argparse`, `unittest`, HTML/CSS.

> **Note:** This project uses Python's standard library, not Nmap. It demonstrates TCP connect scanning; it does not perform OS detection, vulnerability assessment, or verified service fingerprinting.

## 🚀 Quick start

Clone or download the repository, then open a terminal in the project directory.

```bash
python main.py 127.0.0.1
```

Scan selected ports:

```bash
python main.py 127.0.0.1 --ports 22,80,443,8000-8010
```

Customize performance:

```bash
python main.py 127.0.0.1 --ports 1-100 --timeout 0.3 --workers 16
```

Reports are created in `reports/scan-report.json` and `reports/scan-report.html`. Open the HTML file in your browser.

### Example terminal output

```json
{
  "target": "127.0.0.1",
  "resolved_ip": "127.0.0.1",
  "ports_checked": 3,
  "open_ports": [
    {"port": 80, "service": "HTTP", "status": "open"}
  ]
}
```

*Illustrative output only. Actual results depend on your machine and running services.*

## 🧪 Run tests

```bash
python -m unittest discover -s tests -v
```

## 📁 Project structure

```text
Network-Security-Scanner/
├── main.py                # CLI and arguments
├── scanner/
│   ├── __init__.py
│   ├── core.py            # TCP scan and validation
│   └── reports.py         # JSON and HTML exports
├── tests/
│   └── test_scanner.py    # Unit tests
├── examples/
│   └── example-report.json
├── .gitignore
├── LICENSE
└── README.md
```

## 🔒 Responsible use

Only scan hosts you own or are **explicitly authorized** to assess. The default target restriction is a safeguard, not a substitute for permission. A private IP address is not automatically authorized. Public hosts require the `--allow-public` flag and prior authorization. This tool scans **one host**, not an entire subnet.

**Interpretation:** A TCP connection succeeding indicates an open port at scan time. The service label is only a common-port guess. An open port does **not** prove a vulnerability, and a filtered or timed-out port is not necessarily closed.

## 🗺️ Future improvements

- Optional verified service banners where appropriate
- CSV exports
- Improved test coverage and CI
- Comparison between scans over time

## 👨‍💻 Author

Created as a hands-on cybersecurity engineering portfolio project by [Grebici](https://github.com/Grebici).
