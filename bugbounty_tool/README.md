# bug-bounty-toolkit

Modular, professional bug bounty automation toolkit written in Python.
**Use ONLY on systems for which you have explicit, written authorization.**
Unauthorized use is illegal in most jurisdictions.

It ships with:

* a full **command-line interface** (`bugbounty_tool.py`) usable on
  Windows/Linux/macOS,
* a **REST API** (FastAPI) wrapping the same modules,
* and a **web UI** (React) to launch scans, follow them in real time and
  browse historical reports.

## Modules

| Module | Purpose |
|--------|---------|
| `recon` | DNS resolution, optional WHOIS, subdomain enumeration via crt.sh + wordlist, technology fingerprinting, directory fuzzing, form/parameter discovery. |
| `scan`  | TCP probe of common web ports (80, 443, 8080, 8443, 8000, 3000, 5000), HTTP banner grabbing, version/tech detection. |
| `vuln`  | CVE lookup against an internal offline DB, security-header audit, exposed sensitive-file checks, HTML comment hygiene, rate-limited brute-force helper. |
| `report` | Render the merged result as plain text, JSON or Markdown. |

## Installation

```bash
cd bugbounty_tool
pip install -r requirements.txt
```

## CLI usage

```bash
# Recon only, save plain text
python bugbounty_tool.py recon -t example.com --i-have-authorization \
    -o report.txt

# Full pipeline with custom wordlists, JSON output, verbose
python bugbounty_tool.py all -t example.com --i-have-authorization -v \
    --subdomain-wordlist subdomains.txt --dir-wordlist dirs.txt \
    --output-format json -o report.json

# Port scan only with explicit ports and rate limiting
python bugbounty_tool.py scan -t 192.168.1.100 --i-have-authorization \
    --ports 80,443,8080 --delay 5 --output-format md -o report.md
```

The `--i-have-authorization` flag is **mandatory**: the tool refuses to start
without it.

## Configuration file

Pass a YAML file via `--config config.yaml`. Recognised keys: `timeout`,
`delay`, `ports`, `output_format`.

## Project layout

```
bugbounty_tool/
├── bugbounty_tool.py         # CLI entry point
├── core.py                   # High-level pipeline orchestration
├── modules/
│   ├── recon.py
│   ├── scan.py
│   ├── vuln.py
│   └── report.py
├── utils/
│   ├── network.py
│   ├── parsers.py
│   ├── cve_db.py
│   ├── wordlists.py
│   └── helpers.py
├── config.yaml
└── requirements.txt
```

## Web UI / API

The same modules are exposed through the FastAPI backend (`/app/backend`)
under the `/api/bb/*` prefix and consumed by the React dashboard. See the
project root for instructions.
