# PRD — bug-bounty-toolkit

## Problem statement (original, verbatim from user)

User asked for a professional, modular, robust Python bug-bounty automation
tool runnable from the command line on Windows / Linux / macOS, for use
**only in controlled environments with explicit authorization**. After
clarification the user chose:

* (a) Implement the full CLI tool described in the prompt.
* (b) Complete version with all modules (recon, scan, vuln, report).
* (b) Wrap the CLI in a FastAPI + React UI as well.
* OK to require a mandatory `--i-have-authorization` flag + legal banner.

## Architecture

```
/app/
├── bugbounty_tool/            # Pure-Python CLI package
│   ├── bugbounty_tool.py      # argparse entry point
│   ├── core.py                # run_pipeline orchestration
│   ├── modules/{recon,scan,vuln,report}.py
│   ├── utils/{network,parsers,cve_db,wordlists,helpers}.py
│   ├── config.yaml            # default YAML config
│   ├── requirements.txt
│   └── README.md
├── backend/
│   ├── server.py              # FastAPI app, mounts bb_api router
│   └── bb_api.py              # /api/bb/* endpoints, threaded jobs, Mongo
├── frontend/
│   └── src/
│       ├── App.js             # Dashboard (scan form, history, results)
│       └── App.css            # Custom dark "security console" aesthetic
└── memory/PRD.md
```

## What's implemented (2026-06)

* CLI with 4 subcommands (`recon`, `scan`, `vuln`, `all`).
* Authorization-gated entry: refuses to run without `--i-have-authorization`.
* Recon module: DNS resolve, optional WHOIS, crt.sh + wordlist subdomain
  enumeration, technology fingerprinting via headers/HTML/JS, directory
  fuzzing, form & URL-parameter discovery.
* Scan module: TCP probe of 7 common web ports, HTTP banner + version
  detection.
* Vuln module: offline CVE DB lookup (12 technologies), security-header
  audit, exposed-file checks, sensitive HTML-comment detection, rate-limited
  brute-force helper.
* Report module: txt / JSON / Markdown renderers with severity-sorted findings
  and remediation recommendations.
* FastAPI router at `/api/bb/*` with threaded job runner + MongoDB persistence
  (`db.bb_scans`).
* React dashboard with launch form, live progress console, severity summary,
  per-module result tabs, multi-format report viewer + download, scan history.
* Exhaustive `data-testid` coverage.
* Full test suite (13 tests, 100% passing).

## User personas

* **Authorized pentester / bug-bounty hunter** running engagements on
  systems they own or have written permission to test.
* **Security engineer** doing internal CI-time scans against staging.
* **Educator / CTF organizer** demoing reconnaissance methodology.

## Core requirements (static)

1. CLI must be runnable on Windows/Linux/macOS.
2. Modular code (separate modules + utils).
3. Configurable via CLI args + YAML config.
4. Three output formats: txt, json, md.
5. Internal CVE DB usable offline.
6. Authorization gating + legal banner.

## Backlog

### P1
* Wire `bruteforce_login` (already implemented in `modules/vuln.py`) into the
  CLI/UI behind an explicit subcommand + extra confirmation.
* Replace the offline `CVE_DB` with optional online OSV/NVD enrichment.
* Add nmap-style `-sV` integration when `python-nmap` is available.

### P2
* PDF export of reports.
* SSE/WebSocket streaming of progress (currently polled).
* Multi-target batch mode (file of targets).
* User accounts + RBAC for the API.

## Next action items

* If user wants to deploy publicly, add rate limiting + per-user auth.
* Optionally clear `db.bb_scans` to wipe test scans created during validation.
