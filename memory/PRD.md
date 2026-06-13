# PRD — bug-bounty-toolkit

## Problem statement (original)

User asked for a professional, modular, robust Python bug-bounty automation
tool runnable from the command line on Windows / Linux / macOS, for use
**only in controlled environments with explicit authorization**. After
clarification:

* Implement the full CLI tool described in the prompt.
* Complete version with all modules.
* Wrap in FastAPI + React UI.
* Mandatory `--i-have-authorization` flag + legal banner.

Follow-up (2026-06): user tested v1.0 against DVWA and reported it found
"nothing real" — only headers + CVEs. Asked for actual vulnerability
exploitation: SQLi, XSS, LFI, command injection, etc.

## Architecture (v1.2)

```
/app/
├── bugbounty_tool/
│   ├── bugbounty_tool.py          # CLI entry
│   ├── core.py                    # Pipeline orchestration
│   ├── modules/
│   │   ├── recon.py
│   │   ├── scan.py
│   │   ├── crawler.py             # BFS endpoint/param discovery (v1.1)
│   │   ├── exploits.py            # 15 active vulnerability scanners (v1.1)
│   │   ├── vuln.py                # Passive + active orchestration
│   │   └── report.py              # txt / json / md
│   ├── utils/
│   │   ├── network.py             # safe_request, host_only, host_port
│   │   ├── session.py             # HttpContext + login_form (v1.1)
│   │   ├── parsers.py
│   │   ├── cve_db.py
│   │   ├── wordlists.py
│   │   └── helpers.py
│   ├── tests/vulnserver.py        # Local vulnerable HTTP server (self-test)
│   ├── config.yaml
│   └── requirements.txt
├── backend/
│   ├── server.py                  # mounts bb_api router
│   └── bb_api.py                  # /api/bb/*  (pymongo persistence)
├── frontend/
│   └── src/{App.js, App.css}      # Dark security-console dashboard
└── memory/PRD.md
```

## What's implemented

### v1.0 (2026-06-12)
* CLI with 4 subcommands (`recon`, `scan`, `vuln`, `all`).
* Authorization gating (`--i-have-authorization`).
* Recon: DNS, WHOIS, crt.sh + wordlist subdomain enum, tech fingerprinting,
  dir fuzzing, form & URL-param discovery.
* Scan: TCP probe of common web ports, HTTP banner, version detection.
* Vuln (passive): CVE lookup (offline DB), security-header audit, exposed
  sensitive-file checks, sensitive HTML-comment scan.
* Report: txt / JSON / Markdown.
* FastAPI router (`/api/bb/*`) + React dashboard with live progress, summary
  stats, per-module tabs, multi-format report viewer.

### v1.1 (2026-06-13) — Active exploitation
* **BFS crawler** with depth + page caps, respects per-context delay.
* **HttpContext** session abstraction (cookies + custom headers + timeout +
  TLS verify) used by every module.
* **Optional auto-login** (`login_url` + `login_user` + `login_password`)
  populates cookies before scanning (DVWA, Juice Shop, etc.).
* **15 active exploit scanners**:
  - `sqli` — error-based + boolean + time-based (MySQL/Postgres/SQLite)
  - `xss` — reflected XSS with multiple sentinel payloads
  - `cmdi` — sleep-based blind command injection
  - `lfi` — path traversal (Linux /etc/passwd, Windows win.ini)
  - `open_redirect` — `?next=`, `?url=` etc.
  - `crlf` — CRLF header injection
  - `csrf` — POST forms missing anti-CSRF token
  - `default_creds` — small dictionary of default admin pairs
  - `cookies` — Secure / HttpOnly / SameSite audit
  - `cors` — Origin reflection + ACAC: true
  - `dir_listing` — auto-index detection on crawled URLs
  - `methods` — PUT / DELETE / TRACE via OPTIONS
  - `git` — `.git/HEAD` exposure
  - `backups` — `.bak/.old/.swp/~` variants of common config files
  - `wordpress` — `wp-json/wp/v2/users` enum + xmlrpc
* CLI: `--cookie`, `--cookies`, `-H`, `--login-url/user/password`,
  `--crawl-depth`, `--crawl-max-pages`, `--exploits`.
* API: same fields on `POST /api/bb/scans`; new `GET /api/bb/exploits`.
* UI: collapsible Advanced panel exposing all new options + 15 exploit pills.
* Local vulnerable test server `tests/vulnserver.py` (port 9999) for
  self-test — produces 25 findings across all severity tiers.

### v1.2 (2026-06-13) — Hardening
* Fixed motor "Event loop is closed" on `/api/bb/scans` + DELETE by switching
  persistence to synchronous pymongo.
* Fixed `normalize_target` stripping `:port`. New `host_only()` + `host_port()`
  helpers. `run_scan` now auto-uses explicit port when given `host:port`.
* All 21 backend tests pass (10 v1.0 + 6 v1.1 + 5 v1.2 regression).

## Test results

| Iteration | Tests | Status |
|-----------|-------|--------|
| 1 (v1.0)  | 13/13 | All pass |
| 2 (v1.1)  | 14/16 | 2 critical bugs caught (motor loop, port stripping) |
| 3 (v1.2)  | 21/21 | Fully green — both v1.1 bugs fixed |

Local vulnserver self-test: **25 findings** (3 critical, 6 high, 7 medium,
8 low, 1 info) including `sqli_error`, `xss_reflected`, `command_injection`,
`lfi`, `open_redirect`, `csrf_missing`, `insecure_cookie`, `dir_listing`,
`dangerous_methods`, `git_exposure`, `backup_file`, `wp_user_enum`.

## Backlog

### P1
* Online CVE enrichment (OSV/NVD) replacing the small offline DB.
* nmap `-sV` integration when `python-nmap` is available.
* Stored XSS detection (multi-step: store then retrieve).
* SSRF (out-of-band Burp Collaborator style).
* IPv6 host:port parsing in `host_port()`.

### P2
* PDF export of reports.
* SSE/WebSocket streaming of progress (today: polling).
* Multi-target batch mode.
* Auth + RBAC for the public API.
* Module-level shared MongoClient (today: opens/closes per scan).

## Next action items

* If publishing publicly, add rate limiting + per-user auth.
* Optional: persist intermediate job state so a backend restart does not
  lose running jobs.
