#!/usr/bin/env python3
"""Command-line entry point for the bug-bounty toolkit.

Examples
--------
    python bugbounty_tool.py recon -t example.com -o report.txt
    python bugbounty_tool.py all   -t example.com -v --output-format json --output report.json
    python bugbounty_tool.py scan  -t 192.168.1.10 --ports 80,443,8080 --delay 5
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

# Allow running as a standalone script: `python bugbounty_tool.py ...`
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bugbounty_tool.core import run_pipeline  # noqa: E402
from bugbounty_tool.modules import report as report_mod  # noqa: E402
from bugbounty_tool.utils import helpers  # noqa: E402

try:
    import yaml  # noqa: F401
    HAS_YAML = True
except ImportError:  # pragma: no cover - yaml is a soft dependency
    HAS_YAML = False


def _parse_ports(raw: Optional[str]) -> Optional[List[int]]:
    if not raw:
        return None
    return [int(p) for p in raw.split(",") if p.strip()]


def _load_wordlist(path: Optional[str]) -> Optional[List[str]]:
    if not path:
        return None
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def _load_config(path: Optional[str]) -> dict:
    if not path:
        return {}
    if not HAS_YAML:
        raise SystemExit("PyYAML is required to use --config")
    import yaml as _yaml
    with open(path, "r", encoding="utf-8") as fh:
        data = _yaml.safe_load(fh)
    return data or {}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bugbounty_tool",
        description=(
            "Modular bug-bounty automation toolkit. USE ONLY ON TARGETS YOU "
            "HAVE EXPLICIT WRITTEN AUTHORIZATION TO TEST."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=helpers.authorization_warning(),
    )
    sub = parser.add_subparsers(dest="module", required=True,
                                metavar="{recon,scan,vuln,all}")

    def _common(p: argparse.ArgumentParser) -> None:
        p.add_argument("-t", "--target", required=True,
                       help="Target domain or IP (e.g. example.com).")
        p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging.")
        p.add_argument("--timeout", type=int, default=10, help="Network timeout in seconds.")
        p.add_argument("--delay", type=float, default=0.0,
                       help="Delay between requests in seconds.")
        p.add_argument("--config", help="YAML config file with default values.")
        p.add_argument("-o", "--output", help="Write the report to this file.")
        p.add_argument("--output-format", choices=["txt", "json", "md"], default="txt",
                       help="Report format (default: txt).")
        p.add_argument(
            "--i-have-authorization",
            action="store_true",
            help="Required confirmation that you have explicit written "
                 "authorization to test the target.",
        )

    p_recon = sub.add_parser("recon", help="Reconnaissance only")
    _common(p_recon)
    p_recon.add_argument("--subdomain-wordlist", help="Custom subdomain wordlist file.")
    p_recon.add_argument("--dir-wordlist", help="Custom directory wordlist file.")
    p_recon.add_argument("--no-whois", action="store_true", help="Skip WHOIS lookup.")

    p_scan = sub.add_parser("scan", help="Port + version scan only")
    _common(p_scan)
    p_scan.add_argument("--ports", help="Comma-separated port list (default 80,443,8080,8443,8000,3000,5000)")

    p_vuln = sub.add_parser("vuln", help="Vulnerability heuristics only")
    _common(p_vuln)

    p_all = sub.add_parser("all", help="Run every module (recon -> scan -> vuln)")
    _common(p_all)
    p_all.add_argument("--subdomain-wordlist", help="Custom subdomain wordlist file.")
    p_all.add_argument("--dir-wordlist", help="Custom directory wordlist file.")
    p_all.add_argument("--no-whois", action="store_true", help="Skip WHOIS lookup.")
    p_all.add_argument("--ports", help="Comma-separated port list.")
    p_all.add_argument("-s", "--silent-banner", action="store_true",
                       help="Do not print the ascii banner.")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "silent_banner", False):
        print(helpers.banner(), file=sys.stderr)
    print(helpers.authorization_warning(), file=sys.stderr)

    if not args.i_have_authorization:
        print(
            "\nERROR: refusing to run without --i-have-authorization.\n"
            "       Re-run with the flag once you confirm written consent.",
            file=sys.stderr,
        )
        return 2

    log = helpers.get_logger(verbose=args.verbose)

    cfg = _load_config(args.config)

    modules = ["recon", "scan", "vuln"] if args.module == "all" else [args.module]

    subdomain_wl = _load_wordlist(getattr(args, "subdomain_wordlist", None))
    dir_wl = _load_wordlist(getattr(args, "dir_wordlist", None))
    ports = _parse_ports(getattr(args, "ports", None)) or cfg.get("ports")
    with_whois = not getattr(args, "no_whois", False)

    log.info(f"target={args.target} modules={modules}")

    try:
        result = run_pipeline(
            target=args.target,
            modules=modules,
            timeout=args.timeout or cfg.get("timeout", 10),
            delay=args.delay or cfg.get("delay", 0.0),
            ports=ports,
            subdomain_wordlist=subdomain_wl,
            dir_wordlist=dir_wl,
            with_whois=with_whois,
            on_progress=log.info,
        )
    except KeyboardInterrupt:
        log.warning("interrupted by user")
        return 130

    rendered = report_mod.render(result, args.output_format)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        log.info(f"report written to {args.output}")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    sys.exit(main())
