#!/usr/bin/env python3
"""Command-line entry point for the bug-bounty toolkit."""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bugbounty_tool.core import run_pipeline  # noqa: E402
from bugbounty_tool.modules import report as report_mod  # noqa: E402
from bugbounty_tool.modules.exploits import ALL_EXPLOITS  # noqa: E402
from bugbounty_tool.utils import helpers  # noqa: E402
from bugbounty_tool.utils.session import parse_cookie_string, parse_header_list  # noqa: E402

try:
    import yaml  # noqa: F401
    HAS_YAML = True
except ImportError:
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
        return _yaml.safe_load(fh) or {}


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
        p.add_argument("--timeout", type=int, default=10, help="Network timeout (s).")
        p.add_argument("--delay", type=float, default=0.0, help="Delay between requests (s).")
        p.add_argument("--config", help="YAML config file.")
        p.add_argument("-o", "--output", help="Write the report to this file.")
        p.add_argument("--output-format", choices=["txt", "json", "md"], default="txt",
                       help="Report format (default: txt).")
        p.add_argument(
            "--i-have-authorization",
            action="store_true",
            help="Required: confirm you have explicit written authorization to test the target.",
        )
        # Session / auth
        p.add_argument("--cookie", action="append", default=[],
                       help="Add a cookie (name=value). Repeat to set multiple.")
        p.add_argument("--cookies",
                       help="Raw cookie string 'a=b; c=d' (overrides --cookie if both used).")
        p.add_argument("-H", "--header", action="append", default=[],
                       help="Custom header 'Name: value'. Repeat for multiple.")
        p.add_argument("--login-url", help="URL of a login form to populate session cookies.")
        p.add_argument("--login-user", help="Username for --login-url.")
        p.add_argument("--login-password", help="Password for --login-url.")
        p.add_argument("--login-user-field", default="username")
        p.add_argument("--login-password-field", default="password")

    p_recon = sub.add_parser("recon", help="Reconnaissance only")
    _common(p_recon)
    p_recon.add_argument("--subdomain-wordlist")
    p_recon.add_argument("--dir-wordlist")
    p_recon.add_argument("--no-whois", action="store_true")

    p_scan = sub.add_parser("scan", help="Port + version scan only")
    _common(p_scan)
    p_scan.add_argument("--ports", help="Comma-separated port list.")

    p_vuln = sub.add_parser("vuln", help="Vulnerability scan (passive + active exploits)")
    _common(p_vuln)
    p_vuln.add_argument("--crawl-depth", type=int, default=2)
    p_vuln.add_argument("--crawl-max-pages", type=int, default=30)
    p_vuln.add_argument("--exploits",
                        help=f"Comma-separated exploits to enable. Choices: {','.join(ALL_EXPLOITS)} "
                             "(default: all)")

    p_all = sub.add_parser("all", help="Run every module (recon -> scan -> vuln)")
    _common(p_all)
    p_all.add_argument("--subdomain-wordlist")
    p_all.add_argument("--dir-wordlist")
    p_all.add_argument("--no-whois", action="store_true")
    p_all.add_argument("--ports")
    p_all.add_argument("--crawl-depth", type=int, default=2)
    p_all.add_argument("--crawl-max-pages", type=int, default=30)
    p_all.add_argument("--exploits")
    p_all.add_argument("-s", "--silent-banner", action="store_true",
                       help="Do not print the ascii banner.")

    return parser


def _resolve_cookies(args) -> dict:
    if getattr(args, "cookies", None):
        return parse_cookie_string(args.cookies)
    return parse_cookie_string("; ".join(args.cookie or []))


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "silent_banner", False):
        print(helpers.banner(), file=sys.stderr)
    print(helpers.authorization_warning(), file=sys.stderr)

    if not args.i_have_authorization:
        print(
            "\nERROR: refusing to run without --i-have-authorization.",
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

    exploits = None
    raw_ex = getattr(args, "exploits", None)
    if raw_ex:
        exploits = [e.strip() for e in raw_ex.split(",") if e.strip()]

    cookies = _resolve_cookies(args)
    headers = parse_header_list(args.header)

    log.info(f"target={args.target} modules={modules} cookies={list(cookies)} headers={list(headers)}")

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
            cookies=cookies,
            headers=headers,
            crawl_depth=getattr(args, "crawl_depth", 2),
            crawl_max_pages=getattr(args, "crawl_max_pages", 30),
            enabled_exploits=exploits,
            login_url=getattr(args, "login_url", None),
            login_user=getattr(args, "login_user", None),
            login_password=getattr(args, "login_password", None),
            login_user_field=getattr(args, "login_user_field", "username"),
            login_password_field=getattr(args, "login_password_field", "password"),
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
