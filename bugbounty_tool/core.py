"""Top-level orchestration of all the modules."""
from __future__ import annotations

from typing import Callable, Dict, List, Optional

from .modules import recon as recon_mod
from .modules import scan as scan_mod
from .modules import vuln as vuln_mod
from .modules import crawler as crawler_mod
from .modules import report as report_mod
from .utils import helpers, network
from .utils.session import HttpContext, login_form

log = helpers.get_logger()


MODULES = ("recon", "scan", "vuln")


def run_pipeline(
    target: str,
    modules: Optional[List[str]] = None,
    *,
    timeout: int = 10,
    delay: float = 0.0,
    ports: Optional[List[int]] = None,
    subdomain_wordlist: Optional[List[str]] = None,
    dir_wordlist: Optional[List[str]] = None,
    with_whois: bool = True,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    crawl_depth: int = 2,
    crawl_max_pages: int = 30,
    enabled_exploits: Optional[List[str]] = None,
    login_url: Optional[str] = None,
    login_user: Optional[str] = None,
    login_password: Optional[str] = None,
    login_user_field: str = "username",
    login_password_field: str = "password",
    on_progress: Optional[Callable[[str], None]] = None,
) -> Dict:
    """Run a sequence of modules and return a single result dict."""
    modules = list(modules) if modules else list(MODULES)
    target = network.normalize_target(target)
    progress = on_progress or (lambda msg: log.info(msg))

    ctx = HttpContext(
        cookies=cookies or {},
        headers=headers or {},
        timeout=timeout,
        delay=delay,
    )

    # Optional login to populate the session cookies
    if login_url and login_user and login_password:
        progress(f"login attempt against {login_url} as {login_user}")
        ok = login_form(
            ctx, login_url, login_user, login_password,
            username_field=login_user_field, password_field=login_password_field,
        )
        progress(f"login -> {'cookies set' if ok else 'no cookies returned'}")

    result: Dict = {"meta": report_mod.build_meta(target, modules)}
    recon_result: Optional[Dict] = None
    scan_result: Optional[Dict] = None
    crawl_result: Optional[Dict] = None

    if "recon" in modules:
        progress("== module: recon ==")
        recon_result = recon_mod.run_recon(
            target, ctx,
            with_whois=with_whois,
            subdomain_wordlist=subdomain_wordlist,
            dir_wordlist=dir_wordlist,
            on_progress=progress,
        )
        result["recon"] = recon_result

    if "scan" in modules:
        progress("== module: scan ==")
        scan_result = scan_mod.run_scan(
            target, ctx, ports=ports,
            timeout=max(2.0, float(timeout) / 3.0),
            on_progress=progress,
        )
        result["scan"] = scan_result

    # Crawl whenever vuln is requested - that's how we find injection points
    if "vuln" in modules:
        base_url = (recon_result or {}).get("base_url") or f"http://{target}"
        progress(f"== module: crawl ({crawl_depth}/{crawl_max_pages}) ==")
        crawl_result = crawler_mod.crawl(
            base_url, ctx,
            max_depth=crawl_depth, max_pages=crawl_max_pages,
            on_progress=progress,
        )
        # Merge crawler params/forms with what recon found (recon only looked at root)
        if recon_result:
            for f in recon_result.get("forms") or []:
                if not any(
                    cf["action"] == f["action"] and cf["method"] == f["method"]
                    for cf in crawl_result["forms"]
                ):
                    crawl_result["forms"].append(f)
            for p in recon_result.get("url_params") or []:
                existing_sigs = {
                    (cp["url"], cp["param"]) for cp in crawl_result["params"]
                }
                if (p["url"], p["param"]) not in existing_sigs:
                    crawl_result["params"].append({
                        "url": p["url"], "param": p["param"], "sample": ""
                    })
        result["crawl"] = {
            "url_count": len(crawl_result.get("urls", [])),
            "form_count": len(crawl_result.get("forms", [])),
            "param_count": len(crawl_result.get("params", [])),
            "urls": crawl_result.get("urls", [])[:50],
            "params": crawl_result.get("params", [])[:100],
        }

        progress("== module: vuln ==")
        vuln_result = vuln_mod.run_vuln(
            target=target, ctx=ctx,
            recon_result=recon_result, scan_result=scan_result,
            crawl_result=crawl_result, enabled_exploits=enabled_exploits,
            on_progress=progress,
        )
        result["vuln"] = vuln_result

    return result
