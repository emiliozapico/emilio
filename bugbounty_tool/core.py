"""Top-level orchestration of all the modules."""
from __future__ import annotations

from typing import Callable, Dict, List, Optional

from .modules import recon as recon_mod
from .modules import scan as scan_mod
from .modules import vuln as vuln_mod
from .modules import report as report_mod
from .utils import helpers, network

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
    on_progress: Optional[Callable[[str], None]] = None,
) -> Dict:
    """Run a sequence of modules and return a single result dict."""
    modules = list(modules) if modules else list(MODULES)
    target = network.normalize_target(target)
    progress = on_progress or (lambda msg: log.info(msg))

    result: Dict = {"meta": report_mod.build_meta(target, modules)}

    recon_result: Optional[Dict] = None
    scan_result: Optional[Dict] = None

    if "recon" in modules:
        progress("== module: recon ==")
        recon_result = recon_mod.run_recon(
            target,
            with_whois=with_whois,
            subdomain_wordlist=subdomain_wordlist,
            dir_wordlist=dir_wordlist,
            timeout=timeout,
            delay=delay,
            on_progress=progress,
        )
        result["recon"] = recon_result

    if "scan" in modules:
        progress("== module: scan ==")
        scan_result = scan_mod.run_scan(
            target,
            ports=ports,
            timeout=max(2.0, float(timeout) / 3.0),
            delay=delay,
            on_progress=progress,
        )
        result["scan"] = scan_result

    if "vuln" in modules:
        progress("== module: vuln ==")
        vuln_result = vuln_mod.run_vuln(
            target=target,
            recon_result=recon_result,
            scan_result=scan_result,
            timeout=timeout,
            delay=delay,
            on_progress=progress,
        )
        result["vuln"] = vuln_result

    return result
