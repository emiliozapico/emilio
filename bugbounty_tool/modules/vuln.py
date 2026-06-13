"""Vulnerability heuristics: passive checks (CVEs, headers, exposed files,
comments) plus the full active exploit battery from :mod:`exploits`."""
from __future__ import annotations

from typing import Callable, Dict, List, Optional

from ..utils import network, parsers, helpers
from ..utils.cve_db import get_cves_for_technology
from ..utils.session import HttpContext
from . import exploits as exploits_mod

log = helpers.get_logger()


SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS not enforced - TLS downgrade possible."),
    ("content-security-policy", "CSP missing - XSS impact is not mitigated."),
    ("x-content-type-options", "X-Content-Type-Options missing - MIME sniffing risk."),
    ("x-frame-options", "X-Frame-Options missing - clickjacking risk."),
    ("referrer-policy", "Referrer-Policy missing - referrer leakage possible."),
    ("permissions-policy", "Permissions-Policy missing - hardware/API exposure."),
]

EXPOSED_FILES = [
    ".env", ".env.local", ".env.production",
    "web.config", ".htaccess", ".git/config", ".git/HEAD",
    "config.php", "configuration.php", "wp-config.php.bak",
    "phpinfo.php", "info.php", "server-status", "server-info",
    "actuator/health", "actuator/env",
]


def cves_from_technologies(technologies: List[Dict]) -> List[Dict]:
    findings: List[Dict] = []
    for tech in technologies or []:
        cves = get_cves_for_technology(tech.get("name", ""), tech.get("version") or "")
        for cve in cves:
            findings.append({
                "type": "cve",
                "severity": cve.get("severity", "unknown"),
                "title": f"{tech['name']} {tech.get('version') or ''} - {cve['id']}",
                "evidence": tech.get("source"),
                "description": cve["desc"],
                "reference": cve.get("link"),
            })
    return findings


def check_security_headers(headers: Dict[str, str]) -> List[Dict]:
    if not headers:
        return []
    h_lower = {k.lower(): v for k, v in headers.items()}
    findings: List[Dict] = []
    for name, advice in SECURITY_HEADERS:
        if name not in h_lower:
            findings.append({
                "type": "missing_header",
                "severity": "low",
                "title": f"Missing security header: {name}",
                "evidence": "Header not present in response.",
                "description": advice,
                "reference": "https://owasp.org/www-project-secure-headers/",
            })
    server = h_lower.get("server", "")
    if server and "/" in server:
        findings.append({
            "type": "version_disclosure",
            "severity": "info",
            "title": "Server version disclosure",
            "evidence": f"Server: {server}",
            "description": "Server header reveals the exact software version, easing attacker fingerprinting.",
            "reference": "https://owasp.org/www-community/Improper_Error_Handling",
        })
    return findings


def check_exposed_files(
    base_url: str,
    ctx: HttpContext,
    on_progress: Optional[Callable[[str], None]] = None,
) -> List[Dict]:
    findings: List[Dict] = []
    base_url = base_url.rstrip("/")
    for path in EXPOSED_FILES:
        url = f"{base_url}/{path}"
        resp = network.safe_get(url, ctx=ctx, retries=0, allow_redirects=False)
        if resp is None:
            continue
        if resp.status_code == 200 and len(resp.content) > 0:
            snippet = (resp.text or "")[:200]
            findings.append({
                "type": "exposed_file",
                "severity": "high" if path.startswith(".env") or "config" in path else "medium",
                "title": f"Exposed sensitive file: /{path}",
                "evidence": f"HTTP 200, {len(resp.content)} bytes",
                "description": helpers.truncate(snippet, 200),
                "reference": "https://owasp.org/www-project-top-ten/",
                "url": url,
            })
            if on_progress:
                on_progress(f"exposed: {url}")
    return findings


def check_html_findings(html: str) -> List[Dict]:
    findings: List[Dict] = []
    for raw in parsers.extract_sensitive_comments(html or ""):
        findings.append({
            "type": "sensitive_comment",
            "severity": "low",
            "title": "Sensitive HTML comment",
            "evidence": helpers.truncate(raw, 200),
            "description": "Comment contains a keyword often associated with leftover debug or credentials.",
            "reference": "https://cwe.mitre.org/data/definitions/615.html",
        })
    return findings


def _build_endpoints_from_recon(recon_result: Optional[Dict], base_url: str) -> Dict:
    """Build the endpoint bag used by the exploit module."""
    urls: List[str] = [base_url]
    forms: List[Dict] = []
    params: List[Dict] = []
    if recon_result:
        forms = list(recon_result.get("forms") or [])
        for p in recon_result.get("url_params") or []:
            params.append({"url": p["url"], "param": p["param"], "sample": ""})
    return {"urls": urls, "forms": forms, "params": params}


def run_vuln(
    *,
    target: str,
    ctx: HttpContext,
    recon_result: Optional[Dict] = None,
    scan_result: Optional[Dict] = None,
    crawl_result: Optional[Dict] = None,
    enabled_exploits: Optional[List[str]] = None,
    on_progress: Optional[Callable[[str], None]] = None,
) -> Dict:
    progress = on_progress or (lambda m: log.info(m))
    findings: List[Dict] = []

    technologies: List[Dict] = []
    headers: Dict[str, str] = {}
    base_url = f"http://{network.normalize_target(target)}"
    html = ""

    if recon_result:
        technologies.extend(recon_result.get("technologies", []))
        headers = recon_result.get("response_headers", {}) or headers
        base_url = recon_result.get("base_url") or base_url

    if scan_result:
        for port_info in scan_result.get("ports", []):
            if port_info.get("open") and port_info.get("technologies"):
                technologies.extend(port_info["technologies"])
            if port_info.get("open") and port_info.get("headers") and not headers:
                headers = port_info["headers"]

    # Fetch the base URL once for HTML / headers / fallback technologies
    resp = network.safe_get(base_url, ctx=ctx, retries=0)
    if resp is not None:
        if not headers:
            headers = dict(resp.headers)
        html = resp.text or ""
        if not technologies:
            technologies = parsers.detect_technologies(headers, html)
        base_url = resp.url

    progress(f"evaluating {len(technologies)} detected technologies for CVEs")
    findings.extend(cves_from_technologies(technologies))

    progress("checking security headers")
    findings.extend(check_security_headers(headers))

    progress("checking exposed sensitive files")
    findings.extend(check_exposed_files(base_url, ctx, on_progress=progress))

    progress("scanning HTML for sensitive comments")
    findings.extend(check_html_findings(html))

    # Active exploitation
    endpoints = crawl_result or _build_endpoints_from_recon(recon_result, base_url)
    progress(
        f"active exploits: {len(endpoints.get('params', []))} params, "
        f"{len(endpoints.get('forms', []))} forms, {len(endpoints.get('urls', []))} urls"
    )
    findings.extend(exploits_mod.run_exploits(
        base_url=base_url, endpoints=endpoints, ctx=ctx,
        on_progress=progress, enabled=enabled_exploits,
    ))

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for f in findings:
        sev = (f.get("severity") or "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1

    return {
        "target": target,
        "base_url": base_url,
        "technologies_evaluated": technologies,
        "findings": findings,
        "counts": counts,
        "endpoints_tested": {
            "url_count": len(endpoints.get("urls", [])),
            "form_count": len(endpoints.get("forms", [])),
            "param_count": len(endpoints.get("params", [])),
        },
    }
