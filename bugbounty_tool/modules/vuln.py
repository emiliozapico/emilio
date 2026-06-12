"""Vulnerability heuristics built on top of the recon + scan outputs."""
from __future__ import annotations

import time
from typing import Callable, Dict, List, Optional

from ..utils import network, parsers, helpers
from ..utils.cve_db import get_cves_for_technology

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
    timeout: int = 6,
    delay: float = 0.0,
    on_progress: Optional[Callable[[str], None]] = None,
) -> List[Dict]:
    findings: List[Dict] = []
    base_url = base_url.rstrip("/")
    for path in EXPOSED_FILES:
        url = f"{base_url}/{path}"
        resp = network.safe_get(url, timeout=timeout, retries=0,
                                allow_redirects=False, verify=False, delay=delay)
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


def bruteforce_login(
    login_url: str,
    usernames: List[str],
    passwords: List[str],
    username_field: str = "username",
    password_field: str = "password",
    timeout: int = 6,
    delay: float = 2.0,
    max_attempts: int = 5,
    on_progress: Optional[Callable[[str], None]] = None,
) -> List[Dict]:
    """Heavily rate-limited demonstration brute-force.

    Stops after ``max_attempts`` total requests to guarantee we do not flood
    the target. Intended only for explicit authorized labs (DVWA, etc.).
    """
    import requests
    findings: List[Dict] = []
    attempts = 0
    baseline = None
    progress = on_progress or (lambda m: log.info(m))
    for user in usernames:
        for pwd in passwords:
            if attempts >= max_attempts:
                progress("brute-force capped at max_attempts")
                return findings
            attempts += 1
            try:
                resp = requests.post(
                    login_url,
                    data={username_field: user, password_field: pwd},
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False,
                )
            except requests.RequestException as exc:
                progress(f"brute-force request failed: {exc}")
                time.sleep(delay)
                continue
            length = len(resp.content or b"")
            if baseline is None:
                baseline = length
            if abs(length - baseline) > 500 or resp.status_code in (301, 302, 303):
                findings.append({
                    "type": "weak_credentials",
                    "severity": "critical",
                    "title": f"Possible valid credentials: {user}:{pwd}",
                    "evidence": f"HTTP {resp.status_code}, length delta {length - baseline}",
                    "description": "Server response differs notably from the baseline failed login.",
                    "reference": "https://owasp.org/www-community/attacks/Brute_force_attack",
                    "url": login_url,
                })
                progress(f"candidate credentials {user}:{pwd}")
            time.sleep(delay)
    return findings


def run_vuln(
    *,
    target: str,
    recon_result: Optional[Dict] = None,
    scan_result: Optional[Dict] = None,
    timeout: int = 6,
    delay: float = 0.0,
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

    if not recon_result and not scan_result:
        resp = network.safe_get(base_url, timeout=timeout, retries=1, verify=False)
        if resp is not None:
            headers = dict(resp.headers)
            html = resp.text or ""
            technologies = parsers.detect_technologies(headers, html)
            base_url = resp.url
    else:
        resp = network.safe_get(base_url, timeout=timeout, retries=0, verify=False)
        if resp is not None:
            html = resp.text or ""

    progress(f"evaluating {len(technologies)} detected technologies for CVEs")
    findings.extend(cves_from_technologies(technologies))

    progress("checking security headers")
    findings.extend(check_security_headers(headers))

    progress("checking exposed sensitive files")
    findings.extend(check_exposed_files(base_url, timeout=timeout, delay=delay,
                                         on_progress=progress))

    progress("scanning HTML for sensitive comments")
    findings.extend(check_html_findings(html))

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
    }
