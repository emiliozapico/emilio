"""Reconnaissance module: WHOIS, DNS, subdomains, tech detection, dir fuzzing."""
from __future__ import annotations

from typing import Callable, Dict, List, Optional

from ..utils import network, parsers, wordlists, helpers

log = helpers.get_logger()


# ---------------------------------------------------------------------------
# WHOIS + DNS
# ---------------------------------------------------------------------------

def whois_lookup(domain: str) -> Dict:
    """Return a small subset of the WHOIS record for ``domain``.

    Failures are swallowed: WHOIS is optional and frequently rate-limited.
    """
    try:
        import whois  # python-whois
    except ImportError:
        return {"error": "python-whois not installed"}
    try:
        record = whois.whois(domain)
    except Exception as exc:  # noqa: BLE001 - WHOIS lib raises generic exceptions
        return {"error": f"whois failed: {exc}"}

    def _first(value):
        if isinstance(value, (list, tuple)):
            return str(value[0]) if value else None
        return str(value) if value else None

    return {
        "domain_name": _first(record.get("domain_name") if hasattr(record, "get") else None),
        "registrar": _first(record.get("registrar") if hasattr(record, "get") else None),
        "creation_date": _first(record.get("creation_date") if hasattr(record, "get") else None),
        "expiration_date": _first(record.get("expiration_date") if hasattr(record, "get") else None),
        "name_servers": list({str(ns) for ns in (record.get("name_servers") or [])}) if hasattr(record, "get") else [],
        "emails": list({str(e) for e in (record.get("emails") or [])}) if hasattr(record, "get") else [],
    }


def resolve(domain: str) -> Optional[str]:
    """Resolve ``domain`` to a single IPv4 (or ``None``)."""
    return network.resolve_host(domain)


# ---------------------------------------------------------------------------
# Subdomain enumeration
# ---------------------------------------------------------------------------

def enumerate_subdomains_crtsh(domain: str, timeout: int = 20) -> List[str]:
    """Query https://crt.sh certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    resp = network.safe_get(url, timeout=timeout)
    if not resp or resp.status_code != 200:
        return []
    try:
        data = resp.json()
    except ValueError:
        return []
    found = set()
    for entry in data:
        name = entry.get("name_value", "")
        for line in name.split("\n"):
            line = line.strip().lower().lstrip("*.")
            if line and line.endswith(domain):
                found.add(line)
    return sorted(found)


def enumerate_subdomains_wordlist(
    domain: str,
    wordlist: Optional[List[str]] = None,
    timeout: float = 2.0,
    on_progress: Optional[Callable[[str], None]] = None,
) -> List[str]:
    """Resolve ``<word>.<domain>`` for each entry; return ones that resolve."""
    words = wordlist if wordlist else wordlists.DEFAULT_SUBDOMAINS
    alive: List[str] = []
    for word in words:
        host = f"{word}.{domain}"
        ip = network.resolve_host(host)
        if ip:
            alive.append(host)
            if on_progress:
                on_progress(f"subdomain {host} -> {ip}")
    return alive


# ---------------------------------------------------------------------------
# Tech detection (fetch + parse)
# ---------------------------------------------------------------------------

def fetch_target(url: str, timeout: int = 10) -> Optional[Dict]:
    resp = network.safe_get(url, timeout=timeout)
    if resp is None:
        return None
    return {
        "url": resp.url,
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "html": resp.text or "",
    }


def detect_technologies(url: str, timeout: int = 10) -> Dict:
    fetched = fetch_target(url, timeout=timeout)
    if not fetched:
        return {"url": url, "ok": False, "technologies": [], "headers": {}}
    techs = parsers.detect_technologies(fetched["headers"], fetched["html"])
    return {
        "url": fetched["url"],
        "ok": True,
        "status_code": fetched["status_code"],
        "headers": fetched["headers"],
        "technologies": techs,
    }


# ---------------------------------------------------------------------------
# Directory enumeration
# ---------------------------------------------------------------------------

def enumerate_directories(
    base_url: str,
    wordlist: Optional[List[str]] = None,
    timeout: int = 6,
    delay: float = 0.0,
    on_progress: Optional[Callable[[str], None]] = None,
) -> List[Dict]:
    words = wordlist if wordlist else wordlists.DEFAULT_DIRS
    findings: List[Dict] = []
    base_url = base_url.rstrip("/")
    for word in words:
        url = f"{base_url}/{word}"
        resp = network.safe_get(
            url,
            timeout=timeout,
            retries=0,
            delay=delay,
            allow_redirects=False,
            verify=False,
        )
        if resp is None:
            continue
        if resp.status_code in (200, 201, 204, 301, 302, 401, 403):
            findings.append({
                "url": url,
                "status_code": resp.status_code,
                "length": len(resp.content),
            })
            if on_progress:
                on_progress(f"found {url} [{resp.status_code}]")
    return findings


# ---------------------------------------------------------------------------
# Param + form discovery
# ---------------------------------------------------------------------------

def discover_inputs(url: str, timeout: int = 10) -> Dict:
    fetched = fetch_target(url, timeout=timeout)
    if not fetched:
        return {"forms": [], "url_params": []}
    return {
        "forms": parsers.extract_forms(fetched["html"], fetched["url"]),
        "url_params": parsers.extract_url_parameters(fetched["html"], fetched["url"]),
    }


# ---------------------------------------------------------------------------
# High level orchestration
# ---------------------------------------------------------------------------

def run_recon(
    target: str,
    *,
    with_whois: bool = True,
    with_subdomains: bool = True,
    subdomain_wordlist: Optional[List[str]] = None,
    dir_wordlist: Optional[List[str]] = None,
    timeout: int = 10,
    delay: float = 0.0,
    on_progress: Optional[Callable[[str], None]] = None,
) -> Dict:
    target = network.normalize_target(target)
    progress = on_progress or (lambda msg: log.info(msg))

    progress(f"resolving {target}")
    ip = resolve(target)
    progress(f"ip = {ip or 'unresolved'}")

    whois_data: Dict = {}
    if with_whois:
        progress("running WHOIS")
        whois_data = whois_lookup(target)

    subdomains_crt: List[str] = []
    subdomains_wl: List[str] = []
    if with_subdomains:
        progress("querying crt.sh for subdomains")
        subdomains_crt = enumerate_subdomains_crtsh(target)
        progress(f"crt.sh returned {len(subdomains_crt)} subdomains")
        progress("brute-forcing common subdomains")
        subdomains_wl = enumerate_subdomains_wordlist(
            target, wordlist=subdomain_wordlist, on_progress=progress
        )

    base_url = f"http://{target}"
    progress(f"detecting technologies on {base_url}")
    tech = detect_technologies(base_url, timeout=timeout)
    if not tech.get("ok"):
        base_url = f"https://{target}"
        progress(f"http failed, trying {base_url}")
        tech = detect_technologies(base_url, timeout=timeout)

    progress("enumerating common directories")
    dirs = enumerate_directories(
        base_url,
        wordlist=dir_wordlist,
        timeout=timeout,
        delay=delay,
        on_progress=progress,
    )

    progress("discovering forms and URL parameters")
    inputs = discover_inputs(base_url, timeout=timeout)

    all_subdomains = sorted(set(subdomains_crt) | set(subdomains_wl))

    return {
        "target": target,
        "ip": ip,
        "whois": whois_data,
        "subdomains": all_subdomains,
        "subdomains_crtsh_count": len(subdomains_crt),
        "subdomains_wordlist_count": len(subdomains_wl),
        "technologies": tech.get("technologies", []),
        "response_headers": tech.get("headers", {}),
        "status_code": tech.get("status_code"),
        "base_url": tech.get("url", base_url),
        "directories": dirs,
        "forms": inputs["forms"],
        "url_params": inputs["url_params"],
    }
