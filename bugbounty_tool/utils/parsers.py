"""HTML / header / URL parsers used by the recon and scan modules."""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup


# ---------------------------------------------------------------------------
# Technology fingerprinting
# ---------------------------------------------------------------------------

_SERVER_VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9\-]*)/([0-9][0-9A-Za-z\.\-]*)")
_X_POWERED_RE = re.compile(r"([A-Za-z][A-Za-z0-9\-]*)/([0-9][0-9A-Za-z\.\-]*)")
_JQUERY_RE = re.compile(r"jquery[/-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_BOOTSTRAP_RE = re.compile(r"bootstrap[/-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_WP_GENERATOR_RE = re.compile(r"wordpress\s*(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_DRUPAL_GENERATOR_RE = re.compile(r"drupal\s*(\d+(?:\.\d+)*)", re.IGNORECASE)
_JOOMLA_GENERATOR_RE = re.compile(r"joomla!?\s*-?\s*(\d+\.\d+(?:\.\d+)?)?", re.IGNORECASE)


def _add_tech(tech: List[Dict], name: str, version: Optional[str], source: str) -> None:
    name = name.strip().lower()
    if not name:
        return
    for existing in tech:
        if existing["name"] == name and (existing.get("version") or "") == (version or ""):
            return
    tech.append({"name": name, "version": version, "source": source})


def detect_technologies(headers: Dict[str, str], html: str) -> List[Dict]:
    """Extract a list of ``{name, version, source}`` dicts from headers + HTML."""
    tech: List[Dict] = []
    headers_l = {k.lower(): v for k, v in (headers or {}).items()}

    server = headers_l.get("server")
    if server:
        match = _SERVER_VERSION_RE.search(server)
        if match:
            _add_tech(tech, match.group(1), match.group(2), "Server header")
        else:
            _add_tech(tech, server.strip(), None, "Server header")

    x_pow = headers_l.get("x-powered-by")
    if x_pow:
        match = _X_POWERED_RE.search(x_pow)
        if match:
            _add_tech(tech, match.group(1), match.group(2), "X-Powered-By header")
        else:
            _add_tech(tech, x_pow.strip(), None, "X-Powered-By header")

    if headers_l.get("x-aspnet-version"):
        _add_tech(tech, "asp.net", headers_l["x-aspnet-version"], "X-AspNet-Version header")
    if headers_l.get("x-drupal-cache"):
        _add_tech(tech, "drupal", None, "X-Drupal-Cache header")

    if not html:
        return tech

    soup = BeautifulSoup(html, "html.parser")
    gen = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
    if gen and gen.get("content"):
        content = gen["content"]
        wp = _WP_GENERATOR_RE.search(content)
        if wp:
            _add_tech(tech, "wordpress", wp.group(1), "meta generator")
        dr = _DRUPAL_GENERATOR_RE.search(content)
        if dr:
            _add_tech(tech, "drupal", dr.group(1), "meta generator")
        jm = _JOOMLA_GENERATOR_RE.search(content)
        if jm:
            _add_tech(tech, "joomla", jm.group(1) if jm.group(1) else None, "meta generator")
        if not (wp or dr or jm):
            _add_tech(tech, content.split()[0].lower(), None, "meta generator")

    # JS libraries by script src
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        jq = _JQUERY_RE.search(src)
        if jq:
            _add_tech(tech, "jquery", jq.group(1), "script src")
        bs = _BOOTSTRAP_RE.search(src)
        if bs:
            _add_tech(tech, "bootstrap", bs.group(1), "script src")

    # Bootstrap can also appear in <link href=...>
    for tag in soup.find_all("link", href=True):
        href = tag["href"]
        bs = _BOOTSTRAP_RE.search(href)
        if bs:
            _add_tech(tech, "bootstrap", bs.group(1), "link href")

    if "wp-content" in html or "wp-includes" in html:
        _add_tech(tech, "wordpress", None, "html path hint")

    return tech


# ---------------------------------------------------------------------------
# Forms / URL parameters
# ---------------------------------------------------------------------------

def extract_forms(html: str, base_url: str) -> List[Dict]:
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    forms: List[Dict] = []
    for f in soup.find_all("form"):
        action = f.get("action") or ""
        method = (f.get("method") or "get").upper()
        inputs = []
        for inp in f.find_all(["input", "textarea", "select"]):
            inputs.append({
                "name": inp.get("name"),
                "type": inp.get("type", inp.name),
            })
        forms.append({
            "action": urljoin(base_url, action) if action else base_url,
            "method": method,
            "inputs": inputs,
        })
    return forms


def extract_url_parameters(html: str, base_url: str) -> List[Dict]:
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    found: List[Dict] = []
    seen: Set[Tuple[str, str]] = set()
    for tag in soup.find_all(["a", "link", "form"], href=True) + soup.find_all("a", href=True):
        href = tag.get("href")
        if not href:
            continue
        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)
        if not parsed.query:
            continue
        for key in parse_qs(parsed.query).keys():
            sig = (parsed.path, key)
            if sig in seen:
                continue
            seen.add(sig)
            found.append({"url": absolute, "param": key})
    return found


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

_HTML_COMMENT_RE = re.compile(r"<!--(.+?)-->", re.DOTALL)
_SENSITIVE_KEYWORDS_RE = re.compile(
    r"(todo|fixme|password|secret|api[_\-]?key|token|debug|backdoor)",
    re.IGNORECASE,
)


def extract_sensitive_comments(html: str) -> List[str]:
    """Return HTML comments that contain potentially sensitive keywords."""
    findings: List[str] = []
    if not html:
        return findings
    for raw in _HTML_COMMENT_RE.findall(html):
        if _SENSITIVE_KEYWORDS_RE.search(raw):
            cleaned = raw.strip()
            if cleaned and cleaned not in findings:
                findings.append(cleaned[:400])
    return findings
