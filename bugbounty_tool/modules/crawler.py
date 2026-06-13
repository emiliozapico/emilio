"""Same-origin BFS crawler that yields URLs, forms and GET parameters.

The crawler is intentionally small and polite: it caps depth, total pages
and respects the per-context delay. Discovered endpoints feed the active
exploit module.
"""
from __future__ import annotations

from collections import deque
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin, parse_qsl

from bs4 import BeautifulSoup

from ..utils import network
from ..utils.session import HttpContext


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


def _extract_links(html: str, base_url: str) -> List[str]:
    soup = BeautifulSoup(html or "", "html.parser")
    links: List[str] = []
    for tag in soup.find_all(["a", "link", "iframe"], href=True):
        links.append(urljoin(base_url, tag.get("href")))
    for tag in soup.find_all(["script", "img", "source"], src=True):
        links.append(urljoin(base_url, tag.get("src")))
    return links


def _extract_forms(html: str, base_url: str) -> List[Dict]:
    soup = BeautifulSoup(html or "", "html.parser")
    forms: List[Dict] = []
    for f in soup.find_all("form"):
        action = urljoin(base_url, f.get("action") or "")
        method = (f.get("method") or "get").upper()
        inputs: List[Dict] = []
        for inp in f.find_all(["input", "textarea", "select"]):
            inputs.append({
                "name": inp.get("name"),
                "type": (inp.get("type") or inp.name or "text").lower(),
                "value": inp.get("value") or "",
            })
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


def crawl(
    start_url: str,
    ctx: HttpContext,
    *,
    max_depth: int = 2,
    max_pages: int = 30,
    on_progress: Optional[Callable[[str], None]] = None,
) -> Dict:
    """Return ``{urls, forms, params}`` discovered from ``start_url``."""
    progress = on_progress or (lambda m: None)
    visited: Set[str] = set()
    forms: List[Dict] = []
    params: List[Dict] = []
    queue: deque = deque([(start_url, 0)])

    def _add_param(url: str, key: str, value: str) -> None:
        signature: Tuple[str, str] = (urlparse(url).path, key)
        for existing in params:
            if (urlparse(existing["url"]).path, existing["param"]) == signature:
                return
        params.append({"url": url, "param": key, "sample": value})

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        resp = network.safe_get(url, ctx=ctx, retries=0, allow_redirects=True)
        if resp is None:
            continue
        progress(f"crawl [{depth}] {url} -> {resp.status_code}")

        # Record GET parameters on the visited URL
        parsed = urlparse(resp.url)
        for k, v in parse_qsl(parsed.query, keep_blank_values=True):
            _add_param(resp.url, k, v)

        # Record forms
        for form in _extract_forms(resp.text or "", resp.url):
            if not any(
                ff["action"] == form["action"] and ff["method"] == form["method"]
                for ff in forms
            ):
                forms.append(form)

        if depth < max_depth:
            for link in _extract_links(resp.text or "", resp.url):
                if not _same_origin(link, start_url):
                    continue
                clean = link.split("#", 1)[0]
                if clean in visited:
                    continue
                # also register query params discovered in href
                parsed_link = urlparse(clean)
                for k, v in parse_qsl(parsed_link.query, keep_blank_values=True):
                    _add_param(clean, k, v)
                queue.append((clean, depth + 1))

    return {"urls": sorted(visited), "forms": forms, "params": params}
