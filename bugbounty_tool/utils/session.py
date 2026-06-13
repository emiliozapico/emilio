"""HTTP session abstraction so every module shares cookies + custom headers.

The pipeline builds one :class:`HttpContext` and passes it to every module
that needs it. All HTTP traffic still flows through :func:`safe_get` /
:func:`safe_request` so behaviour (retries, timeout, UA) stays uniform.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

import requests

DEFAULT_UA = (
    "BugBountyToolkit/1.1 (+authorized-testing-only)"
)


@dataclass
class HttpContext:
    """Authenticated HTTP session config."""

    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    timeout: int = 10
    delay: float = 0.0
    verify_tls: bool = False
    user_agent: str = DEFAULT_UA

    def build_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({"User-Agent": self.user_agent})
        if self.headers:
            s.headers.update(self.headers)
        if self.cookies:
            s.cookies.update(self.cookies)
        s.verify = self.verify_tls
        return s


def parse_cookie_string(raw: str) -> Dict[str, str]:
    """Parse a "name1=value1; name2=value2" string into a dict."""
    out: Dict[str, str] = {}
    if not raw:
        return out
    for part in raw.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def parse_header_list(raw_list) -> Dict[str, str]:
    """Parse ['Name: value', ...] into a dict."""
    out: Dict[str, str] = {}
    for raw in raw_list or []:
        if ":" in raw:
            k, v = raw.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def login_form(
    ctx: HttpContext,
    login_url: str,
    username: str,
    password: str,
    username_field: str = "username",
    password_field: str = "password",
    extra_fields: Optional[Dict[str, str]] = None,
) -> bool:
    """Submit a login form to populate the context cookies.

    Returns ``True`` if the response sets at least one cookie (best-effort
    detection of a successful login). Used to support DVWA / Juice-Shop
    style apps from the CLI/UI.
    """
    session = ctx.build_session()
    try:
        # GET first to capture CSRF tokens etc.
        prev = session.get(login_url, timeout=ctx.timeout, allow_redirects=True)
        from bs4 import BeautifulSoup
        payload = {username_field: username, password_field: password}
        if extra_fields:
            payload.update(extra_fields)
        soup = BeautifulSoup(prev.text or "", "html.parser")
        for inp in soup.find_all("input"):
            name = inp.get("name")
            if not name or name in payload:
                continue
            if (inp.get("type") or "").lower() in ("hidden", "submit"):
                payload[name] = inp.get("value") or ""
        resp = session.post(
            login_url, data=payload, timeout=ctx.timeout, allow_redirects=True
        )
    except requests.RequestException:
        return False
    # Merge session cookies back into context
    ctx.cookies.update({c.name: c.value for c in session.cookies})
    return bool(session.cookies)
