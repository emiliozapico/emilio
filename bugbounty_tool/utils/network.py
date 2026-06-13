"""Network helpers shared across modules.

All HTTP traffic goes through :func:`safe_request` so we have a single
place to configure timeouts, retries, User-Agent, cookies, headers and
inter-request delays.
"""
from __future__ import annotations

import socket
import time
from typing import Optional
from urllib.parse import urlparse

import requests

from .session import HttpContext, DEFAULT_UA  # re-export for backward compat


def safe_request(
    url: str,
    method: str = "GET",
    *,
    ctx: Optional[HttpContext] = None,
    timeout: Optional[int] = None,
    retries: int = 1,
    delay: float = 0.0,
    headers: Optional[dict] = None,
    cookies: Optional[dict] = None,
    data=None,
    params=None,
    allow_redirects: bool = True,
    verify: Optional[bool] = None,
) -> Optional[requests.Response]:
    """Issue an HTTP request with retries. Returns ``None`` on total failure."""
    final_headers = {"User-Agent": (ctx.user_agent if ctx else DEFAULT_UA)}
    if ctx and ctx.headers:
        final_headers.update(ctx.headers)
    if headers:
        final_headers.update(headers)
    final_cookies = dict(ctx.cookies) if ctx and ctx.cookies else {}
    if cookies:
        final_cookies.update(cookies)
    final_timeout = timeout if timeout is not None else (ctx.timeout if ctx else 10)
    final_verify = verify if verify is not None else (ctx.verify_tls if ctx else False)
    final_delay = max(delay, ctx.delay if ctx else 0.0)

    last_exc: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            response = requests.request(
                method.upper(),
                url,
                timeout=final_timeout,
                headers=final_headers,
                cookies=final_cookies or None,
                data=data,
                params=params,
                allow_redirects=allow_redirects,
                verify=final_verify,
            )
            if final_delay > 0:
                time.sleep(final_delay)
            return response
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(min(2 ** attempt, 5))
                continue
    _ = last_exc  # silenced for type-checkers
    return None


def safe_get(url: str, **kwargs) -> Optional[requests.Response]:
    """Backwards-compatible shortcut for GET."""
    return safe_request(url, method="GET", **kwargs)


def resolve_host(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return None


def tcp_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def normalize_target(target: str) -> str:
    """Return ``host`` or ``host:port`` (strip scheme + path)."""
    if "://" in target:
        parsed = urlparse(target)
        netloc = parsed.netloc or parsed.hostname or target
        if "@" in netloc:
            netloc = netloc.split("@", 1)[1]
        target = netloc
    return target.strip().strip("/")


def host_only(target: str) -> str:
    """Strip any ``:port`` suffix and return the bare hostname/IP."""
    target = normalize_target(target)
    if target.startswith("["):
        # IPv6 literal '[::1]:port'
        end = target.find("]")
        return target[: end + 1] if end > 0 else target
    if target.count(":") == 1:
        return target.split(":", 1)[0]
    return target


def host_port(target: str) -> Optional[int]:
    """Extract the explicit port from a target if any, else ``None``."""
    target = normalize_target(target)
    if target.count(":") == 1:
        try:
            return int(target.split(":", 1)[1])
        except ValueError:
            return None
    return None


def build_base_url(host: str, port: int) -> str:
    if port in (443, 8443):
        return f"https://{host}:{port}" if port != 443 else f"https://{host}"
    return f"http://{host}:{port}" if port != 80 else f"http://{host}"
