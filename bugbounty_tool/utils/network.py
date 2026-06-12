"""Network helpers shared across modules.

All HTTP traffic in this tool goes through :func:`safe_get` so we have a single
place to configure timeouts, retries, User-Agent, and inter-request delays.
"""
from __future__ import annotations

import socket
import time
from typing import Optional
from urllib.parse import urlparse

import requests

DEFAULT_UA = (
    "BugBountyToolkit/1.0 (+authorized-testing-only; "
    "https://github.com/example/bugbounty-toolkit)"
)


def safe_get(
    url: str,
    timeout: int = 10,
    retries: int = 2,
    delay: float = 0.0,
    headers: Optional[dict] = None,
    allow_redirects: bool = True,
    verify: bool = True,
) -> Optional[requests.Response]:
    """Issue an HTTP GET with retries and a polite default User-Agent.

    Returns the :class:`requests.Response` on success or ``None`` if every
    attempt failed. Never raises.
    """
    final_headers = {"User-Agent": DEFAULT_UA}
    if headers:
        final_headers.update(headers)

    last_exc: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            response = requests.get(
                url,
                timeout=timeout,
                headers=final_headers,
                allow_redirects=allow_redirects,
                verify=verify,
            )
            if delay > 0:
                time.sleep(delay)
            return response
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(min(2 ** attempt, 5))
                continue
    if last_exc is not None:
        # Swallow but expose via attribute on None? Simpler: just return None.
        pass
    return None


def resolve_host(host: str) -> Optional[str]:
    """Resolve a hostname to a single IPv4 address, ``None`` on failure."""
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return None


def tcp_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    """Return ``True`` if a TCP connection to ``host:port`` succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def normalize_target(target: str) -> str:
    """Return a bare hostname (strip scheme, path, port)."""
    if "://" in target:
        parsed = urlparse(target)
        target = parsed.hostname or target
    return target.strip().strip("/")


def build_base_url(host: str, port: int) -> str:
    """Build an http(s) base URL given a host and a known web port."""
    if port in (443, 8443):
        return f"https://{host}:{port}" if port != 443 else f"https://{host}"
    return f"http://{host}:{port}" if port != 80 else f"http://{host}"
