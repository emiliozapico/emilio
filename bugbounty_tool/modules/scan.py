"""Port scanning, banner grabbing and version detection."""
from __future__ import annotations

import time
from typing import Callable, Dict, List, Optional

from ..utils import network, parsers, helpers
from ..utils.session import HttpContext

log = helpers.get_logger()

DEFAULT_WEB_PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000]


def scan_port(host: str, port: int, ctx: HttpContext, timeout: float = 2.0) -> Dict:
    is_open = network.tcp_connect(host, port, timeout=timeout)
    result: Dict = {"port": port, "open": is_open, "banner": None,
                    "server": None, "technologies": []}
    if not is_open:
        return result
    base = network.build_base_url(host, port)
    response = network.safe_get(base, ctx=ctx, retries=0, timeout=int(timeout) + 3)
    if response is None:
        return result
    headers = {k: v for k, v in response.headers.items()}
    result["status_code"] = response.status_code
    result["url"] = response.url
    server = headers.get("Server") or headers.get("server")
    if server:
        result["server"] = server
        result["banner"] = server
    result["headers"] = headers
    result["technologies"] = parsers.detect_technologies(headers, response.text or "")
    return result


def scan_ports(
    host: str,
    ctx: HttpContext,
    ports: Optional[List[int]] = None,
    timeout: float = 2.0,
    on_progress: Optional[Callable[[str], None]] = None,
) -> List[Dict]:
    ports = ports if ports else DEFAULT_WEB_PORTS
    progress = on_progress or (lambda msg: log.info(msg))
    results: List[Dict] = []
    for port in ports:
        progress(f"scanning {host}:{port}")
        result = scan_port(host, port, ctx, timeout=timeout)
        if result["open"]:
            progress(
                f"OPEN {host}:{port} -> {helpers.truncate(result.get('server') or 'no server header', 80)}"
            )
        results.append(result)
        if ctx.delay > 0:
            time.sleep(ctx.delay)
    return results


def run_scan(
    target: str,
    ctx: HttpContext,
    *,
    ports: Optional[List[int]] = None,
    timeout: float = 2.0,
    on_progress: Optional[Callable[[str], None]] = None,
) -> Dict:
    target = network.normalize_target(target)
    host = network.host_only(target)
    explicit_port = network.host_port(target)
    if explicit_port is not None and ports is None:
        ports = [explicit_port]
    ip = network.resolve_host(host) or host
    progress = on_progress or (lambda msg: log.info(msg))
    progress(f"resolved {host} -> {ip}")
    open_ports = scan_ports(ip, ctx, ports=ports, timeout=timeout, on_progress=progress)
    return {
        "target": target,
        "ip": ip,
        "ports": open_ports,
        "open_count": sum(1 for p in open_ports if p["open"]),
    }
