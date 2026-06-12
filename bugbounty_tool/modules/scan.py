"""Port scanning, banner grabbing and version detection."""
from __future__ import annotations

from typing import Callable, Dict, List, Optional

from ..utils import network, parsers, helpers

log = helpers.get_logger()

DEFAULT_WEB_PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000]


def scan_port(host: str, port: int, timeout: float = 2.0) -> Dict:
    """Probe a single port, returning a dict describing what we found."""
    is_open = network.tcp_connect(host, port, timeout=timeout)
    result: Dict = {"port": port, "open": is_open, "banner": None,
                    "server": None, "technologies": []}
    if not is_open:
        return result

    base = network.build_base_url(host, port)
    response = network.safe_get(base, timeout=int(timeout) + 3, retries=0, verify=False)
    if response is None:
        return result

    headers = {k: v for k, v in response.headers.items()}
    result["status_code"] = response.status_code
    result["url"] = response.url
    if headers.get("Server"):
        result["server"] = headers["Server"]
        result["banner"] = headers["Server"]
    elif headers.get("server"):
        result["server"] = headers["server"]
        result["banner"] = headers["server"]
    result["headers"] = headers
    result["technologies"] = parsers.detect_technologies(headers, response.text or "")
    return result


def scan_ports(
    host: str,
    ports: Optional[List[int]] = None,
    timeout: float = 2.0,
    delay: float = 0.0,
    on_progress: Optional[Callable[[str], None]] = None,
) -> List[Dict]:
    ports = ports if ports else DEFAULT_WEB_PORTS
    progress = on_progress or (lambda msg: log.info(msg))
    results: List[Dict] = []
    for port in ports:
        progress(f"scanning {host}:{port}")
        result = scan_port(host, port, timeout=timeout)
        if result["open"]:
            progress(
                f"OPEN {host}:{port} -> {helpers.truncate(result.get('server') or 'no server header', 80)}"
            )
        results.append(result)
        if delay > 0:
            import time
            time.sleep(delay)
    return results


def run_scan(
    target: str,
    *,
    ports: Optional[List[int]] = None,
    timeout: float = 2.0,
    delay: float = 0.0,
    on_progress: Optional[Callable[[str], None]] = None,
) -> Dict:
    target = network.normalize_target(target)
    ip = network.resolve_host(target) or target
    progress = on_progress or (lambda msg: log.info(msg))
    progress(f"resolved {target} -> {ip}")
    open_ports = scan_ports(
        ip, ports=ports, timeout=timeout, delay=delay, on_progress=progress
    )
    return {
        "target": target,
        "ip": ip,
        "ports": open_ports,
        "open_count": sum(1 for p in open_ports if p["open"]),
    }
