"""Internal CVE knowledge base.

This is a *small, curated* offline database of well-known vulnerabilities used
when the tool detects a specific (technology, version) pair. It is intentionally
limited; for production use a real vulnerability feed (NVD, OSV, etc.).
"""

from typing import List, Dict


CVE_DB: Dict[str, Dict[str, List[Dict]]] = {
    "apache": {
        "2.4.49": [{
            "id": "CVE-2021-41773",
            "desc": "Apache HTTP Server 2.4.49 path traversal & RCE",
            "severity": "critical",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        }],
        "2.4.50": [{
            "id": "CVE-2021-42013",
            "desc": "Apache HTTP Server 2.4.50 path traversal & RCE (incomplete fix of 41773)",
            "severity": "critical",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
        }],
        "2.4.41": [{
            "id": "CVE-2020-11984",
            "desc": "mod_proxy_uwsgi buffer overflow in Apache 2.4.32-2.4.44",
            "severity": "high",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-11984",
        }],
    },
    "nginx": {
        "1.18.0": [{
            "id": "CVE-2021-23017",
            "desc": "Off-by-one in nginx resolver leading to DoS / potential RCE",
            "severity": "high",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
        }],
        "1.20.0": [{
            "id": "CVE-2021-23017",
            "desc": "Off-by-one in nginx resolver leading to DoS / potential RCE",
            "severity": "high",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
        }],
    },
    "openssl": {
        "1.0.1": [{
            "id": "CVE-2014-0160",
            "desc": "Heartbleed - information disclosure in OpenSSL TLS heartbeat",
            "severity": "critical",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
        }],
    },
    "php": {
        "7.4.0": [{
            "id": "CVE-2019-11043",
            "desc": "PHP-FPM remote code execution under nginx",
            "severity": "critical",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2019-11043",
        }],
        "5.6.0": [{
            "id": "CVE-2019-11034",
            "desc": "PHP EXIF heap buffer over-read",
            "severity": "medium",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2019-11034",
        }],
    },
    "wordpress": {
        "5.7": [{
            "id": "CVE-2021-29447",
            "desc": "WordPress 5.7 media library XXE via WAV file upload",
            "severity": "high",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-29447",
        }],
        "4.7.0": [{
            "id": "CVE-2017-1001000",
            "desc": "WordPress REST API content injection / unauthenticated post update",
            "severity": "critical",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2017-1001000",
        }],
    },
    "drupal": {
        "7.58": [{
            "id": "CVE-2018-7600",
            "desc": "Drupalgeddon2 - Drupal core RCE",
            "severity": "critical",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2018-7600",
        }],
    },
    "joomla": {
        "3.4.5": [{
            "id": "CVE-2015-8562",
            "desc": "Joomla! object injection RCE",
            "severity": "critical",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2015-8562",
        }],
    },
    "jquery": {
        "1.12.4": [{
            "id": "CVE-2020-11022",
            "desc": "jQuery XSS via HTML containing <option> elements",
            "severity": "medium",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-11022",
        }],
        "3.4.0": [{
            "id": "CVE-2020-11023",
            "desc": "jQuery XSS via HTML containing <option> elements (regression)",
            "severity": "medium",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-11023",
        }],
    },
    "bootstrap": {
        "3.3.7": [{
            "id": "CVE-2019-8331",
            "desc": "Bootstrap XSS in tooltip / popover data-template attribute",
            "severity": "medium",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2019-8331",
        }],
        "4.0.0": [{
            "id": "CVE-2018-14041",
            "desc": "Bootstrap XSS in collapse data-parent attribute",
            "severity": "medium",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2018-14041",
        }],
    },
    "django": {
        "3.2.0": [{
            "id": "CVE-2021-35042",
            "desc": "Django QuerySet.order_by SQL injection",
            "severity": "high",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-35042",
        }],
        "2.2.0": [{
            "id": "CVE-2019-19844",
            "desc": "Django account takeover via password reset (unicode case folding)",
            "severity": "high",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2019-19844",
        }],
    },
    "tomcat": {
        "9.0.0": [{
            "id": "CVE-2020-1938",
            "desc": "Ghostcat - Apache Tomcat AJP file inclusion / RCE",
            "severity": "critical",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-1938",
        }],
    },
    "iis": {
        "7.5": [{
            "id": "CVE-2017-7269",
            "desc": "Microsoft IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow",
            "severity": "high",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2017-7269",
        }],
    },
}


def _normalize(name: str) -> str:
    return (name or "").strip().lower()


def get_cves_for_technology(tech_name: str, tech_version: str) -> List[Dict]:
    """Return the list of CVEs for an exact (tech, version) pair.

    The lookup is intentionally simple (exact match). A real implementation
    would parse semver ranges or query an external feed.
    """
    name = _normalize(tech_name)
    version = (tech_version or "").strip()
    if not name or not version:
        return []
    entry = CVE_DB.get(name)
    if not entry:
        return []
    # Exact match first
    if version in entry:
        return entry[version]
    # Best-effort: match by major.minor prefix
    parts = version.split(".")
    while parts:
        prefix = ".".join(parts)
        for known_version, cves in entry.items():
            if known_version.startswith(prefix):
                return cves
        parts.pop()
    return []
