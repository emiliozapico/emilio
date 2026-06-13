"""CVSS 3.1 lookup table per finding type.

CVSS vectors are chosen as a reasonable default for the *typical* exploitation
of each finding category. A real engagement should refine the temporal /
environmental metrics per asset.
"""
from __future__ import annotations

from typing import Dict, Tuple


# (base_score, vector_string)
CVSS_BY_TYPE: Dict[str, Tuple[float, str]] = {
    # SQL injection — high impact on confidentiality+integrity
    "sqli_error":         (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "sqli_boolean":       (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "sqli_time":          (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    # XSS — needs user interaction
    "xss_reflected":      (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    # Command injection — full RCE, scope change
    "command_injection":  (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    # LFI / path traversal
    "lfi":                (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
    # Open redirect
    "open_redirect":      (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    # CRLF
    "crlf":               (7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"),
    # CSRF
    "csrf_missing":       (6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"),
    # Default credentials / weak creds
    "weak_credentials":   (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    # Insecure cookies
    "insecure_cookie":    (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    # CORS misconfig
    "cors_misconfig":     (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    # Directory listing
    "dir_listing":        (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    # Dangerous HTTP methods
    "dangerous_methods":  (5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"),
    # .git exposure — full source disclosure
    "git_exposure":       (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    # Backup file
    "backup_file":        (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    # WordPress user enum
    "wp_user_enum":       (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    # WordPress xmlrpc
    "wp_xmlrpc":          (3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L"),
    # Passive findings
    "exposed_file":       (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "sensitive_comment":  (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "missing_header":     (3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "version_disclosure": (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    # CVE entries — depend on the CVE itself; default to high
    "cve":                (8.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
}


def severity_from_score(score: float) -> str:
    """Map a CVSS 3.1 base score to its qualitative severity bucket."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def cvss_for_finding_type(finding_type: str) -> Dict:
    """Return ``{score, vector, severity}`` for a known type, or empty dict."""
    entry = CVSS_BY_TYPE.get(finding_type)
    if not entry:
        return {}
    score, vector = entry
    return {"score": score, "vector": vector, "severity": severity_from_score(score)}
