"""v1.1 backend tests: exploit listing, vuln scan against local vulnserver, validation."""
import os
import time

import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL").rstrip("/")
BB = f"{BASE_URL}/api/bb"

# Minimum exploits that MUST be advertised by /api/bb/exploits
REQUIRED_EXPLOITS = {"sqli", "xss", "cmdi", "lfi", "csrf", "cors", "git", "backups", "wordpress"}

# Finding types we expect at least one of after scanning the vulnserver
REQUIRED_FINDING_TYPES = {
    "xss_reflected",
    "command_injection",
    "lfi",
    "open_redirect",
    "csrf_missing",
    "insecure_cookie",
    "dir_listing",
    "dangerous_methods",
    "git_exposure",
    "backup_file",
    "wp_user_enum",
}
# At least one of these two SQLi indicators
SQLI_TYPES = {"sqli_error", "sqli_boolean"}


@pytest.fixture(scope="module")
def session():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


def _wait(session, job_id, timeout=120):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        r = session.get(f"{BB}/scans/{job_id}", timeout=15)
        assert r.status_code == 200, r.text
        last = r.json()
        if last.get("status") in ("completed", "failed"):
            return last
        time.sleep(2)
    pytest.fail(f"timeout, last status={last and last.get('status')}")


# ----- /api/bb/exploits -----
class TestExploitsEndpoint:
    def test_exploits_returns_available_list(self, session):
        r = session.get(f"{BB}/exploits", timeout=10)
        assert r.status_code == 200
        body = r.json()
        assert "available" in body and isinstance(body["available"], list)
        missing = REQUIRED_EXPLOITS - set(body["available"])
        assert not missing, f"missing exploits: {missing}"


# ----- Validation of new fields -----
class TestScanValidation:
    def test_unknown_exploit_returns_400(self, session):
        r = session.post(
            f"{BB}/scans",
            json={
                "target": "127.0.0.1:9999",
                "modules": ["vuln"],
                "i_have_authorization": True,
                "enabled_exploits": ["not_a_real_exploit"],
            },
            timeout=15,
        )
        assert r.status_code == 400
        assert "not_a_real_exploit" in (r.json().get("detail") or "")

    def test_accepts_new_fields(self, session):
        # just enqueue; this validates the schema accepts cookies/headers/crawl/login_*
        r = session.post(
            f"{BB}/scans",
            json={
                "target": "127.0.0.1:9999",
                "modules": ["vuln"],
                "i_have_authorization": True,
                "with_whois": False,
                "cookies": {"PHPSESSID": "test", "security": "low"},
                "headers": {"X-Test": "1"},
                "crawl_depth": 1,
                "crawl_max_pages": 5,
                "enabled_exploits": ["sqli", "xss"],
                "login_url": "http://127.0.0.1:9999/login",
                "login_user": "admin",
                "login_password": "admin",
                "timeout": 5,
            },
            timeout=15,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] in ("queued", "running")
        # let it terminate to keep things tidy but we don't assert on findings
        _wait(session, body["id"], timeout=120)


# ----- E2E against the local vulnserver -----
@pytest.fixture(scope="module")
def vuln_scan(session):
    payload = {
        "target": "127.0.0.1:9999",
        "modules": ["vuln"],
        "with_whois": False,
        "i_have_authorization": True,
        "timeout": 8,
        "crawl_depth": 1,
        "crawl_max_pages": 15,
    }
    r = session.post(f"{BB}/scans", json=payload, timeout=15)
    assert r.status_code == 200, r.text
    job = r.json()
    final = _wait(session, job["id"], timeout=180)
    assert final["status"] == "completed", f"status={final.get('status')} err={final.get('error')}"
    return final


class TestVulnE2E:
    def test_finding_types_present(self, vuln_scan):
        vuln = (vuln_scan.get("result") or {}).get("vuln") or {}
        findings = vuln.get("findings") or []
        assert findings, "no findings returned"
        types = {f.get("type") for f in findings}
        missing = REQUIRED_FINDING_TYPES - types
        assert not missing, f"missing finding types: {missing}; got {sorted(types)}"
        assert types & SQLI_TYPES, f"no sqli_error/sqli_boolean; got {sorted(types)}"

    def test_severity_counts(self, vuln_scan):
        counts = (vuln_scan.get("result") or {}).get("vuln", {}).get("counts") or {}
        assert counts.get("critical", 0) >= 2, f"critical>=2 required, got {counts}"
        assert counts.get("high", 0) >= 4, f"high>=4 required, got {counts}"

    def test_markdown_report_has_vulnerabilities_section(self, session, vuln_scan):
        r = session.get(
            f"{BB}/scans/{vuln_scan['id']}/report",
            params={"fmt": "md"}, timeout=15,
        )
        assert r.status_code == 200
        content = r.json().get("content") or ""
        assert "Vulnerabilities" in content, "md report missing 'Vulnerabilities' section"
