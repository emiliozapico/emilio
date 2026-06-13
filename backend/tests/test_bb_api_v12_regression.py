"""v1.2 regression tests: verify the two critical bugs from iteration_2 are fixed.

1) Motor 'Event loop is closed' on GET /api/bb/scans & DELETE /api/bb/scans/{id}
   after a scan completes (caused by asyncio.run() in worker thread).
2) normalize_target stripping :port when the target has a scheme.
"""
import os
import time

import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL").rstrip("/")
BB = f"{BASE_URL}/api/bb"

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
SQLI_TYPES = {"sqli_error", "sqli_boolean"}


@pytest.fixture(scope="module")
def session():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


def _wait(session, job_id, timeout=180):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        r = session.get(f"{BB}/scans/{job_id}", timeout=20)
        assert r.status_code == 200, r.text
        last = r.json()
        if last.get("status") in ("completed", "failed"):
            return last
        time.sleep(2)
    pytest.fail(f"timeout, last status={last and last.get('status')}")


def _run_scan(session, target):
    payload = {
        "target": target,
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
    final = _wait(session, job["id"], timeout=240)
    assert final["status"] == "completed", f"status={final.get('status')} err={final.get('error')}"
    return final


class TestNormalizeTargetPortPreserved:
    """Bug #2: normalize_target now preserves :port even when scheme is given."""

    def test_scan_with_host_port_no_scheme(self, session):
        final = _run_scan(session, "127.0.0.1:9999")
        findings = (final.get("result") or {}).get("vuln", {}).get("findings") or []
        types = {f.get("type") for f in findings}
        missing = REQUIRED_FINDING_TYPES - types
        assert not missing, f"missing finding types (host:port): {missing}; got {sorted(types)}"
        assert types & SQLI_TYPES, f"no sqli; got {sorted(types)}"

    def test_scan_with_scheme_and_port(self, session):
        final = _run_scan(session, "http://127.0.0.1:9999")
        findings = (final.get("result") or {}).get("vuln", {}).get("findings") or []
        types = {f.get("type") for f in findings}
        missing = REQUIRED_FINDING_TYPES - types
        assert not missing, f"missing finding types (http://host:port): {missing}; got {sorted(types)}"
        assert types & SQLI_TYPES, f"no sqli with scheme; got {sorted(types)}"


class TestMotorLoopRegression:
    """Bug #1: list and delete should work AFTER a scan completes."""

    def test_list_scans_after_completed_scan(self, session):
        # The two scans above already completed in this module run order.
        # Ensure list returns 200 and contains both.
        r = session.get(f"{BB}/scans", timeout=15)
        assert r.status_code == 200, f"GET /api/bb/scans returned {r.status_code}: {r.text}"
        items = r.json()
        assert isinstance(items, list)
        # We just need >=2 entries with completed status
        completed = [i for i in items if i.get("status") == "completed"]
        assert len(completed) >= 2, f"expected at least 2 completed scans in list, got {len(completed)}: {items}"

    def test_delete_scan_after_completion(self, session):
        # Run one more scan and then DELETE it.
        final = _run_scan(session, "127.0.0.1:9999")
        job_id = final["id"]
        r = session.delete(f"{BB}/scans/{job_id}", timeout=15)
        assert r.status_code == 200, f"DELETE returned {r.status_code}: {r.text}"
        body = r.json()
        assert body.get("status") == "deleted"
        # Confirm subsequent GET returns 404
        r2 = session.get(f"{BB}/scans/{job_id}", timeout=15)
        assert r2.status_code == 404


class TestExploitValidationStillWorks:
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
