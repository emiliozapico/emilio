"""Backend API tests for the bug-bounty toolkit endpoints (/api/bb/*)."""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://test-project-102.preview.emergentagent.com").rstrip("/")
BB = f"{BASE_URL}/api/bb"


# Shared session for connection reuse
@pytest.fixture(scope="module")
def session():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


def _wait_for_complete(session, job_id, timeout=60):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        r = session.get(f"{BB}/scans/{job_id}", timeout=15)
        assert r.status_code == 200, r.text
        last = r.json()
        if last.get("status") in ("completed", "failed"):
            return last
        time.sleep(1.5)
    pytest.fail(f"Scan {job_id} did not finish in {timeout}s; last status={last and last.get('status')}")


# --------- Health endpoint ---------
class TestHealth:
    def test_health_ok(self, session):
        r = session.get(f"{BB}/health", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["service"] == "bugbounty-toolkit"


# --------- Authorization gating & validation ---------
class TestAuthorization:
    def test_create_scan_without_authorization_returns_400(self, session):
        r = session.post(
            f"{BB}/scans",
            json={"target": "example.com", "modules": ["scan"], "i_have_authorization": False},
            timeout=15,
        )
        assert r.status_code == 400
        body = r.json()
        assert "authorization" in (body.get("detail") or "").lower()

    def test_create_scan_unknown_module_returns_400(self, session):
        r = session.post(
            f"{BB}/scans",
            json={
                "target": "example.com",
                "modules": ["scan", "nonexistent_module"],
                "i_have_authorization": True,
            },
            timeout=15,
        )
        assert r.status_code == 400
        assert "nonexistent_module" in (r.json().get("detail") or "")


# --------- End-to-end scan flow ---------
@pytest.fixture(scope="module")
def completed_scan(session):
    payload = {
        "target": "example.com",
        "modules": ["scan", "vuln"],
        "with_whois": False,
        "i_have_authorization": True,
        "timeout": 8,
    }
    r = session.post(f"{BB}/scans", json=payload, timeout=15)
    assert r.status_code == 200, r.text
    job = r.json()
    assert "id" in job and job["status"] in ("queued", "running")
    assert job["target"] == "example.com"
    assert job["modules"] == ["scan", "vuln"]

    final = _wait_for_complete(session, job["id"], timeout=90)
    assert final["status"] == "completed", f"job ended with status={final.get('status')} error={final.get('error')}"
    return final


class TestScanLifecycle:
    def test_scan_result_shape(self, completed_scan):
        res = completed_scan.get("result")
        assert res, "result missing on completed scan"
        # scan module
        scan_block = res.get("scan") or {}
        assert isinstance(scan_block.get("ports"), list), "result.scan.ports must be a list"
        # vuln module
        vuln_block = res.get("vuln") or {}
        assert isinstance(vuln_block.get("findings"), list), "result.vuln.findings must be a list"
        assert isinstance(vuln_block.get("counts"), dict), "result.vuln.counts must be present (dict)"

    def test_list_scans_contains_created(self, session, completed_scan):
        r = session.get(f"{BB}/scans", timeout=15)
        assert r.status_code == 200
        items = r.json()
        assert isinstance(items, list)
        ids = [it.get("id") for it in items]
        assert completed_scan["id"] in ids, "Newly created scan must appear in listing"

    @pytest.mark.parametrize("fmt", ["txt", "json", "md"])
    def test_report_formats_non_empty(self, session, completed_scan, fmt):
        r = session.get(f"{BB}/scans/{completed_scan['id']}/report", params={"fmt": fmt}, timeout=15)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data.get("format") == fmt
        content = data.get("content") or ""
        assert isinstance(content, str) and len(content) > 20, f"report content for {fmt} too small"

    def test_get_scan_by_id_persisted(self, session, completed_scan):
        r = session.get(f"{BB}/scans/{completed_scan['id']}", timeout=15)
        assert r.status_code == 200
        body = r.json()
        assert body.get("id") == completed_scan["id"]
        # progress or status visible
        assert body.get("status") == "completed"


# --------- Delete & cleanup ---------
class TestDelete:
    def test_delete_scan(self, session):
        # create a quick scan with scan-only & no whois then delete
        payload = {
            "target": "example.com",
            "modules": ["scan"],
            "with_whois": False,
            "i_have_authorization": True,
            "timeout": 5,
        }
        r = session.post(f"{BB}/scans", json=payload, timeout=15)
        assert r.status_code == 200
        jid = r.json()["id"]
        _wait_for_complete(session, jid, timeout=60)

        d = session.delete(f"{BB}/scans/{jid}", timeout=15)
        assert d.status_code == 200
        assert d.json().get("status") == "deleted"

        # Verify gone (in-memory removed, persisted removed): list must not contain it
        lst = session.get(f"{BB}/scans", timeout=15).json()
        assert jid not in [it.get("id") for it in lst]
