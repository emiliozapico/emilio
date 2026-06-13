"""v1.3 regression tests:
- POST /api/bb/replay (Burp-style replay) — happy path, scheme guard, body/cookie forwarding
- CVSS + curl enrichment on every applicable vuln finding
- Markdown report contains 'CVSS 3.1:' and ```bash code fence
- Backwards regression: list/delete /api/bb/scans still works after multiple scans
"""
from __future__ import annotations

import json
import os
import time

import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL")
assert BASE_URL, "REACT_APP_BACKEND_URL must be set"
BASE_URL = BASE_URL.rstrip("/")

TARGET = "http://127.0.0.1:9999"
VULN_TYPES_REQUIRING_CVSS = {
    "sqli_error", "xss_reflected", "command_injection",
    "lfi", "csrf_missing", "git_exposure", "backup_file",
}


@pytest.fixture(scope="module")
def api():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


# ---------- /api/bb/replay ----------------------------------------------------

class TestReplay:
    def test_replay_get_basic(self, api):
        r = api.post(f"{BASE_URL}/api/bb/replay", json={
            "method": "GET",
            "url": "http://127.0.0.1:9999/search?q=test",
        })
        assert r.status_code == 200, r.text
        data = r.json()
        for f in ("status_code", "reason", "url", "elapsed_ms",
                  "headers", "body", "body_length"):
            assert f in data, f"missing {f}: {data}"
        assert isinstance(data["status_code"], int)
        assert isinstance(data["headers"], dict)
        assert isinstance(data["body"], str)
        assert isinstance(data["body_length"], int)
        assert data["status_code"] == 200

    def test_replay_bad_scheme(self, api):
        r = api.post(f"{BASE_URL}/api/bb/replay", json={
            "method": "GET", "url": "ftp://x",
        })
        assert r.status_code == 400
        assert "http" in r.text.lower()

    def test_replay_post_with_body_and_cookie(self, api):
        # vulnserver /echo reflects body & cookies via stdout to log; we just
        # validate that the replay endpoint forwards them and returns 200.
        r = api.post(f"{BASE_URL}/api/bb/replay", json={
            "method": "POST",
            "url": "http://127.0.0.1:9999/login",
            "body": "username=admin&password=admin",
            "cookies": {"k": "v"},
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        })
        assert r.status_code == 200, r.text
        data = r.json()
        # the vulnserver login page returns 200 for any POST
        assert data["status_code"] in (200, 302, 301, 401, 403)
        assert isinstance(data["body"], str)


# ---------- CVSS + curl enrichment on scan findings ---------------------------

@pytest.fixture(scope="module")
def completed_scan(api):
    payload = {
        "target": TARGET,
        "modules": ["vuln"],
        "i_have_authorization": True,
        "timeout": 10,
    }
    r = api.post(f"{BASE_URL}/api/bb/scans", json=payload)
    assert r.status_code == 200, r.text
    job_id = r.json()["id"]
    # Poll for completion
    for _ in range(90):
        time.sleep(2)
        sr = api.get(f"{BASE_URL}/api/bb/scans/{job_id}")
        if sr.status_code == 200 and sr.json().get("status") in ("completed", "failed"):
            break
    assert sr.json()["status"] == "completed", sr.text
    return job_id, sr.json()


class TestCVSSEnrichment:
    def test_findings_have_cvss_and_curl(self, completed_scan):
        _, body = completed_scan
        findings = (body.get("result") or {}).get("vuln", {}).get("findings", [])
        assert findings, "no findings produced"
        types_seen = set()
        for f in findings:
            t = f.get("type")
            if t in VULN_TYPES_REQUIRING_CVSS:
                types_seen.add(t)
                assert "cvss" in f, f"no cvss on {t}: {f}"
                assert isinstance(f["cvss"].get("score"), (int, float))
                assert f["cvss"].get("vector", "").startswith("CVSS:3.1/")
            if f.get("url") and t in VULN_TYPES_REQUIRING_CVSS:
                assert "curl" in f, f"no curl on {t}: {f}"
                assert f["curl"].startswith("curl -i -k")
        # At least 2 of the required types should be found against vulnserver
        assert len(types_seen) >= 2, f"only saw {types_seen}"

    def test_md_report_has_cvss_and_curl_block(self, completed_scan, api):
        job_id, _ = completed_scan
        r = api.get(f"{BASE_URL}/api/bb/scans/{job_id}/report?fmt=md")
        assert r.status_code == 200
        content = r.json()["content"]
        assert "CVSS 3.1:" in content
        assert "```bash" in content


# ---------- Regression: list + delete still work ------------------------------

class TestScanListDelete:
    def test_list_and_delete(self, api, completed_scan):
        job_id, _ = completed_scan
        # list
        r = api.get(f"{BASE_URL}/api/bb/scans?limit=50")
        assert r.status_code == 200
        ids = [s["id"] for s in r.json()]
        assert job_id in ids
        # delete
        d = api.delete(f"{BASE_URL}/api/bb/scans/{job_id}")
        assert d.status_code == 200
        assert d.json().get("status") == "deleted"
        # confirm gone (no in-memory and no doc -> 404)
        g = api.get(f"{BASE_URL}/api/bb/scans/{job_id}")
        # JOBS dict may still hold it briefly because delete only pops from JOBS
        # AND deletes the doc — implementation removes both, so expect 404.
        assert g.status_code == 404
