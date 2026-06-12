"""CLI tests for /app/bugbounty_tool/bugbounty_tool.py."""
import json
import subprocess
import sys
from pathlib import Path

CLI = str(Path("/app/bugbounty_tool/bugbounty_tool.py"))


def _run(args, timeout=120):
    return subprocess.run(
        [sys.executable, CLI, *args],
        capture_output=True, text=True, timeout=timeout,
    )


class TestCLI:
    def test_help_shows_subcommands(self):
        r = _run(["--help"], timeout=15)
        assert r.returncode == 0
        out = r.stdout + r.stderr
        for sub in ("recon", "scan", "vuln", "all"):
            assert sub in out, f"missing subcommand '{sub}' in --help"

    def test_refuses_without_authorization(self):
        r = _run(["scan", "-t", "example.com"], timeout=15)
        assert r.returncode != 0, "CLI must exit non-zero without --i-have-authorization"
        assert "i-have-authorization" in (r.stderr + r.stdout).lower() \
            or "refusing" in (r.stderr + r.stdout).lower()

    def test_scan_json_output(self, tmp_path):
        out = tmp_path / "scan.json"
        r = _run([
            "scan", "-t", "example.com",
            "--i-have-authorization",
            "--output-format", "json",
            "--output", str(out),
        ], timeout=120)
        assert r.returncode == 0, f"scan failed: {r.stderr}"
        data = json.loads(out.read_text())
        assert "scan" in data, "Expected 'scan' key in JSON report"
        assert isinstance(data["scan"].get("ports"), list)
