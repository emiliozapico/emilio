"""Reporting: render results to plain text, JSON or Markdown."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Dict, List


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def _sort_findings(findings: List[Dict]) -> List[Dict]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get((f.get("severity") or "unknown").lower(), 5))


def _general_recommendations(findings: List[Dict]) -> List[str]:
    recs = set()
    for f in findings:
        t = f.get("type")
        if t == "missing_header":
            recs.add("Enable the missing security headers at the web-server or framework level.")
        elif t == "version_disclosure":
            recs.add("Remove or anonymize the Server / X-Powered-By headers.")
        elif t == "exposed_file":
            recs.add("Block access to dotfiles and configuration files at the web-server level.")
        elif t == "cve":
            recs.add("Patch or upgrade vulnerable software to a supported release.")
        elif t == "sensitive_comment":
            recs.add("Strip HTML comments at build time in production.")
        elif t == "weak_credentials":
            recs.add("Enforce strong-password policy and brute-force lockout / MFA on login forms.")
    if not recs:
        recs.add("No findings detected, but periodic re-scanning is recommended.")
    return sorted(recs)


def to_json(result: Dict) -> str:
    return json.dumps(result, indent=2, sort_keys=True, default=str)


def to_text(result: Dict) -> str:
    lines: List[str] = []
    meta = result.get("meta", {})
    lines.append("=" * 70)
    lines.append(f" Bug-Bounty Toolkit report")
    lines.append(f" Target:    {meta.get('target')}")
    lines.append(f" Generated: {meta.get('generated_at')}")
    lines.append(f" Modules:   {', '.join(meta.get('modules', []))}")
    lines.append("=" * 70)

    recon = result.get("recon") or {}
    if recon:
        lines.append("")
        lines.append("[RECON]")
        lines.append(f"  IP:           {recon.get('ip')}")
        lines.append(f"  Base URL:     {recon.get('base_url')}")
        lines.append(f"  Subdomains:   {len(recon.get('subdomains', []))}")
        for sd in recon.get("subdomains", [])[:50]:
            lines.append(f"    - {sd}")
        techs = recon.get("technologies", [])
        lines.append(f"  Technologies: {len(techs)}")
        for t in techs:
            lines.append(f"    - {t['name']} {t.get('version') or ''} ({t.get('source')})")
        dirs = recon.get("directories", [])
        lines.append(f"  Directories found: {len(dirs)}")
        for d in dirs:
            lines.append(f"    - [{d['status_code']}] {d['url']} ({d['length']} bytes)")
        lines.append(f"  Forms found:  {len(recon.get('forms', []))}")
        lines.append(f"  Parameters:   {len(recon.get('url_params', []))}")
        whois_data = recon.get("whois") or {}
        if whois_data and not whois_data.get("error"):
            lines.append("  WHOIS:")
            for k, v in whois_data.items():
                lines.append(f"    {k}: {v}")

    scan = result.get("scan") or {}
    if scan:
        lines.append("")
        lines.append("[SCAN]")
        for p in scan.get("ports", []):
            if p.get("open"):
                lines.append(
                    f"  Port {p['port']:<5} OPEN  server='{p.get('server') or ''}'"
                )
                for t in p.get("technologies", []):
                    lines.append(f"      tech: {t['name']} {t.get('version') or ''}")
            else:
                lines.append(f"  Port {p['port']:<5} closed")

    vuln = result.get("vuln") or {}
    if vuln:
        lines.append("")
        lines.append("[VULNERABILITIES]")
        counts = vuln.get("counts", {})
        lines.append("  Summary: " + ", ".join(
            f"{k}={v}" for k, v in counts.items() if v
        ) or "  No findings")
        for f in _sort_findings(vuln.get("findings", [])):
            lines.append(f"  [{f['severity'].upper():<8}] {f['title']}")
            if f.get("cvss"):
                lines.append(f"      cvss:      {f['cvss']['score']} ({f['cvss']['vector']})")
            if f.get("description"):
                lines.append(f"      {f['description']}")
            if f.get("url"):
                lines.append(f"      url:       {f['url']}")
            if f.get("evidence"):
                lines.append(f"      evidence:  {f['evidence']}")
            if f.get("reference"):
                lines.append(f"      reference: {f['reference']}")
            if f.get("curl"):
                lines.append(f"      reproduce: {f['curl']}")

        lines.append("")
        lines.append("[RECOMMENDATIONS]")
        for r in _general_recommendations(vuln.get("findings", [])):
            lines.append(f"  - {r}")

    return "\n".join(lines)


def to_markdown(result: Dict) -> str:
    lines: List[str] = []
    meta = result.get("meta", {})
    lines.append(f"# Bug-Bounty Toolkit Report")
    lines.append("")
    lines.append(f"- **Target:** `{meta.get('target')}`")
    lines.append(f"- **Generated:** {meta.get('generated_at')}")
    lines.append(f"- **Modules:** {', '.join(meta.get('modules', []))}")
    lines.append("")

    recon = result.get("recon") or {}
    if recon:
        lines.append("## Reconnaissance")
        lines.append("")
        lines.append(f"- IP: `{recon.get('ip')}`")
        lines.append(f"- Base URL: `{recon.get('base_url')}`")
        lines.append(f"- Subdomains discovered: **{len(recon.get('subdomains', []))}**")
        if recon.get("subdomains"):
            lines.append("")
            for sd in recon["subdomains"][:100]:
                lines.append(f"  - `{sd}`")
        techs = recon.get("technologies", [])
        if techs:
            lines.append("")
            lines.append("### Technologies")
            lines.append("")
            lines.append("| Name | Version | Source |")
            lines.append("|------|---------|--------|")
            for t in techs:
                lines.append(f"| {t['name']} | {t.get('version') or '-'} | {t.get('source') or '-'} |")
        dirs = recon.get("directories", [])
        if dirs:
            lines.append("")
            lines.append("### Directories / Files")
            lines.append("")
            lines.append("| Status | URL | Size |")
            lines.append("|--------|-----|------|")
            for d in dirs:
                lines.append(f"| {d['status_code']} | `{d['url']}` | {d['length']} |")
        lines.append("")

    scan = result.get("scan") or {}
    if scan:
        lines.append("## Port Scan")
        lines.append("")
        lines.append("| Port | State | Server | Technologies |")
        lines.append("|------|-------|--------|--------------|")
        for p in scan.get("ports", []):
            techs = ", ".join(
                f"{t['name']} {t.get('version') or ''}".strip() for t in p.get("technologies", [])
            ) or "-"
            lines.append(
                f"| {p['port']} | {'open' if p.get('open') else 'closed'} | "
                f"{p.get('server') or '-'} | {techs} |"
            )
        lines.append("")

    vuln = result.get("vuln") or {}
    if vuln:
        lines.append("## Vulnerabilities")
        lines.append("")
        counts = vuln.get("counts", {})
        lines.append(
            "**Summary:** " + ", ".join(f"`{k}`={v}" for k, v in counts.items() if v)
            or "No findings."
        )
        lines.append("")
        for f in _sort_findings(vuln.get("findings", [])):
            lines.append(f"### {f['severity'].upper()} — {f['title']}")
            if f.get("cvss"):
                lines.append("")
                lines.append(f"**CVSS 3.1:** {f['cvss']['score']} ({f['cvss']['severity']}) — `{f['cvss']['vector']}`")
            if f.get("description"):
                lines.append("")
                lines.append(f["description"])
            details = []
            if f.get("url"):
                details.append(f"- URL: `{f['url']}`")
            if f.get("evidence"):
                details.append(f"- Evidence: `{f['evidence']}`")
            if f.get("reference"):
                details.append(f"- Reference: [{f['reference']}]({f['reference']})")
            if details:
                lines.append("")
                lines.extend(details)
            if f.get("curl"):
                lines.append("")
                lines.append("```bash")
                lines.append(f["curl"])
                lines.append("```")
            lines.append("")

        lines.append("## Recommendations")
        lines.append("")
        for r in _general_recommendations(vuln.get("findings", [])):
            lines.append(f"- {r}")
        lines.append("")
    return "\n".join(lines)


def build_meta(target: str, modules: List[str]) -> Dict:
    return {
        "target": target,
        "modules": modules,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "bugbounty-toolkit",
        "version": "1.0.0",
    }


def render(result: Dict, fmt: str) -> str:
    fmt = (fmt or "txt").lower()
    if fmt in ("json",):
        return to_json(result)
    if fmt in ("md", "markdown"):
        return to_markdown(result)
    return to_text(result)
