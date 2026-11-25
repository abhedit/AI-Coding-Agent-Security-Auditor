"""Command-line interface: `agent-auditor scan <path>` (local) or `--remote` (SaaS API)."""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request

from . import __version__
from .models import Severity
from .sarif import to_sarif
from .scanner import scan_path, rule_catalog, ScanResult
from . import discovery

COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
RESET = "\033[0m"


def _fmt_text(result: ScanResult, color: bool) -> str:
    c = (lambda s, t: f"{COLORS[s]}{t}{RESET}") if color else (lambda s, t: t)
    out = [f"AI Coding Agent Security Auditor v{__version__}",
           f"Scanned {len(result.files)} agent config file(s); agents: {', '.join(result.agents) or 'none detected'}", ""]
    for f in result.findings:
        out.append(f"{c(f.severity.value, f.severity.value.upper().ljust(8))} {f.rule_id}  {f.file}:{f.line}")
        out.append(f"         {f.title}: {f.message}")
        if f.evidence:
            out.append(f"         > {f.evidence}")
        out.append(f"         fix: {f.remediation}")
        out.append("")
    counts = ", ".join(f"{k}: {v}" for k, v in result.counts.items() if v)
    out.append(f"Score {result.score}/100 (grade {result.grade}) - {len(result.findings)} finding(s){' (' + counts + ')' if counts else ''}")
    return "\n".join(out)


def _remote(path: str, api_url: str, api_key: str, project: str | None, exclude: list[str]) -> dict:
    files = {sf.path: sf.content for sf in discovery.discover(path, exclude)}
    body = json.dumps({"files": files, "project": project, "source": "cli"}).encode()
    req = urllib.request.Request(api_url.rstrip("/") + "/api/v1/scans", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agent-auditor", description="Audit AI coding agent configuration for security risks.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a directory")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    s.add_argument("-o", "--output", help="write report to file")
    s.add_argument("--fail-on", choices=[x.value for x in Severity] + ["none"], default="high",
                   help="exit non-zero when a finding at or above this severity exists (default: high)")
    s.add_argument("--disable", default="", help="comma-separated rule IDs to skip")
    s.add_argument("--exclude", action="append", default=[], help="path or glob to skip (repeatable), e.g. tests/fixtures")
    s.add_argument("--remote", action="store_true", help="upload to the SaaS API (needs AGENT_AUDITOR_API_KEY) to record history")
    s.add_argument("--api-url", default=os.environ.get("AGENT_AUDITOR_API_URL", "http://localhost:8000"))
    s.add_argument("--project", default=os.environ.get("AGENT_AUDITOR_PROJECT"))
    sub.add_parser("rules", help="list all rules")
    sub.add_parser("version")
    a = p.parse_args(argv)

    if a.cmd == "version":
        print(__version__)
        return 0
    if a.cmd == "rules":
        for r in rule_catalog():
            print(f"{r['id']:<12} {r['severity']:<9} {r['category']:<18} {r['title']}")
        return 0

    disabled = {x.strip() for x in a.disable.split(",") if x.strip()}
    result = scan_path(a.path, disabled, a.exclude)
    if a.remote:
        key = os.environ.get("AGENT_AUDITOR_API_KEY")
        if not key:
            print("AGENT_AUDITOR_API_KEY is not set", file=sys.stderr)
            return 2
        resp = _remote(a.path, a.api_url, key, a.project, a.exclude)
        print(f"Uploaded scan #{resp.get('id')} - report: {resp.get('report_url')}", file=sys.stderr)

    if a.format == "json":
        text = json.dumps(result.to_dict(), indent=2)
    elif a.format == "sarif":
        text = json.dumps(to_sarif(result, version=__version__), indent=2)
    else:
        text = _fmt_text(result, color=sys.stdout.isatty() and not a.output)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        print(text)

    if a.fail_on != "none":
        threshold = Severity(a.fail_on).rank
        if any(f.severity.rank >= threshold for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
