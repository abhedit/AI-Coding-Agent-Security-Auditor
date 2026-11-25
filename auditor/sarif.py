"""SARIF 2.1.0 output for GitHub code scanning and other SAST dashboards."""
from __future__ import annotations

from .models import Severity
from .rules import RULES
from .scanner import ScanResult

LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
SEC_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0", Severity.INFO: "0.0"}


def to_sarif(result: ScanResult, tool_name: str = "AI Coding Agent Security Auditor", version: str = "0.1.0", info_uri: str = "") -> dict:
    used = sorted({f.rule_id for f in result.findings})
    rules = []
    for rid in used:
        r = RULES[rid]
        rule = {
            "id": r.id, "name": r.title.title().replace(" ", "").replace("/", "")[:60],
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.description},
            "help": {"text": r.remediation, "markdown": f"**Remediation:** {r.remediation}"},
            "defaultConfiguration": {"level": LEVEL[r.severity]},
            "properties": {"tags": ["security", "ai-agent", r.category], "security-severity": SEC_SEVERITY[r.severity]},
        }
        if r.references:
            rule["helpUri"] = r.references[0]
        rules.append(rule)
    driver = {"name": tool_name, "version": version, "rules": rules}
    if info_uri:
        driver["informationUri"] = info_uri
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": driver},
            "results": [{
                "ruleId": f.rule_id,
                "level": LEVEL[f.severity],
                "message": {"text": f"{f.message}. {f.remediation}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": {"startLine": f.line}}}],
            } for f in result.findings],
        }],
    }
