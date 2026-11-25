"""Scan orchestration, scoring and report shaping."""
from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field

from . import discovery
from .models import Finding, Severity, SourceFile
from .rules import CHECKS, RULES

GRADES = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]


@dataclass
class ScanResult:
    files: list[SourceFile]
    findings: list[Finding]
    duration_ms: int
    errors: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        c = Counter(f.severity.value for f in self.findings)
        return {s.value: c.get(s.value, 0) for s in Severity}

    @property
    def score(self) -> int:
        """0-100 risk posture score. Repeated hits of the same rule are discounted."""
        per_rule: Counter = Counter()
        penalty = 0.0
        for f in self.findings:
            n = per_rule[f.rule_id]
            penalty += f.severity.weight / (1 + n)
            per_rule[f.rule_id] += 1
        if any(f.severity == Severity.CRITICAL for f in self.findings):
            penalty = max(penalty, 61)  # any critical caps the grade at D
        return max(0, round(100 - penalty))

    @property
    def grade(self) -> str:
        s = self.score
        return next(g for t, g in GRADES if s >= t)

    @property
    def agents(self) -> list[str]:
        return sorted({f.agent for f in self.files if f.agent != "generic"})

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "counts": self.counts,
            "agents_detected": self.agents,
            "files_scanned": [{"path": f.path, "kind": f.kind, "agent": f.agent} for f in self.files],
            "findings": [f.to_dict() for f in self.findings],
            "duration_ms": self.duration_ms,
            "errors": self.errors,
        }


def scan_files(files: list[SourceFile], disabled_rules: set[str] | None = None) -> ScanResult:
    start = time.perf_counter()
    disabled = disabled_rules or set()
    findings: list[Finding] = []
    errors: list[str] = []
    for sf in files:
        for kinds, fn in CHECKS:
            if sf.kind not in kinds:
                continue
            try:
                for f in fn(sf):
                    if f.rule_id not in disabled:
                        findings.append(f)
            except Exception as e:  # a buggy rule must never kill a scan
                errors.append(f"{fn.__name__} on {sf.path}: {e!r}")
    # de-duplicate identical findings
    uniq: dict[tuple, Finding] = {}
    for f in findings:
        uniq.setdefault((f.rule_id, f.file, f.line, f.message), f)
    ordered = sorted(uniq.values(), key=lambda f: (-f.severity.rank, f.file, f.line))
    return ScanResult(files, ordered, int((time.perf_counter() - start) * 1000), errors)


def scan_path(path: str, disabled_rules: set[str] | None = None, exclude: list[str] | None = None) -> ScanResult:
    return scan_files(discovery.discover(path, exclude), disabled_rules)


def scan_mapping(files: dict[str, str], disabled_rules: set[str] | None = None) -> ScanResult:
    return scan_files(discovery.from_mapping(files), disabled_rules)


def rule_catalog() -> list[dict]:
    return [
        {"id": r.id, "title": r.title, "severity": r.severity.value, "category": r.category,
         "description": r.description, "remediation": r.remediation, "references": r.references}
        for r in sorted(RULES.values(), key=lambda r: r.id)
    ]
