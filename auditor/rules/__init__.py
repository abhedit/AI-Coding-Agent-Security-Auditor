"""Rule registry. Each rule module registers checks with @check(kinds=...)."""
from __future__ import annotations

from typing import Callable, Iterable

from ..models import Finding, Rule, SourceFile

RULES: dict[str, Rule] = {}
CHECKS: list[tuple[set[str], Callable[[SourceFile], Iterable[Finding]]]] = []


def register(rule: Rule) -> Rule:
    if rule.id in RULES:
        raise ValueError(f"duplicate rule id {rule.id}")
    RULES[rule.id] = rule
    return rule


def check(*kinds: str):
    def deco(fn):
        CHECKS.append((set(kinds), fn))
        return fn
    return deco


def finding(rule: Rule, sf: SourceFile, line: int, message: str, evidence: str = "") -> Finding:
    ev = evidence.strip()
    if len(ev) > 200:
        ev = ev[:197] + "..."
    return Finding(
        rule_id=rule.id, title=rule.title, severity=rule.severity, category=rule.category,
        file=sf.path, line=max(1, line), message=message, evidence=ev, remediation=rule.remediation,
    )


def line_of(content: str, needle: str, default: int = 1) -> int:
    if not needle:
        return default
    idx = content.find(needle)
    if idx < 0:
        return default
    return content.count("\n", 0, idx) + 1


# import rule modules for their registration side effects
from . import secrets, mcp, claude_settings, instructions, agents, tools, workflows  # noqa: E402,F401
