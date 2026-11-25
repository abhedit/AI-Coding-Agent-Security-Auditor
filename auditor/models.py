"""Core data types for the scan engine."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}[self.value]

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    remediation: str
    references: list[str] = field(default_factory=list)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    file: str
    line: int
    message: str
    evidence: str
    remediation: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class SourceFile:
    """A file discovered as part of an AI coding agent's configuration surface."""
    path: str          # path relative to scan root, POSIX style
    kind: str          # mcp_config | claude_settings | instructions | agent_definition | ...
    agent: str         # claude-code | cursor | copilot | windsurf | ...
    content: str

    @property
    def lines(self) -> list[str]:
        return self.content.splitlines()
