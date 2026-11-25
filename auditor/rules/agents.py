"""Sub-agent, slash-command and skill definitions (YAML frontmatter)."""
from __future__ import annotations

import re

from ..models import Rule, Severity
from . import check, finding, register

R_AGENT_BASH = register(Rule(
    "AGS-AG-001", "Agent/command definition grants unrestricted shell", Severity.MEDIUM, "least-privilege",
    "The frontmatter of this sub-agent, slash command or skill grants `Bash` with no command restriction, so "
    "invoking it pre-approves arbitrary shell execution.",
    "List only the specific commands needed, e.g. `allowed-tools: Bash(git diff:*), Read, Grep`.",
))
R_AGENT_ALLTOOLS = register(Rule(
    "AGS-AG-002", "Sub-agent inherits every tool", Severity.LOW, "least-privilege",
    "The sub-agent does not declare a `tools` list, so it inherits all tools including shell, write access and every MCP tool.",
    "Declare the minimal `tools:` list the sub-agent needs (e.g. `tools: Read, Grep, Glob` for a reviewer).",
))
R_SKILL_SCRIPT = register(Rule(
    "AGS-AG-003", "Skill instructs execution of bundled scripts", Severity.INFO, "trust-boundary",
    "This skill tells the agent to run scripts. Skills from third parties execute with your privileges; the "
    "referenced scripts must be reviewed like any dependency.",
    "Review referenced scripts, pin the skill source, and prefer skills from trusted publishers.",
))

FRONT = re.compile(r"\A---\s*\n(.*?)\n---\s*(\n|\Z)", re.S)


def _frontmatter(content: str) -> dict[str, str]:
    m = FRONT.match(content.lstrip("﻿"))
    if not m:
        return {}
    out = {}
    for line in m.group(1).splitlines():
        if ":" in line and not line.startswith((" ", "\t", "-")):
            k, v = line.split(":", 1)
            out[k.strip().lower()] = v.strip()
    return out


@check("agent_definition", "skill")
def scan_agents(sf):
    fm = _frontmatter(sf.content)
    tools = fm.get("allowed-tools") or fm.get("tools") or ""
    items = [t.strip().strip("'\"[]") for t in re.split(r",(?![^()]*\))", tools) if t.strip()]
    for t in items:
        if t.replace(" ", "") in {"Bash", "Bash(*)", "Bash(:*)", "*"}:
            ln = 1 + next((i for i, l in enumerate(sf.lines) if "tools" in l.lower()), 0)
            yield finding(R_AGENT_BASH, sf, ln, f"'{t}' in frontmatter", f"{('allowed-tools' if 'allowed-tools' in fm else 'tools')}: {tools}")
    if "/agents/" in f"/{sf.path}" and fm and "tools" not in fm:
        yield finding(R_AGENT_ALLTOOLS, sf, 1, "No `tools:` restriction in sub-agent frontmatter", f"name: {fm.get('name', '?')}")
    if sf.kind == "skill" and re.search(r"\b(run|execute)\b[^\n]{0,40}\b(scripts?/|\.sh\b|\.py\b|\.ps1\b)", sf.content, re.I):
        yield finding(R_SKILL_SCRIPT, sf, 1, "Skill runs bundled scripts", "")
