"""CI workflows that run AI coding agents on untrusted input."""
from __future__ import annotations

import re

from ..models import Rule, Severity
from . import check, finding, line_of, register

AGENT_ACTIONS = re.compile(r"anthropics/claude-code-action|anthropics/claude-code-base-action|openai/codex-action|google-github-actions/run-gemini-cli|@anthropic-ai/claude-code|\bclaude\s+-p\b|\bcodex\s+exec\b|\bgemini\s+-p\b|aider\b|cursor-agent", re.I)
UNTRUSTED_EXPR = re.compile(r"\$\{\{\s*github\.event\.(issue\.(title|body)|comment\.body|pull_request\.(title|body|head\.ref)|review\.body|review_comment\.body|discussion\.(title|body)|head_commit\.message|commits)", re.I)

R_UNTRUSTED = register(Rule(
    "AGS-CI-001", "AI agent workflow interpolates untrusted user input", Severity.HIGH, "prompt-injection",
    "Issue/PR/comment text from any GitHub user is interpolated into the agent's prompt or a shell step. Anyone "
    "can then prompt-inject an agent that holds repository secrets and write tokens.",
    "Pass untrusted text via environment variables and treat it as data; restrict triggers to trusted actors "
    "(check `author_association`), and give the agent read-only permissions.",
))
R_PRT = register(Rule(
    "AGS-CI-002", "AI agent runs on pull_request_target / forks with secrets", Severity.HIGH, "trust-boundary",
    "The workflow runs an AI agent on `pull_request_target` (or `workflow_run`), which executes with repository "
    "secrets in the context of untrusted fork contributions.",
    "Use `pull_request` for untrusted code, or gate with an environment requiring manual approval.",
))
R_CIYOLO = register(Rule(
    "AGS-CI-003", "AI agent in CI runs with permission checks disabled", Severity.HIGH, "human-in-the-loop",
    "The agent is invoked with `--dangerously-skip-permissions`/`--yolo`/full-access sandbox inside CI, where it holds tokens.",
    "Use an explicit `--allowedTools` allow list and least-privilege `permissions:` for GITHUB_TOKEN.",
))
R_WRITEALL = register(Rule(
    "AGS-CI-004", "AI agent workflow has broad token permissions", Severity.MEDIUM, "least-privilege",
    "The workflow grants `write-all` or no explicit `permissions:` block while running an AI agent.",
    "Declare minimal `permissions:` (e.g. `contents: read`, `pull-requests: write`).",
))


@check("workflow")
def scan_workflow(sf):
    if not AGENT_ACTIONS.search(sf.content):
        return
    for i, line in enumerate(sf.lines, 1):
        if UNTRUSTED_EXPR.search(line):
            yield finding(R_UNTRUSTED, sf, i, "Untrusted GitHub event text reaches the agent", line)
        if re.search(r"--dangerously-skip-permissions|--yolo\b|danger-full-access|--full-auto", line):
            yield finding(R_CIYOLO, sf, i, "Agent permission checks disabled in CI", line)
    if re.search(r"^\s*(pull_request_target|workflow_run)\s*:", sf.content, re.M) or re.search(r"on:\s*\[?[^\n]*pull_request_target", sf.content):
        yield finding(R_PRT, sf, line_of(sf.content, "pull_request_target", line_of(sf.content, "workflow_run")), "Agent runs in privileged fork context", "")
    if re.search(r"permissions:\s*write-all", sf.content) or not re.search(r"^\s*permissions\s*:", sf.content, re.M):
        yield finding(R_WRITEALL, sf, line_of(sf.content, "permissions", 1), "No least-privilege permissions block", "")
