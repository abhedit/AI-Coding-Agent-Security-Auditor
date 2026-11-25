"""Hardcoded credential detection across every agent config file."""
from __future__ import annotations

import re

from ..models import Rule, Severity
from . import check, finding, register

SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{32,}")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("Stripe secret key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("Database URL with password", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/@\"']+:[^\s@\"'$]{3,}@")),
    ("Bearer token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.=]{30,}")),
]

GENERIC = re.compile(
    r"""(?i)["']?([A-Z0-9_]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|ACCESS[_-]?KEY)[A-Z0-9_]*)["']?\s*[:=]\s*["']([^"'\s]{12,})["']"""
)
PLACEHOLDER = re.compile(r"(?i)^(\$\{.*\}|\$[A-Z_]+|<.*>|x{6,}|\*{4,}|your[_-].*|changeme|example.*|placeholder|dummy.*|test.*|\{\{.*\}\}|env:.*|op://.*)$")

ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")  # value is the *name* of an env var, not a secret
NON_SECRET_SUFFIXES = ("_env_var", "_env", "_var", "_name", "_file", "_path", "_url", "_header", "_helper", "_command", "_id")

R_KNOWN = register(Rule(
    "AGS-SEC-001", "Hardcoded credential in agent configuration", Severity.CRITICAL, "secrets",
    "A credential with a recognisable provider format is committed in a file that AI coding agents read. "
    "Anyone with repository access - and any MCP server or prompt-injected agent - can read it.",
    "Revoke and rotate the credential now. Reference it through an environment variable "
    "(e.g. \"${GITHUB_TOKEN}\") or a secret manager instead of inlining it.",
    ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
))
R_GENERIC = register(Rule(
    "AGS-SEC-002", "Possible secret assigned to sensitive key", Severity.HIGH, "secrets",
    "A key named like a secret (API_KEY, TOKEN, PASSWORD...) holds an inline literal value.",
    "Move the value to an environment variable or secret store and reference it by name.",
))


@check("mcp_config", "claude_settings", "instructions", "agent_definition", "skill", "devcontainer", "mcp_tools", "workflow")
def scan_secrets(sf):
    seen = set()
    for i, line in enumerate(sf.lines, 1):
        for label, pat in SECRET_PATTERNS:
            m = pat.search(line)
            if m and (i, label) not in seen:
                seen.add((i, label))
                yield finding(R_KNOWN, sf, i, f"{label} found in {sf.path}", _mask(line, m.group(0)))
        if any(k[0] == i for k in seen):
            continue
        for m in GENERIC.finditer(line):
            value = m.group(2)
            key = m.group(1).lower()
            if PLACEHOLDER.match(value) or value.startswith("$") or ENV_NAME.match(value) or key.endswith(NON_SECRET_SUFFIXES):
                continue
            yield finding(R_GENERIC, sf, i, f"Inline value for '{m.group(1)}'", _mask(line, value))


def _mask(line: str, secret: str) -> str:
    if len(secret) <= 8:
        masked = "*" * len(secret)
    else:
        masked = secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
    return line.replace(secret, masked).strip()
