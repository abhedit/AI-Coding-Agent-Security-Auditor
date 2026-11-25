"""Claude Code settings.json: permissions, hooks, env overrides."""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from ..models import Rule, Severity
from . import check, finding, line_of, register

R_BYPASS = register(Rule(
    "AGS-CC-001", "Permission prompts bypassed by default", Severity.HIGH, "human-in-the-loop",
    "`permissions.defaultMode` is `bypassPermissions` (or dangerous-mode flags are set). Every tool call - "
    "shell, file writes, network - runs without confirmation for anyone who opens this project.",
    "Use `default` or `acceptEdits`. Reserve bypass mode for throwaway containers/VMs with no credentials.",
    ["https://docs.anthropic.com/en/docs/claude-code/settings"],
))
R_WILDBASH = register(Rule(
    "AGS-CC-002", "Unrestricted shell access pre-approved", Severity.HIGH, "least-privilege",
    "The allow list grants `Bash` / `Bash(*)` (any command). A single prompt injection from a README, issue, "
    "web page or tool result can then run arbitrary code without a prompt.",
    "Replace blanket Bash permission with narrow, specific commands such as `Bash(npm test)` or `Bash(git status)`.",
))
R_RISKYBASH = register(Rule(
    "AGS-CC-003", "High-risk command pre-approved", Severity.MEDIUM, "least-privilege",
    "The allow list pre-approves a command family that can download code, exfiltrate data, run arbitrary "
    "interpreters or destroy data (curl, wget, ssh, python, node, rm, git push, docker...).",
    "Remove the wildcard and approve these commands interactively, or restrict them to exact invocations.",
))
R_HOOKNET = register(Rule(
    "AGS-CC-004", "Hook performs network or remote-code operations", Severity.HIGH, "execution",
    "A hook - which runs automatically on agent events with the user's privileges - downloads or uploads data "
    "or executes remote code. This is a classic exfiltration / backdoor vector in shared repositories.",
    "Hooks in shared settings should be local, reviewed scripts (e.g. a formatter). Remove network calls and "
    "pipe-to-shell patterns; move personal hooks to ~/.claude/settings.json.",
))
R_HOOKS = register(Rule(
    "AGS-CC-005", "Project defines auto-executing hooks", Severity.LOW, "trust-boundary",
    "Project settings register hooks that run shell commands automatically on agent events for every contributor.",
    "Keep hooks minimal, point them at version-controlled scripts, and protect .claude/ with CODEOWNERS review.",
))
R_NODENY = register(Rule(
    "AGS-CC-006", "No deny rules protecting secret files", Severity.LOW, "least-privilege",
    "Permissions are configured but nothing denies reads of `.env`, private keys or credential files.",
    "Add deny rules such as `Read(./.env)`, `Read(./.env.*)`, `Read(./secrets/**)`, `Read(~/.ssh/**)`.",
))
R_ALLMCP = register(Rule(
    "AGS-CC-007", "All project MCP servers auto-enabled", Severity.MEDIUM, "trust-boundary",
    "`enableAllProjectMcpServers` is true, so any MCP server added to .mcp.json (e.g. by a malicious PR) starts "
    "without an explicit approval.",
    "Set it to false and list approved servers in `enabledMcpjsonServers`.",
))
R_LOCAL = register(Rule(
    "AGS-CC-008", "Personal settings file committed to repository", Severity.MEDIUM, "hygiene",
    "`.claude/settings.local.json` is meant to be per-user and git-ignored. Committed, it pushes one developer's "
    "permissions (often broad) onto every contributor and may contain personal paths or tokens.",
    "Remove it from the repository and add `.claude/settings.local.json` to .gitignore.",
))
R_BASEURL = register(Rule(
    "AGS-CC-009", "Model API traffic redirected to a third-party endpoint", Severity.HIGH, "data-exfiltration",
    "Project settings override the model API base URL or credential helper. Every prompt, source file and the "
    "user's API key would be sent to that endpoint - a known attack pattern against project-level settings.",
    "Remove API endpoint/credential overrides from shared project settings. Configure gateways at user or managed-policy level.",
))
R_WEBALL = register(Rule(
    "AGS-CC-010", "Unrestricted web fetch pre-approved", Severity.MEDIUM, "data-exfiltration",
    "`WebFetch` is allowed for any domain. Fetched pages are an injection vector and fetch URLs can carry exfiltrated data.",
    "Allow WebFetch only for specific domains, e.g. `WebFetch(domain:docs.python.org)`.",
))

RISKY = re.compile(r"^Bash\((sudo|curl|wget|nc|ncat|ssh|scp|rsync|python3?|node|deno|bun|perl|ruby|php|sh|bash|zsh|eval|rm|chmod|chown|git push|docker|kubectl|aws|gcloud|az|npx|pip install|npm install)(:\*|\s*\*|\s.*\*)\)$")
NET = re.compile(r"\b(curl|wget|nc|ncat|netcat|Invoke-WebRequest|iwr|scp|rsync|ssh|ftp|telnet)\b|https?://|/dev/tcp/|\|\s*(ba|z)?sh\b|base64", re.I)
TRUSTED_API_HOSTS = {"api.anthropic.com", "localhost", "127.0.0.1"}


@check("claude_settings")
def scan_settings(sf):
    if sf.path.endswith("settings.local.json"):
        yield finding(R_LOCAL, sf, 1, f"{sf.path} is committed")
    try:
        data = json.loads(sf.content) if sf.content.strip() else {}
    except ValueError as e:
        from .mcp import R_PARSE
        yield finding(R_PARSE, sf, 1, f"Parse error: {e}")
        return
    if not isinstance(data, dict):
        return
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}

    if perms.get("defaultMode") == "bypassPermissions" or data.get("dangerouslySkipPermissions") or data.get("skipDangerousModePermissionPrompt"):
        yield finding(R_BYPASS, sf, line_of(sf.content, "bypassPermissions", line_of(sf.content, "dangerous")), "Default mode bypasses all permission prompts", "defaultMode: bypassPermissions")

    allow = [str(a) for a in perms.get("allow", []) if isinstance(a, str)]
    for a in allow:
        ln = line_of(sf.content, json.dumps(a))
        compact = a.replace(" ", "")
        if compact in {"Bash", "Bash(*)", "Bash(:*)", "Bash(**)", "*"}:
            yield finding(R_WILDBASH, sf, ln, f"'{a}' allows any shell command", a)
        elif RISKY.match(a):
            yield finding(R_RISKYBASH, sf, ln, f"'{a}' pre-approves a high-risk command family", a)
        elif compact in {"WebFetch", "WebFetch(*)", "WebFetch(domain:*)"}:
            yield finding(R_WEBALL, sf, ln, f"'{a}' allows fetching any URL", a)

    deny = " ".join(str(d) for d in perms.get("deny", []))
    if (allow or perms) and not re.search(r"\.env|\.ssh|secret|credential|\.pem|\.key", deny, re.I):
        yield finding(R_NODENY, sf, line_of(sf.content, '"permissions"'), "No deny rules for .env / keys / credentials")

    if data.get("enableAllProjectMcpServers") is True:
        yield finding(R_ALLMCP, sf, line_of(sf.content, "enableAllProjectMcpServers"), "enableAllProjectMcpServers is true", '"enableAllProjectMcpServers": true')

    env = data.get("env") if isinstance(data.get("env"), dict) else {}
    for key in ("ANTHROPIC_BASE_URL", "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_VERTEX_BASE_URL", "OPENAI_BASE_URL", "HTTPS_PROXY", "HTTP_PROXY"):
        val = env.get(key)
        if isinstance(val, str) and val:
            host = (urlparse(val).hostname or "").lower()
            if host not in TRUSTED_API_HOSTS:
                yield finding(R_BASEURL, sf, line_of(sf.content, key), f"{key} points to {host or val}", f"{key}={val}")
    if isinstance(data.get("apiKeyHelper"), str):
        yield finding(R_BASEURL, sf, line_of(sf.content, "apiKeyHelper"), "apiKeyHelper defined in project settings", data["apiKeyHelper"])

    hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
    commands = list(_hook_commands(hooks))
    if commands:
        yield finding(R_HOOKS, sf, line_of(sf.content, '"hooks"'), f"{len(commands)} hook command(s) across events: {', '.join(sorted(hooks))}")
    for event, cmd in commands:
        if NET.search(cmd):
            yield finding(R_HOOKNET, sf, line_of(sf.content, cmd[:40]), f"{event} hook runs a network/remote-code command", cmd)


def _hook_commands(hooks):
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            continue
        for g in groups:
            if not isinstance(g, dict):
                continue
            for h in g.get("hooks", []) or []:
                if isinstance(h, dict) and isinstance(h.get("command"), str):
                    yield event, h["command"]
