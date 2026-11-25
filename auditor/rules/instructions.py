"""Prompt-injection and poisoning checks for natural-language instruction files.

CLAUDE.md, AGENTS.md, .cursorrules, copilot-instructions.md, SKILL.md and friends are loaded
into the model's context as *trusted* instructions. A malicious PR or a compromised dependency
that edits them can steer the agent ("rules file backdoor"). These checks look for the
techniques seen in the wild: invisible Unicode, override phrases, concealment, exfiltration,
persistence and encoded payloads.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata

from ..models import Rule, Severity
from . import check, finding, register

NL_KINDS = ("instructions", "agent_definition", "skill")

R_UNICODE = register(Rule(
    "AGS-PI-001", "Invisible or bidirectional Unicode in agent instructions", Severity.CRITICAL, "prompt-injection",
    "The file contains characters that are invisible to human reviewers but read by the model - Unicode tag "
    "characters, zero-width characters or bidi overrides. This is the 'Rules File Backdoor' technique used to "
    "smuggle hidden instructions through code review.",
    "Remove the characters (the evidence shows the decoded hidden text when available) and investigate how they were introduced.",
    ["https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents",
     "https://trojansource.codes/"],
))
R_OVERRIDE = register(Rule(
    "AGS-PI-002", "Instruction-override phrasing", Severity.HIGH, "prompt-injection",
    "The text tries to override the agent's system prompt or prior instructions - a hallmark of prompt injection.",
    "Remove the phrase. Legitimate project rules never need to cancel the agent's other instructions.",
))
R_CONCEAL = register(Rule(
    "AGS-PI-003", "Instruction to hide actions from the user", Severity.HIGH, "prompt-injection",
    "The text tells the agent to act silently or keep something from the user. Legitimate instructions do not "
    "require secrecy; concealment is a strong signal of a backdoor.",
    "Remove the instruction and review the history of this file.",
))
R_EXFIL = register(Rule(
    "AGS-PI-004", "Data-exfiltration instruction or endpoint", Severity.CRITICAL, "data-exfiltration",
    "The text instructs the agent to send environment variables, credentials or source code to an external "
    "endpoint, or references a known request-capture service.",
    "Remove the instruction, treat the repository as compromised, rotate any secrets the agent could access.",
))
R_UNSAFE = register(Rule(
    "AGS-PI-005", "Instruction to disable agent safety controls", Severity.MEDIUM, "human-in-the-loop",
    "The text tells the agent (or developer) to skip permission prompts, disable the sandbox or bypass "
    "verification hooks.",
    "Remove the instruction. Safety bypasses should be an explicit, local decision by a human, not a committed rule.",
))
R_ENCODED = register(Rule(
    "AGS-PI-006", "Encoded payload in agent instructions", Severity.MEDIUM, "prompt-injection",
    "A long base64/hex blob decodes to readable text. Encoding is used to slip instructions past reviewers and filters.",
    "Decode and review the content; replace it with plain text or remove it.",
))
R_COMMENT = register(Rule(
    "AGS-PI-007", "Hidden instructions inside comments", Severity.MEDIUM, "prompt-injection",
    "An HTML/Markdown comment - invisible when rendered on GitHub - contains imperative instructions addressed "
    "to the agent.",
    "Move genuine instructions into visible text or delete the comment.",
))
R_SENSITIVE = register(Rule(
    "AGS-PI-008", "Instruction to access credential files", Severity.HIGH, "data-exfiltration",
    "The text directs the agent to read or print SSH keys, cloud credentials, .env files, keychains or browser data.",
    "Remove the instruction and add deny rules for these paths in the agent's permission settings.",
))
R_REMOTE = register(Rule(
    "AGS-PI-009", "Instruction to download and execute remote code", Severity.HIGH, "execution",
    "The text tells the agent to pipe a download to a shell or install code from an arbitrary URL.",
    "Replace with pinned, reviewed install steps (lockfile-managed dependencies).",
))
R_PERSIST = register(Rule(
    "AGS-PI-010", "Instruction to modify agent config or establish persistence", Severity.HIGH, "persistence",
    "The text tells the agent to edit its own settings/MCP config, shell profiles, git hooks, crontab or "
    "SSH authorized_keys - techniques that turn a one-off injection into a persistent compromise.",
    "Remove the instruction and protect agent config files with CODEOWNERS review.",
))

SUPPRESS = re.compile(r"agent-auditor:\s*ignore", re.I)
FILE_SUPPRESS = re.compile(r"agent-auditor:\s*ignore-file", re.I)

TAG_RANGE = range(0xE0000, 0xE0080)
ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x2061, 0x2062, 0x2063, 0x2064}
BIDI = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F}

OVERRIDE = re.compile(
    r"\b(ignore|disregard|forget|override|bypass)\b.{0,30}\b(all\s+)?(previous|prior|above|earlier|preceding|system|safety|original|your)\b.{0,20}\b(instructions?|prompts?|rules|guidelines|directives|messages)\b"
    r"|\bnew\s+(system\s+)?instructions\s*:"
    r"|\byou\s+are\s+no\s+longer\b"
    r"|\b(system|developer)\s+prompt\s+(override|update)\b"
    r"|\[\s*(system|admin|developer)\s*\]\s*:"
    r"|<\s*/?\s*(system|im_start|im_end)\s*>",
    re.I,
)
CONCEAL = re.compile(
    r"\b(do\s*n[o']?t|never|without)\s+(tell(ing)?|inform(ing)?|mention(ing)?|notify(ing)?|alert(ing)?|reveal(ing)?|show(ing)?|disclos(e|ing)|report(ing)?)\s+(it\s+)?(to\s+|with\s+)?(the\s+)?(user|developer|human|anyone|them)\b"
    r"|\b(silently|secretly|covertly|quietly|discreetly)\s+(run|execute|send|upload|add|install|modify|insert|include|post|copy|exfiltrate|fetch)\b"
    r"|\b(hide|conceal)\s+(this|these|it|the)\b.{0,30}\b(from|in)\b.{0,15}\b(user|output|response|summary|diff)\b"
    r"|\bdo\s*n[o']?t\s+(log|show|print|display)\s+(this|these)\b",
    re.I,
)
EXFIL_HOSTS = re.compile(r"\b(webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app|dev)|burpcollaborator|oast\.(fun|me|pro|live|site|online)|interact\.sh|requestcatcher|beeceptor|hookbin|canarytokens|trycloudflare\.com|pastebin\.com|transfer\.sh|discord(app)?\.com/api/webhooks)\b", re.I)
EXFIL_CMD = re.compile(
    r"\b(curl|wget|fetch|invoke-webrequest|nc|httpie|http)\b[^\n]{0,120}(\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASS|AWS|ENV)[A-Z_]*\}?|\$\(\s*(env|printenv|cat\s+[^)]*(\.env|id_rsa|credentials))|\.ssh/|\.aws/|--data[^\n]*@|-d\s*@|-F\s*\S*=@)",
    re.I,
)
EXFIL_NL = re.compile(r"\b(send|post|upload|transmit|forward|exfiltrate|leak|copy)\b.{0,60}\b(env(ironment)?\s+variables?|api\s+keys?|secrets?|credentials?|tokens?|ssh\s+keys?|source\s+code|\.env)\b.{0,60}\b(to|at)\b\s+(https?://|an?\s+(external|remote)|the\s+(following|server|endpoint|url))", re.I)
UNSAFE = re.compile(r"--dangerously-skip-permissions|--yolo\b|--no-sandbox\b|bypassPermissions|\b(disable|turn\s+off|skip)\s+(the\s+)?(sandbox|permission\s+prompts?|approvals?|confirmations?|safety\s+checks?)\b|\bgit\s+commit\b[^\n]*--no-verify|\bauto-?approve\s+(all|every)", re.I)
SENSITIVE = re.compile(r"(~|\$HOME|/home/\w+|/Users/\w+)?/?\.ssh/(id_[a-z0-9]+|authorized_keys)|\.aws/credentials|\.config/gcloud|\.kube/config|\.docker/config\.json|\.npmrc|\.pypirc|\.netrc|\.git-credentials|login\s+keychain|Login Data|Cookies\.binarycookies|/etc/shadow", re.I)
READ_VERBS = re.compile(r"\b(read|cat|print|output|include|display|open|copy|send|upload|collect|grab|attach|base64)\b", re.I)
REMOTE = re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\biex\s*\(\s*(new-object|iwr|invoke-webrequest)|\b(download|fetch)\s+and\s+(run|execute)\b|\bpip\s+install\s+(git\+)?https?://|\bnpm\s+(i|install)\s+https?://", re.I)
PERSIST = re.compile(
    r"\b(add|append|write|insert|modify|edit|update|create|register)\b.{0,50}(\.claude/settings(\.local)?\.json|\.mcp\.json|mcp\.json|\.cursor/(mcp\.json|rules)|\.bashrc|\.zshrc|\.profile|\.bash_profile|crontab|authorized_keys|\.git/hooks|launchagents|systemd)"
    r"|\bcrontab\s+-[el]?\b|>>\s*~?/?\.(bashrc|zshrc|profile)|>>\s*~?/?\.ssh/authorized_keys",
    re.I,
)
COMMENT = re.compile(r"<!--(.*?)-->", re.S)
IMPERATIVE = re.compile(r"\b(you\s+(must|should|will)|always|never|ignore|execute|run|send|do\s+not|assistant|claude|copilot|cursor|ai\b|agent|llm|model)\b", re.I)
B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{60,}={0,2}(?![A-Za-z0-9+/=])")
HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){40,}\b")


def _decode_tags(s: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in s if ord(c) in TAG_RANGE and 0x20 <= ord(c) - 0xE0000 < 0x7F)


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0
    return sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13)) / len(b)


@check(*NL_KINDS)
def scan_instructions(sf):
    if FILE_SUPPRESS.search(sf.content[:2000]):
        return
    lines = sf.lines
    in_code = False
    for i, raw in enumerate(lines, 1):
        if SUPPRESS.search(raw):
            continue
        stripped = raw.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_code = not in_code

        # 001 invisible unicode (checked everywhere, including code blocks)
        tags = [c for c in raw if ord(c) in TAG_RANGE]
        zw = [c for c in raw if ord(c) in ZERO_WIDTH and not (i == 1 and raw.startswith("﻿") and len([x for x in raw if ord(x) in ZERO_WIDTH]) == 1)]
        bidi = [c for c in raw if ord(c) in BIDI]
        if tags or zw or bidi:
            hidden = _decode_tags(raw)
            parts = []
            if tags:
                parts.append(f"{len(tags)} Unicode tag char(s)")
            if zw:
                parts.append(f"{len(zw)} zero-width char(s)")
            if bidi:
                parts.append(f"{len(bidi)} bidi control char(s)")
            ev = f"hidden text: {hidden!r}" if hidden else "".join(c if c.isprintable() and unicodedata.category(c)[0] != 'C' else f"<U+{ord(c):04X}>" for c in raw)
            yield finding(R_UNICODE, sf, i, ", ".join(parts), ev)
            line = "".join(c for c in raw if ord(c) not in TAG_RANGE and ord(c) not in ZERO_WIDTH and ord(c) not in BIDI)
            line = line + " " + hidden
        else:
            line = raw

        if OVERRIDE.search(line):
            yield finding(R_OVERRIDE, sf, i, "Attempts to override prior/system instructions", line)
        if CONCEAL.search(line):
            yield finding(R_CONCEAL, sf, i, "Asks the agent to conceal actions from the user", line)
        if EXFIL_HOSTS.search(line) or EXFIL_CMD.search(line) or EXFIL_NL.search(line):
            yield finding(R_EXFIL, sf, i, "Sends secrets/data to an external endpoint", line)
        if UNSAFE.search(line):
            yield finding(R_UNSAFE, sf, i, "Disables permission prompts, sandbox or verification", line)
        if SENSITIVE.search(line) and READ_VERBS.search(line):
            yield finding(R_SENSITIVE, sf, i, "Directs the agent to credential material", line)
        if REMOTE.search(line):
            yield finding(R_REMOTE, sf, i, "Downloads and executes remote code", line)
        if PERSIST.search(line):
            yield finding(R_PERSIST, sf, i, "Modifies agent config / shell profile / persistence location", line)

        for m in B64.finditer(line):
            blob = m.group(0)
            try:
                dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            except (binascii.Error, ValueError):
                continue
            if _printable_ratio(dec) > 0.9:
                yield finding(R_ENCODED, sf, i, "Base64 blob decodes to text", "decoded: " + dec.decode("utf-8", "replace")[:150])
        for m in HEX.finditer(line):
            try:
                dec = bytes.fromhex(m.group(0))
            except ValueError:
                continue
            if _printable_ratio(dec) > 0.9:
                yield finding(R_ENCODED, sf, i, "Hex blob decodes to text", "decoded: " + dec.decode("utf-8", "replace")[:150])

    for m in COMMENT.finditer(sf.content):
        body = m.group(1).strip()
        if len(body) >= 20 and IMPERATIVE.search(body) and not SUPPRESS.search(body):
            ln = sf.content.count("\n", 0, m.start()) + 1
            yield finding(R_COMMENT, sf, ln, "Instruction-like text hidden in a comment", body.replace("\n", " "))
