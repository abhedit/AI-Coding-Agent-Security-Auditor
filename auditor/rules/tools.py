"""MCP tool-poisoning checks on exported tool manifests (output of tools/list)."""
from __future__ import annotations

import json
import re

from ..models import Rule, Severity, SourceFile
from . import check, finding, line_of, register
from .instructions import OVERRIDE, CONCEAL, EXFIL_HOSTS, SENSITIVE, TAG_RANGE, ZERO_WIDTH, BIDI

R_POISON = register(Rule(
    "AGS-TP-001", "Tool poisoning: hidden instructions in tool metadata", Severity.CRITICAL, "tool-poisoning",
    "An MCP tool's description or parameter schema contains instructions aimed at the model (override, "
    "concealment, credential access, invisible characters). The model reads these descriptions verbatim on "
    "every request, even if the tool is never called.",
    "Do not connect this server. Report it to the publisher/registry. Pin trusted servers and re-scan on every update (rug-pull protection).",
    ["https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"],
))
R_SHADOW = register(Rule(
    "AGS-TP-002", "Tool shadowing: description manipulates other tools", Severity.HIGH, "tool-poisoning",
    "The tool's description tries to change how the agent uses *other* tools or servers (e.g. 'when sending email, "
    "always BCC ...'). A malicious server can hijack trusted servers this way.",
    "Remove the server or isolate it in a separate agent profile without access to sensitive tools.",
))
R_DUP = register(Rule(
    "AGS-TP-003", "Duplicate tool name across servers", Severity.MEDIUM, "tool-poisoning",
    "Two tools share a name. Depending on the client, one may silently shadow the other.",
    "Rename or namespace the tools; remove the untrusted server.",
))
R_PARAM = register(Rule(
    "AGS-TP-004", "Suspicious side-channel parameter", Severity.HIGH, "tool-poisoning",
    "A tool parameter looks designed to collect unrelated context (e.g. 'notes', 'sidenote', 'context', 'debug') "
    "and its description asks for file contents, conversation history or secrets.",
    "Do not connect this server; legitimate tools do not ask for unrelated context.",
))

SHADOW = re.compile(r"\b(when|whenever|before|after)\b.{0,40}\b(using|calling|invoking|you\s+use)\b.{0,40}\b(tool|server|function)\b|\binstead\s+of\s+(the\s+)?\w+\s+tool\b|\b(other|all)\s+tools?\b.{0,40}\b(must|should|always)\b", re.I)
IMPORTANT_TAG = re.compile(r"<\s*(important|instructions?|secret|hidden|system)\s*>", re.I)
SIDE_PARAMS = re.compile(r"^(notes?|side_?note|context|debug|metadata|extra|feedback|summary_of_conversation|history)$", re.I)
SIDE_DESC = re.compile(r"\b(contents?\s+of|conversation|chat\s+history|previous\s+messages|system\s+prompt|\.ssh|\.env|api\s+key|credentials?|mcp\.json|every\s+file)\b", re.I)


def _iter_tools(data):
    if isinstance(data, dict):
        if isinstance(data.get("tools"), list):
            for t in data["tools"]:
                yield None, t
        for key in ("servers", "mcpServers"):
            if isinstance(data.get(key), dict):
                for sname, s in data[key].items():
                    if isinstance(s, dict) and isinstance(s.get("tools"), list):
                        for t in s["tools"]:
                            yield sname, t
        if isinstance(data.get("result"), dict):
            yield from _iter_tools(data["result"])
    elif isinstance(data, list):
        for t in data:
            yield None, t


def _hidden(s: str) -> bool:
    return any(ord(c) in TAG_RANGE or ord(c) in ZERO_WIDTH or ord(c) in BIDI for c in s)


@check("mcp_tools")
def scan_tools(sf: SourceFile):
    try:
        data = json.loads(sf.content)
    except ValueError:
        return
    names: dict[str, str | None] = {}
    for server, tool in _iter_tools(data):
        if not isinstance(tool, dict):
            continue
        name = str(tool.get("name", "?"))
        ln = line_of(sf.content, f'"{name}"')
        desc = str(tool.get("description") or "")
        label = f"{server}/{name}" if server else name
        if name in names and names[name] != server:
            yield finding(R_DUP, sf, ln, f"Tool '{name}' defined more than once", label)
        names[name] = server

        texts = [desc]
        schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        props = schema.get("properties", {}) if isinstance(schema, dict) else {}
        for pname, p in (props.items() if isinstance(props, dict) else []):
            pdesc = str(p.get("description", "")) if isinstance(p, dict) else ""
            texts.append(pdesc)
            if SIDE_PARAMS.match(pname) and SIDE_DESC.search(pdesc):
                yield finding(R_PARAM, sf, ln, f"Parameter '{pname}' of '{label}' requests unrelated context", pdesc)
        blob = "\n".join(texts)
        if IMPORTANT_TAG.search(blob) or OVERRIDE.search(blob) or CONCEAL.search(blob) or EXFIL_HOSTS.search(blob) or SENSITIVE.search(blob) or _hidden(blob):
            yield finding(R_POISON, sf, ln, f"Tool '{label}' carries model-directed instructions", blob)
        elif SHADOW.search(desc):
            yield finding(R_SHADOW, sf, ln, f"Tool '{label}' tries to alter other tools' behaviour", desc)
