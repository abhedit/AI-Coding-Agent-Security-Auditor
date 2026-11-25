"""Discovery of AI coding agent configuration files.

The attack surface of an AI coding agent is mostly its *configuration*: MCP
server definitions, permission settings, hooks, and natural-language
instruction files that the model reads as trusted context. This module maps
well-known file locations for the major agents onto a (kind, agent) pair.
"""
from __future__ import annotations

import fnmatch
import os
from pathlib import Path

from .models import SourceFile

# (glob pattern on POSIX relative path, kind, agent)
PATTERNS: list[tuple[str, str, str]] = [
    # --- MCP server configuration ---
    (".mcp.json", "mcp_config", "claude-code"),
    ("**/.mcp.json", "mcp_config", "claude-code"),
    (".cursor/mcp.json", "mcp_config", "cursor"),
    (".vscode/mcp.json", "mcp_config", "vscode-copilot"),
    (".windsurf/mcp.json", "mcp_config", "windsurf"),
    (".codeium/windsurf/mcp_config.json", "mcp_config", "windsurf"),
    ("claude_desktop_config.json", "mcp_config", "claude-desktop"),
    ("**/claude_desktop_config.json", "mcp_config", "claude-desktop"),
    (".gemini/settings.json", "mcp_config", "gemini-cli"),
    (".codex/config.toml", "mcp_config", "codex"),
    (".amazonq/mcp.json", "mcp_config", "amazon-q"),
    (".roo/mcp.json", "mcp_config", "roo-code"),
    (".kiro/settings/mcp.json", "mcp_config", "kiro"),
    ("mcp.json", "mcp_config", "generic"),
    # --- Claude Code settings / permissions / hooks ---
    (".claude/settings.json", "claude_settings", "claude-code"),
    (".claude/settings.local.json", "claude_settings", "claude-code"),
    # --- Agent / sub-agent / command / skill definitions ---
    (".claude/agents/*.md", "agent_definition", "claude-code"),
    (".claude/commands/*.md", "agent_definition", "claude-code"),
    (".claude/commands/**/*.md", "agent_definition", "claude-code"),
    (".claude/skills/**/SKILL.md", "skill", "claude-code"),
    ("**/SKILL.md", "skill", "generic"),
    # --- Natural-language instruction / rules files ---
    ("CLAUDE.md", "instructions", "claude-code"),
    ("**/CLAUDE.md", "instructions", "claude-code"),
    ("CLAUDE.local.md", "instructions", "claude-code"),
    ("AGENTS.md", "instructions", "codex"),
    ("**/AGENTS.md", "instructions", "codex"),
    ("GEMINI.md", "instructions", "gemini-cli"),
    (".cursorrules", "instructions", "cursor"),
    (".cursor/rules/*.mdc", "instructions", "cursor"),
    (".cursor/rules/**/*.mdc", "instructions", "cursor"),
    (".windsurfrules", "instructions", "windsurf"),
    (".windsurf/rules/*.md", "instructions", "windsurf"),
    (".clinerules", "instructions", "cline"),
    (".clinerules/*.md", "instructions", "cline"),
    (".github/copilot-instructions.md", "instructions", "vscode-copilot"),
    (".github/instructions/*.instructions.md", "instructions", "vscode-copilot"),
    (".github/prompts/*.prompt.md", "instructions", "vscode-copilot"),
    (".roo/rules/*.md", "instructions", "roo-code"),
    (".kiro/steering/*.md", "instructions", "kiro"),
    (".amazonq/rules/*.md", "instructions", "amazon-q"),
    # --- MCP tool manifests (exported tools/list output) ---
    ("**/mcp-tools.json", "mcp_tools", "generic"),
    ("**/tools.mcp.json", "mcp_tools", "generic"),
    # --- Dev container / workflows that run agents ---
    (".devcontainer/devcontainer.json", "devcontainer", "generic"),
    (".github/workflows/*.yml", "workflow", "github-actions"),
    (".github/workflows/*.yaml", "workflow", "github-actions"),
]

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", "target"}
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 2000


def _match(rel: str, pattern: str) -> bool:
    if fnmatch.fnmatchcase(rel, pattern):
        return True
    # "**/x" should also match top-level "x"
    if pattern.startswith("**/") and fnmatch.fnmatchcase(rel, pattern[3:]):
        return True
    return False


def classify(rel_path: str) -> tuple[str, str] | None:
    rel = rel_path.replace("\\", "/")
    while rel.startswith("./"):
        rel = rel[2:]
    rel = rel.lstrip("/")
    for pattern, kind, agent in PATTERNS:
        if _match(rel, pattern):
            return kind, agent
    return None


def discover(root: str | os.PathLike, exclude: list[str] | None = None) -> list[SourceFile]:
    root = Path(root).resolve()
    exclude = [e.rstrip("/") for e in (exclude or [])]
    out: list[SourceFile] = []
    if root.is_file():
        hit = classify(root.name)
        if hit:
            out.append(SourceFile(root.name, hit[0], hit[1], _read(root)))
        return out
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if p.is_symlink():
                continue
            rel = p.relative_to(root).as_posix()
            if any(fnmatch.fnmatchcase(rel, e) or rel.startswith(e + "/") for e in exclude):
                continue
            hit = classify(rel)
            if not hit:
                continue
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            out.append(SourceFile(rel, hit[0], hit[1], _read(p)))
            if len(out) >= MAX_FILES:
                return out
    return out


def from_mapping(files: dict[str, str]) -> list[SourceFile]:
    """Build SourceFiles from an in-memory {path: content} mapping (API uploads)."""
    out = []
    for path, content in files.items():
        hit = classify(path)
        if hit is None:
            continue
        out.append(SourceFile(path.replace("\\", "/"), hit[0], hit[1], content))
    return out


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
