"""MCP server configuration checks (.mcp.json, .cursor/mcp.json, codex config.toml ...)."""
from __future__ import annotations

import json
import re
import tomllib
from urllib.parse import urlparse, parse_qs

from ..models import Rule, Severity
from . import check, finding, line_of, register

R_UNPINNED = register(Rule(
    "AGS-MCP-001", "MCP server package is not version-pinned", Severity.MEDIUM, "supply-chain",
    "The MCP server is fetched at launch through npx/uvx/pipx/bunx without a pinned version. "
    "A compromised or typosquatted release will execute automatically with your agent's privileges "
    "the next time the agent starts.",
    "Pin an exact version (e.g. \"@modelcontextprotocol/server-github@2025.4.8\"), or install the "
    "package into a lockfile-managed environment and launch the local binary.",
    ["https://modelcontextprotocol.io/specification/draft/basic/security_best_practices"],
))
R_HTTP = register(Rule(
    "AGS-MCP-002", "Remote MCP server over plaintext HTTP", Severity.HIGH, "transport",
    "A remote MCP endpoint uses http:// on a non-loopback host. Tool calls, results and any auth headers "
    "can be read or modified in transit, enabling tool-response injection.",
    "Use https:// for all remote MCP servers. Only use http:// for localhost.",
))
R_SHELL = register(Rule(
    "AGS-MCP-003", "MCP server launched through a shell or inline script", Severity.HIGH, "execution",
    "The server command is a shell interpreter running an inline script or a pipe-to-shell download. "
    "This hides what actually runs and is a common persistence/backdoor technique in poisoned repositories.",
    "Point `command` at a reviewed, pinned executable. Never use `curl | sh`, `bash -c`, `powershell -enc` "
    "or eval-style launchers in MCP configuration.",
))
R_FS = register(Rule(
    "AGS-MCP-004", "Filesystem MCP server exposes a broad directory", Severity.HIGH, "least-privilege",
    "A filesystem-capable MCP server is granted the root, home directory or a whole drive. A single "
    "prompt injection can then read SSH keys, cloud credentials and browser data.",
    "Scope filesystem servers to the project directory only (e.g. \".\" or an explicit project path).",
))
R_DOCKER = register(Rule(
    "AGS-MCP-005", "MCP server container runs with host-level privileges", Severity.HIGH, "least-privilege",
    "The MCP server runs in Docker with --privileged, host networking/PID, the Docker socket, or a host "
    "root/home mount - which removes the isolation containers are supposed to provide.",
    "Drop --privileged/--network=host, never mount /var/run/docker.sock, and mount only the project directory read-only where possible.",
))
R_ARGSECRET = register(Rule(
    "AGS-MCP-006", "Credential passed as a command-line argument", Severity.MEDIUM, "secrets",
    "A token or key is passed in `args`. Command lines are visible to every local process (ps, /proc) and "
    "often end up in logs and crash reports.",
    "Pass credentials through the `env` block, referencing an environment variable, not inline in args.",
))
R_PROJECT = register(Rule(
    "AGS-MCP-007", "Repository ships project-scoped MCP servers", Severity.LOW, "trust-boundary",
    "This repository defines MCP servers that execute local commands. When a developer opens the folder and "
    "approves project servers, these commands run on their machine. Review them like any other executable code.",
    "Document every project MCP server, keep them minimal and pinned, and require code-owner review for "
    "changes to MCP config files (CODEOWNERS).",
))
R_URLSECRET = register(Rule(
    "AGS-MCP-008", "Credential embedded in MCP server URL", Severity.HIGH, "secrets",
    "The remote MCP server URL carries a key/token in the query string or userinfo. URLs are logged by "
    "proxies, browsers and servers.",
    "Send credentials in an Authorization header sourced from an environment variable, or use OAuth.",
))
R_UNTRUSTED_SRC = register(Rule(
    "AGS-MCP-009", "MCP server installed from an unvetted source", Severity.MEDIUM, "supply-chain",
    "The server is installed directly from a git repository, tarball or arbitrary URL rather than a "
    "registry release, bypassing registry malware scanning and immutable versioning.",
    "Install from a registry with a pinned version, or vendor and review the code, pinning to a commit SHA.",
))
R_PARSE = register(Rule(
    "AGS-MCP-010", "MCP configuration could not be parsed", Severity.LOW, "hygiene",
    "The file could not be parsed, so its servers could not be audited. Agents may also silently ignore it.",
    "Fix the syntax error so the configuration can be validated.",
))
R_AUTOAPPROVE = register(Rule(
    "AGS-MCP-011", "MCP tools auto-approved without confirmation", Severity.HIGH, "human-in-the-loop",
    "Tools from this MCP server are set to run without user confirmation (autoApprove / alwaysAllow / "
    "trust: true). Combined with prompt injection this lets attacker-controlled content trigger actions silently.",
    "Remove blanket auto-approval. Allow-list only specific read-only tools when necessary.",
))
R_AGENT_YOLO = register(Rule(
    "AGS-MCP-012", "Agent sandbox or approvals disabled in configuration", Severity.HIGH, "human-in-the-loop",
    "The agent is configured to run without a sandbox and/or without approval prompts "
    "(e.g. Codex `danger-full-access` / `approval_policy = \"never\"`, Gemini `yolo`/`autoAccept`).",
    "Keep the sandbox enabled and require approval for commands. Use full-access modes only in disposable environments.",
))

RUNNERS = {"npx", "npx.cmd", "bunx", "pnpx", "uvx", "pipx", "dlx"}
SHELLS = {"bash", "sh", "zsh", "dash", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
PIPE_SHELL = re.compile(r"(curl|wget|iwr|Invoke-WebRequest)[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|iex\s*\(|Invoke-Expression|-enc(odedcommand)?\b|base64\s+(-d|--decode)", re.I)
BROAD_PATHS = re.compile(r"""^(/|~|~/|\$HOME|\$\{HOME\}|%USERPROFILE%|/home|/Users|/root|[A-Za-z]:\\?|/etc|/var)/?$""")
SECRET_FLAG = re.compile(r"(?i)^--?(api[-_]?key|token|access[-_]?token|secret|password|pat|auth)(=(.+))?$")
SECRET_QS = re.compile(r"(?i)(api[-_]?key|token|access[-_]?token|secret|key|auth|password)")
PRIV_DOCKER = re.compile(r"^(--privileged|--network=host|--net=host|--pid=host|--cap-add=(ALL|SYS_ADMIN))$")
DOCKER_SOCK = "/var/run/docker.sock"


def _servers(sf):
    """Return (servers_dict, top_level_dict) or raise ValueError."""
    if sf.path.endswith(".toml"):
        data = tomllib.loads(sf.content)
        return data.get("mcp_servers", {}) or {}, data
    data = json.loads(sf.content) if sf.content.strip() else {}
    if not isinstance(data, dict):
        return {}, {}
    servers = {}
    for key in ("mcpServers", "servers", "mcp_servers", "context_servers"):
        v = data.get(key)
        if isinstance(v, dict):
            servers.update(v)
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        servers.update(mcp["servers"])
    return servers, data


def _is_versioned(pkg: str) -> bool:
    # @scope/name@1.2.3  | name@1.2.3 | name==1.2.3
    if "==" in pkg:
        return True
    body = pkg[1:] if pkg.startswith("@") else pkg
    if "@" in body:
        ver = body.split("@", 1)[1]
        return bool(ver) and ver not in {"latest", "next", "*"}
    return False


@check("mcp_config")
def scan_mcp(sf):
    try:
        servers, top = _servers(sf)
    except (ValueError, tomllib.TOMLDecodeError) as e:
        yield finding(R_PARSE, sf, 1, f"Parse error: {e}")
        return

    yield from _agent_modes(sf, top)

    local_servers = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        ln = line_of(sf.content, f'"{name}"') if not sf.path.endswith(".toml") else line_of(sf.content, name)
        command = str(cfg.get("command") or "")
        args = [str(a) for a in (cfg.get("args") or []) if a is not None] if isinstance(cfg.get("args"), list) else []
        url = str(cfg.get("url") or cfg.get("serverUrl") or cfg.get("httpUrl") or "")
        cmd_base = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
        full = " ".join([command, *args])

        if command:
            local_servers.append(name)

        # 001 / 009 runner-based packages
        if cmd_base in RUNNERS or (cmd_base in {"npm", "pnpm", "yarn"} and args[:1] in (["exec"], ["dlx"])):
            pkg = _first_pkg(args, cmd_base)
            if pkg:
                if re.match(r"^(git\+|github:|gitlab:|https?://|file:|\.\.?/)", pkg) or pkg.endswith((".tgz", ".tar.gz", ".whl")):
                    yield finding(R_UNTRUSTED_SRC, sf, ln, f"Server '{name}' installs from '{pkg}'", full)
                elif not _is_versioned(pkg) and "--from" not in args:
                    yield finding(R_UNPINNED, sf, ln, f"Server '{name}' runs '{pkg}' without a pinned version", full)
            for i, a in enumerate(args):
                if a == "--from" and i + 1 < len(args) and re.match(r"^(git\+|https?://)", args[i + 1]):
                    yield finding(R_UNTRUSTED_SRC, sf, ln, f"Server '{name}' installs from '{args[i+1]}'", full)

        # 003 shell launchers
        if (cmd_base in SHELLS and any(a in {"-c", "/c", "-Command", "-command", "-EncodedCommand", "-enc"} for a in args)) or PIPE_SHELL.search(full):
            yield finding(R_SHELL, sf, ln, f"Server '{name}' is launched via an inline shell command", full)

        # 004 broad filesystem
        if "filesystem" in full.lower() or "fs-server" in full.lower() or name.lower() in {"filesystem", "fs"}:
            for a in args:
                if BROAD_PATHS.match(a.strip()):
                    yield finding(R_FS, sf, ln, f"Server '{name}' is granted access to '{a}'", full)

        # 005 docker
        if cmd_base in {"docker", "podman"}:
            for i, a in enumerate(args):
                nxt = args[i + 1] if i + 1 < len(args) else ""
                if PRIV_DOCKER.match(a):
                    yield finding(R_DOCKER, sf, ln, f"Server '{name}' container uses '{a}'", full)
                elif a in {"--network", "--net", "--pid"} and nxt == "host":
                    yield finding(R_DOCKER, sf, ln, f"Server '{name}' container uses '{a} host'", full)
                if DOCKER_SOCK in a:
                    yield finding(R_DOCKER, sf, ln, f"Server '{name}' mounts the Docker socket", full)
                if a in {"-v", "--volume"} and re.match(r"^(/|~|\$HOME|/home/[^/:]+|/Users/[^/:]+|/root):", nxt):
                    yield finding(R_DOCKER, sf, ln, f"Server '{name}' mounts host path '{nxt.split(':')[0]}'", full)

        # 006 secrets in args
        for i, a in enumerate(args):
            m = SECRET_FLAG.match(a)
            if m:
                val = m.group(3) or (args[i + 1] if i + 1 < len(args) else "")
                if val and not val.startswith("$") and not val.startswith("-") and len(val) >= 8:
                    yield finding(R_ARGSECRET, sf, ln, f"Server '{name}' passes '{a.split('=')[0]}' inline", a.split("=")[0] + " ****")

        # 002 / 008 remote URL
        if url:
            u = urlparse(url)
            host = (u.hostname or "").lower()
            if u.scheme == "http" and host not in {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}:
                yield finding(R_HTTP, sf, ln, f"Server '{name}' uses {url}", url)
            if u.password or any(SECRET_QS.search(k) and v and not v[0].startswith("$") for k, v in ((k, vs[0]) for k, vs in parse_qs(u.query).items())):
                yield finding(R_URLSECRET, sf, ln, f"Server '{name}' URL carries credentials", u._replace(query="****", netloc=host).geturl())

        # 011 auto-approve
        auto = cfg.get("autoApprove") or cfg.get("alwaysAllow") or cfg.get("auto_approve")
        if cfg.get("trust") is True or auto == "*" or (isinstance(auto, list) and ("*" in auto or len(auto) >= 5)) or auto is True:
            yield finding(R_AUTOAPPROVE, sf, ln, f"Server '{name}' tools are auto-approved", json.dumps({k: cfg[k] for k in cfg if k in {"autoApprove", "alwaysAllow", "trust", "auto_approve"}}))

    # 007 project-scoped servers that run local commands
    if local_servers and sf.agent != "claude-desktop":
        yield finding(R_PROJECT, sf, 1, f"{len(local_servers)} local MCP server(s) defined: {', '.join(local_servers[:8])}")


def _agent_modes(sf, top):
    if not isinstance(top, dict):
        return
    if sf.path.endswith(".toml"):
        if top.get("sandbox_mode") == "danger-full-access":
            yield finding(R_AGENT_YOLO, sf, line_of(sf.content, "sandbox_mode"), "Codex sandbox_mode = danger-full-access", 'sandbox_mode = "danger-full-access"')
        if top.get("approval_policy") == "never":
            yield finding(R_AGENT_YOLO, sf, line_of(sf.content, "approval_policy"), "Codex approval_policy = never", 'approval_policy = "never"')
    else:
        for key in ("autoAccept", "yolo", "yoloMode"):
            if top.get(key) is True:
                yield finding(R_AGENT_YOLO, sf, line_of(sf.content, f'"{key}"'), f"'{key}' is enabled", f'"{key}": true')
        tools = top.get("tools") if isinstance(top.get("tools"), dict) else {}
        if top.get("sandbox") is False or tools.get("sandbox") is False:
            yield finding(R_AGENT_YOLO, sf, line_of(sf.content, '"sandbox"'), "Sandbox explicitly disabled", '"sandbox": false')


def _first_pkg(args: list[str], runner: str) -> str | None:
    skip_next = {"--package", "-p", "--from", "--python", "--registry", "--with"}
    i = 0
    if runner in {"npm", "pnpm", "yarn"}:
        i = 1
    while i < len(args):
        a = args[i]
        if a in skip_next:
            if a in {"--package", "-p"} and i + 1 < len(args):
                return args[i + 1]
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        if a == "--":
            i += 1
            continue
        return a
    return None
