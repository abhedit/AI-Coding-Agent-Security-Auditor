# Prior art: open-source work in this domain

Before building, we surveyed open-source projects that audit AI coding agents and MCP
configuration. Listed below is what each does well and what this platform took from it.
Popularity and maintenance status change quickly, so check each repo before you rely on it.

| Project | What it does | Approach we adopted |
|---|---|---|
| **Snyk agent-scan** (formerly Invariant Labs **mcp-scan**) — github.com/snyk/agent-scan | Auto-discovers MCP configs, connects to the servers, and checks tool descriptions for prompt injection, tool poisoning, "toxic flows" and vulnerable skills. Can also run as a proxy. | Tool-poisoning taxonomy: hidden `<IMPORTANT>` instructions, cross-tool shadowing, rug-pulls. We check **exported tool manifests** instead of launching servers. Their README warns that starting stdio servers from untrusted config is itself a risk. |
| **AgentShield** — github.com/affaan-m/agentshield | Audits Claude Code setups (secrets, permissions, hook injection, MCP risks, agent prompt injection). Ships as a CLI, a GitHub Action, and a GitHub App. | Claude Code focus on `settings.json` permissions and hooks. The **CLI + Action + hosted app** product shape. |
| **mcp-audit** (`mcp-audit-scanner`, Apache-2.0) | Privacy-first scanner for MCP configs. `scan --project` warns *before* you trust a cloned folder. Covers CLAUDE.md and Cursor rules. Emits SARIF. | The **"repo ships project-scoped MCP servers"** trust-boundary rule (AGS-MCP-007), SARIF output, and the privacy-first default (CLI runs locally; only agent config files are ever uploaded). |
| **AgentAuditKit** (`agent-audit-kit`, MIT) | Large rule set across many agent platforms, SARIF to the GitHub Security tab, GitHub Marketplace action. | Multi-platform discovery table and the SARIF + Marketplace-action CI story. |
| **MCPGuard**, **mcpscan**, **aisecscan**, **CodeGate**, **ai-coding-shield**, **MEDUSA** | Variations: secrets, dangerous permissions, supply-chain and hidden-Unicode checks in steering files, plus fail-on-severity CI modes. | `--fail-on` severity gating, hidden-Unicode detection in steering files, and unpinned `npx -y` supply-chain checks. |
| **Cisco AI Agent Security Scanner for IDEs** (commercial) | Inspects SKILL.md and referenced scripts without executing them, and watches AI config files for unauthorized changes. | Skill-file coverage (AGS-AG-003) and a **never execute** design principle. |
| **Pillar Security "Rules File Backdoor"** research | Showed that invisible Unicode in `.cursorrules` and Copilot instructions can smuggle hidden directives past code review. | AGS-PI-001 decodes Unicode tag characters and shows the hidden text as evidence. |

## Gaps we fill

1. **A hosted SaaS around the engine.** The open-source tools are CLIs. This platform adds
   multi-tenant workspaces, scan history and trend lines, posture scoring and grades, team
   members, API keys, an audit log, plan quotas, billing, README badges and an operator console.
2. **One engine for every agent.** It covers Claude Code, Cursor, Copilot, Codex, Gemini CLI,
   Windsurf, Cline, Roo, Kiro, Amazon Q and plain MCP configs, plus the CI workflows that run these agents.
3. **Safe by construction.** It never launches MCP servers. Zip archives are read in memory and
   never extracted. Git clones are shallow and HTTPS-only, with hooks disabled and only allow-listed
   hosts. Secrets are masked in evidence.
4. **Low-noise rules.** Rules were tuned against real repositories (anthropics/claude-code,
   modelcontextprotocol/servers and openai/codex), with regression tests for the false positives we found.

## Known limits

Static analysis can't see prompt injection that arrives at runtime through web pages, issues or
tool output. It also can't catch a rug-pull, where a server changes its tool descriptions after
approval, unless you re-export the manifest and scan again. A runtime proxy or guardrail product
is the natural next step (see the roadmap in the README).
