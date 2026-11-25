# AgentSentinel: AI Coding Agent Security Auditor
*A SaaS offering by Abhijit*

AI coding agents such as Claude Code, Cursor, GitHub Copilot, Codex, Gemini CLI and Windsurf
treat their configuration files as trusted instructions. These include MCP server definitions,
permission settings, hooks, `CLAUDE.md`/`AGENTS.md`/`.cursorrules` and skills. A malicious pull
request, a poisoned dependency or a compromised MCP server only has to change one of those files
to take over the agent, and through it the developer's machine and credentials.

**AgentSentinel** audits that attack surface. It ships as:

- a **hosted SaaS** with workspaces, history, posture scores, teams, API keys, billing and an admin console
- a **zero-dependency CLI** (`agent-auditor`) that runs locally
- a **GitHub Action** that gates pull requests and uploads SARIF to GitHub code scanning
- a **REST API** (OpenAPI docs at `/api/docs`)

Branding is set through environment variables (`BRAND_NAME`, `BRAND_OWNER`, ...). See [`.env.example`](.env.example).

## Detection coverage (45 rules)

| Family | Examples |
|---|---|
| Prompt injection / rules-file backdoors (`AGS-PI-*`) | Invisible Unicode tag, zero-width and bidi characters (hidden text is decoded), "ignore previous instructions", "don't tell the user", hidden HTML comments, base64/hex payloads |
| Exfiltration & persistence | `curl $(env)` to webhook.site/ngrok, reading `~/.ssh` or `.aws/credentials`, edits to `.bashrc`/crontab/`.mcp.json`, API base-URL hijacks (`ANTHROPIC_BASE_URL`) |
| MCP supply chain & transport (`AGS-MCP-*`) | Unpinned `npx -y`/`uvx`, git/tarball installs, `bash -c`/`curl \| sh` launchers, privileged Docker or docker.sock, plaintext `http://` servers, credentials in URLs/args, auto-approved tools |
| Over-privilege (`AGS-CC-*`, `AGS-AG-*`) | `bypassPermissions`, `Bash(*)`, risky wildcards (`curl:*`, `python:*`), Codex `danger-full-access`, Gemini YOLO, sub-agents that inherit every tool, no deny rules for secrets |
| Tool poisoning (`AGS-TP-*`) | `<IMPORTANT>` instructions in tool descriptions, cross-tool shadowing, side-channel params (`sidenote`), duplicate tool names |
| Agents in CI (`AGS-CI-*`) | Issue/comment text interpolated into an agent prompt, `pull_request_target`, `--dangerously-skip-permissions` in CI, write-all tokens |
| Secrets (`AGS-SEC-*`) | Anthropic/OpenAI/AWS/GitHub/GitLab/Slack/Stripe/Google keys, private keys, DB URLs (masked in reports) |

You can browse the full catalog at `/rules` or with `agent-auditor rules`. To suppress a line, add
`agent-auditor: ignore`. To suppress a whole file, add `agent-auditor: ignore-file`. You can also
disable rules for a single project.

[`docs/RESEARCH.md`](docs/RESEARCH.md) covers the open-source projects this builds on: Snyk
agent-scan/mcp-scan, AgentShield, mcp-audit, AgentAuditKit and others.

## Quick start

```bash
# CLI only (pure standard library)
pip install .
agent-auditor scan /path/to/repo
agent-auditor scan . -f sarif -o agent.sarif --fail-on critical

# SaaS locally
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload        # http://localhost:8000. The first sign-up becomes the admin.

# Production (app + Postgres)
cp .env.example .env    # set SECRET_KEY, BASE_URL, ADMIN_EMAILS, branding, optional Stripe
docker compose up -d
```

Put a TLS-terminating reverse proxy in front (Caddy, nginx or a cloud load balancer), and set `SECURE_COOKIES=true`.

### GitHub Action

```yaml
permissions: { contents: read, security-events: write }
steps:
  - uses: actions/checkout@v4
  - uses: abhedit/AI-Coding-Agent-Security-Auditor@main
    with:
      fail-on: high
      api-key: ${{ secrets.AGENT_AUDITOR_API_KEY }}   # optional: record history in the SaaS
      api-url: https://your-deployment
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with: { sarif_file: agent-auditor.sarif }
```

### API

```bash
curl -X POST $BASE_URL/api/v1/scans -H "Authorization: Bearer ags_..." \
  -H "Content-Type: application/json" \
  -d '{"project":"web","files":{".mcp.json":"{...}","CLAUDE.md":"..."}}'
curl -X POST $BASE_URL/api/v1/scans/git -H "Authorization: Bearer ags_..." \
  -d '{"url":"https://github.com/owner/repo"}' -H "Content-Type: application/json"
```

Other endpoints are `GET /api/v1/scans`, `/scans/{id}`, `/scans/{id}/sarif` (Pro+), `/usage` and `/rules`.

## The SaaS business

| Plan | Price | Limits |
|---|---|---|
| Starter | Free | 30 scans/mo, 2 projects, 14-day history |
| Pro | $29/mo | 1,000 scans, 25 projects, SARIF, badges, 1-yr history |
| Team | $99/mo | 10,000 scans, 250 projects, 25 members |
| Enterprise | Custom | Self-host/VPC, SSO, custom rules, security workshops with Abhijit |

Prices and limits live in [`app/plans.py`](app/plans.py).

**Billing** runs in one of two modes:

- **Stripe mode.** Set `STRIPE_SECRET_KEY`, `STRIPE_PRICE_PRO`, `STRIPE_PRICE_TEAM` and `STRIPE_WEBHOOK_SECRET`, then point a Stripe webhook at `/billing/webhook`. Checkout, the customer portal and plan sync then work automatically.
- **Manual mode** (the default). Customers click *Request upgrade*. The request shows up in `/admin`, where you set the plan after you invoice them.

The **operator console** at `/admin` lists workspaces, owners, monthly usage, list MRR and upgrade requests, and lets you change a workspace's plan.

## Architecture

```
auditor/            pure-stdlib scan engine (usable as a library)
  discovery.py      maps 45+ known agent-config paths -> (kind, agent)
  rules/            secrets, mcp, claude_settings, instructions, agents, tools, workflows
  scanner.py        orchestration, de-dup, scoring (0-100, A-F)
  sarif.py, cli.py
app/                FastAPI SaaS
  main.py           web UI (Jinja2, CSP-strict, no inline JS), auth, billing, admin
  api.py            REST v1 (API-key auth)
  services.py       zip/git ingestion, quotas, persistence
  db.py             SQLAlchemy models: Organization, User, Project, Scan, ApiKey, AuditEvent
```

**Security of the platform itself:**

- Passwords are hashed with scrypt. API keys are stored only as SHA-256 hashes and shown once.
- Every form is CSRF-protected. Session cookies are signed. Next-URLs are checked to block open redirects.
- Strict CSP and security headers are set on every response.
- Every query is tenant-scoped. Tests cover cross-tenant access.
- Zip uploads are read in memory with entry and size caps, so zip-slip is impossible.
- Git clones are HTTPS-only to allow-listed hosts, depth 1, with hooks and symlinks off and a timeout.
- MCP servers are never executed.

## Tests

```bash
pip install pytest && pytest -q     # 27 tests: engine, CLI, SaaS flows, tenancy, CSRF, quotas
```

## Roadmap

- GitHub App: scans every PR automatically and posts inline review comments
- Rug-pull monitoring: scheduled re-export and diff of MCP tool manifests
- Custom rules (YAML) per workspace, plus policy packs (SOC 2, ISO 27001 mappings)
- SSO (SAML/OIDC) and email invitations for Team and Enterprise
- Background job queue for large Git scans; Alembic migrations
- Runtime guard: an MCP proxy that applies the same rules to live tool traffic
