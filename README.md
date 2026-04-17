# Argus — MCP Prompt-Injection Firewall

An MCP-native security firewall that sits between AI agents and their tools,
inspecting every tool call and response for prompt injection, credential
exfiltration, and policy violations.

Built for the A10 Networks Hackathon (April 17-18, 2026, Track 2).

> *"Argus had a hundred eyes. Ours has one for every tool call."*

## Quickstart

```bash
# 1. Install deps (uses uv + Python 3.11)
uv sync

# 2. Add your Anthropic API key
cp .env.example .env
# edit .env and paste your ANTHROPIC_API_KEY

# 3. Run the scripted demo
./run_demo.sh
```

`run_demo.sh` starts the MCP server + Argus, opens the dashboard in your
browser, and walks through three scenarios with pause points so you can
narrate each phase to judges.

## Architecture

```
victim_agent.py  --MCP-->  proxy.py (Argus)  --MCP-->  server.py (tools)
                             |    ^
                             v    |
                          detector.py  (regex / LLM judge)
                             |
                             v
                        /events websocket
                             |
                             v
                        ui/index.html (live dashboard)
```

- `proxy.py` — FastAPI MCP proxy on `:8000`; runs every tool call and response
  through the identity layer + detector and emits events.
- `auth.py` — JWT-based identity layer with per-agent scope policy.
- `detector.py` — layered detection: regex patterns (credentials + injection
  phrases) then Claude-as-judge for novel content.
- `server.py` — real MCP server on `:8001` exposing `read_document`,
  `shell_exec`, and `fetch_github_file` (cached in memory).
- `victim_agent.py` — Claude-based agent that uses tools via the proxy. Two
  personas via `AGENT_ROLE`: `onboarding` (reads local docs) and `coding`
  (pulls CLAUDE.md from a public GitHub repo, Claude-Code-style).
- `ui/index.html` — single-page dashboard streaming events over websocket,
  with per-agent color-coded rows and a "layer" column showing which
  defense caught each block.
- `scratch/test_mcp.py` — basic MCP client sanity check.
- `scratch/attack_exfil.py` — direct-MCP attack simulating a compromised
  agent calling `shell_exec` with a credential-exfil command.
- `scratch/warmup_gh_cache.py` — pre-warms the GitHub-fetch cache so
  Scenario 4 works offline after one successful run.

## Demo scenarios

### Scenario 1 — poisoned response (baseline: Argus bypassed)

```bash
# Two terminals
uv run python server.py                                              # :8001
ARGUS_URL=http://127.0.0.1:8001/mcp uv run python victim_agent.py   # direct
```

Agent reads `documents/onboarding.md`. The doc contains fake AWS
credentials in plain sight. Without Argus in front, the credentials end up
inside the agent's context — visible in logs, token accounting, and any
future jailbreak.

### Scenario 2 — same attack, through Argus

```bash
uv run python server.py    # still running
uv run python proxy.py     # :8000 (Argus)
uv run python victim_agent.py   # defaults to Argus on :8000
```

Argus regex layer detects the AWS key format in the upstream response,
replaces the response with a sanitised error, and pushes a `block` event
to the dashboard in real time. The agent never sees the credentials.

### Scenario 3 — outbound exfil (credential exfil via tool args)

```bash
# Direct, Argus OFF: the shell command actually executes.
uv run python scratch/attack_exfil.py http://127.0.0.1:8001/mcp

# Through Argus: the call is blocked before execution.
uv run python scratch/attack_exfil.py http://127.0.0.1:8000/mcp
```

Argus inspects both directions. A compromised client trying to call
`shell_exec("curl -d \"$(cat ...credentials)\"")` is caught at the regex
layer on the outbound side and never reaches the real tool.

### Scenario 4 — poisoned GitHub CLAUDE.md (Claude Code CVE pattern)

Mirrors the Claude Code CLAUDE.md exploit disclosed March 31, 2026:
a developer clones what looks like a normal public repo, a coding
assistant reads the repo's `CLAUDE.md` for project conventions, and the
file hijacks the agent. Judges can visit the repo on their phones and
verify the attack surface is real.

```bash
# Pre-warm the cache once (uses network)
uv run python scratch/warmup_gh_cache.py

# Run the coding agent through Argus
AGENT_ROLE=coding AGENT_ID=coding-bot uv run python victim_agent.py

# Identity guard: non-privileged agent can't fetch the repo at all
AGENT_ROLE=coding AGENT_ID=onboarding-bot uv run python victim_agent.py
```

The `coding-bot` identity has `fetch_github_file` scope but *not*
`shell_exec` — exactly what a real coding agent should carry. Argus
catches the injection in the response with its regex or LLM-judge layer
(depending on the `CLAUDE.md` payload). The dashboard shows a
colour-coded `coding-bot` row and the layer badge that blocked.

## Configuration (environment)

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | required (victim agent + LLM-judge layer) |
| `ARGUS_UPSTREAM` | `http://127.0.0.1:8001/mcp` | upstream MCP URL for the proxy |
| `ARGUS_HOST` | `127.0.0.1` | proxy bind host |
| `ARGUS_PORT` | `8000` | proxy bind port |
| `ARGUS_DETECT` | `1` | `0` turns the detector off (pure passthrough) |
| `ARGUS_IDENTITY` | `1` | `0` disables the identity/scope check |
| `ARGUS_LLM_RESPONSES` | `1` | run LLM judge on inbound responses |
| `ARGUS_LLM_CALLS` | `0` | run LLM judge on outbound calls (off by default to keep latency predictable) |
| `ARGUS_JUDGE_MODEL` | `claude-sonnet-4-6` | model used by the LLM judge |
| `ARGUS_GH_NO_CACHE` | — | set to `1` to bypass the GitHub fetch cache |
| `ARGUS_JWT_SECRET` | demo-value | HMAC secret for the identity layer (rotate for real deployments) |
| `ARGUS_URL` | `http://127.0.0.1:8000/mcp` | endpoint `victim_agent.py` connects to |
| `VICTIM_MODEL` | `claude-haiku-4-5-20251001` | model used by the victim agent |
| `AGENT_ID` | `deploy-bot` | which identity the agent presents (`deploy-bot` / `onboarding-bot` / `coding-bot`) |
| `AGENT_ROLE` | `onboarding` | victim-agent persona (`onboarding` / `coding`) |
| `GH_REPO` | `akrai37/mcp-toolkit` | which public GitHub repo the coding-assistant reads |
| `GH_BRANCH` | `main` | branch to fetch from |

## Project context

See [argus-project-brief.md](argus-project-brief.md) for the full hackathon
brief — pitch script, judge Q&A prep, detection design notes. See
[CLAUDE.md](CLAUDE.md) for conventions Claude Code should follow when
editing this project.
