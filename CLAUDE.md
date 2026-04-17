# Argus — MCP Prompt-Injection Firewall

## Goal
Build an MCP proxy that inspects tool calls and tool responses for prompt
injection, credential exfiltration, and policy violations — blocking
malicious traffic before it reaches the agent. Read `argus-project-brief.md`
for the full hackathon context, architecture, and build plan.

## Architecture
- `proxy.py` (FastAPI): MCP proxy that forwards to the real MCP server
  and runs each payload through `detector.assess()`.
- `detector.py`: three layers — regex, embedding similarity, LLM judge.
- `server.py`: real MCP server exposing `read_document`, `shell_exec`.
- `victim_agent.py`: Claude-based agent that uses tools via the proxy.
- `ui/index.html`: vanilla JS dashboard showing live events via websocket.

## Conventions
- Python 3.11, type hints on every public function.
- Small functions. Prefer composition over inheritance.
- FastAPI for the proxy; websockets for the event stream.
- No DB. In-memory event log (collections.deque).
- Use the official `mcp` Python SDK and the `anthropic` SDK.
- Log structured events (dict) to an in-memory deque AND push over websocket.
- Use `claude-opus-4-6` for the victim agent; `claude-sonnet-4-6` for the detector LLM judge.
- Run everything via `uv run ...` (project uses uv + pyproject.toml).

## Do not
- Do not rewrite files outside the one you were asked to modify.
- Do not add new dependencies without asking.
- Do not invent MCP SDK APIs — check the installed SDK first (`uv run python -c "import mcp; print(mcp.__file__)"`).
- Do not batch multiple features into one turn.

## Verdict dataclass (detector.py)
```python
from dataclasses import dataclass
from typing import Literal

@dataclass
class Verdict:
    score: float
    action: Literal["allow", "quarantine", "block"]
    reason: str
    layer: Literal["regex", "embedding", "llm"]
```

## Detection thresholds
- `score < 0.5`  -> allow
- `0.5 <= score < 0.8` -> quarantine (pass through with warning event)
- `score >= 0.8` -> block (replace response with sanitized error)
- Short-circuit: once any layer returns block, skip later layers.

## Event shape (for /events websocket)
```json
{
  "timestamp": "2026-04-17T10:23:15Z",
  "tool": "read_document",
  "direction": "response",
  "args_preview": "onboarding.md",
  "verdict": { "score": 0.92, "action": "block", "reason": "...", "layer": "regex" }
}
```
