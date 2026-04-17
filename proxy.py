"""Argus — MCP proxy with inline detection + identity + event streaming.

Responsibilities:
- Forward list_tools / call_tool to the upstream MCP server at :8001.
- Verify the agent's JWT identity on each request (see auth.py).
- Enforce per-agent scope policy before forwarding a tool call.
- Run `detector.assess` on every outbound tool-call argument and every
  inbound tool response.
- On a blocking verdict (identity or content): replace the payload with
  a sanitised error so the agent cannot consume it.
- Emit a structured event for every boundary (list_tools, call, response)
  into an in-memory ring buffer and push it to every connected websocket
  client at /events.

Run with:  uv run python proxy.py
"""
from __future__ import annotations

import asyncio
import contextlib
import contextvars
import datetime as dt
import json
import logging
import os
from collections import deque
from typing import Any

import mcp.types as types
import uvicorn
from dotenv import load_dotenv
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.responses import JSONResponse, FileResponse
from starlette.websockets import WebSocket, WebSocketDisconnect

from auth import Identity, allowed, verify
from detector import Verdict, assess

load_dotenv()

UPSTREAM_URL = os.environ.get("ARGUS_UPSTREAM", "http://127.0.0.1:8001/mcp")
LISTEN_HOST = os.environ.get("ARGUS_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("ARGUS_PORT", "8000"))
DETECTION_ENABLED = os.environ.get("ARGUS_DETECT", "1") != "0"
IDENTITY_ENFORCED = os.environ.get("ARGUS_IDENTITY", "1") != "0"
# Keep the LLM judge off for the tool-call (outbound) direction by
# default — shell_exec args are tiny and the regex layer already covers
# the nasty cases (curl -d "$(cat ...)"). Easy to enable later.
LLM_JUDGE_RESPONSES = os.environ.get("ARGUS_LLM_RESPONSES", "1") != "0"
LLM_JUDGE_CALLS = os.environ.get("ARGUS_LLM_CALLS", "0") != "0"

EVENT_RING_SIZE = 500

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
log = logging.getLogger("argus.proxy")

server: Server = Server("argus-proxy")
upstream: ClientSession | None = None

event_log: deque[dict[str, Any]] = deque(maxlen=EVENT_RING_SIZE)
event_subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

# Set per-request by handle_streamable_http; read by tool handlers.
current_identity: contextvars.ContextVar[Identity | None] = contextvars.ContextVar(
    "current_identity", default=None
)


def _extract_bearer(scope: dict[str, Any]) -> str | None:
    for raw_name, raw_value in scope.get("headers", []):
        if raw_name.lower() == b"authorization":
            value = raw_value.decode("latin-1", errors="replace").strip()
            if value.lower().startswith("bearer "):
                return value[7:].strip()
    return None


def _identity_dict(identity: Identity | None) -> dict[str, Any]:
    if identity is None:
        return {"agent_id": None, "scopes": []}
    return {"agent_id": identity.agent_id, "scopes": list(identity.scopes)}


# ---------------------------------------------------------------------------
# Event plumbing
# ---------------------------------------------------------------------------


def _emit_event(payload: dict[str, Any]) -> None:
    payload = {"timestamp": dt.datetime.utcnow().isoformat() + "Z", **payload}
    event_log.append(payload)
    for queue in list(event_subscribers):
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            log.warning("subscriber queue full, dropping event")


def _preview(obj: Any, limit: int = 200) -> str:
    if obj is None:
        return ""
    text = obj if isinstance(obj, str) else json.dumps(obj, default=str)
    text = text.replace("\n", " ")
    return text[:limit] + ("…" if len(text) > limit else "")


def _content_to_text(blocks: list[types.ContentBlock]) -> str:
    out: list[str] = []
    for block in blocks:
        text = getattr(block, "text", None)
        if text:
            out.append(text)
    return "\n".join(out)


def _sanitised_error(tool: str, reason: str) -> types.CallToolResult:
    """Response Argus returns to the agent when a call is blocked."""
    msg = (
        f"[Argus] Tool call to `{tool}` was blocked by the prompt-injection "
        f"firewall.\nReason: {reason}\nNo downstream call was made."
    )
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=msg)],
        isError=True,
    )


def _redacted_response(
    original: types.CallToolResult, reason: str
) -> types.CallToolResult:
    """Rewrite an inbound response so the agent only sees a notice."""
    msg = (
        f"[Argus] Upstream response was blocked by the prompt-injection "
        f"firewall and will not be forwarded to the agent.\nReason: {reason}"
    )
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=msg)],
        isError=True,
    )


# ---------------------------------------------------------------------------
# MCP handlers
# ---------------------------------------------------------------------------


@server.list_tools()
async def _list_tools() -> list[types.Tool]:
    assert upstream is not None
    identity = current_identity.get()
    result = await upstream.list_tools()
    log.info("list_tools agent=%s -> %d tools",
             identity.agent_id if identity else "-", len(result.tools))
    _emit_event({
        "kind": "list_tools",
        "tool": None,
        "direction": None,
        "count": len(result.tools),
        "identity": _identity_dict(identity),
    })
    return result.tools


@server.call_tool()
async def _call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
    assert upstream is not None
    identity = current_identity.get()
    identity_payload = _identity_dict(identity)

    # --- identity / policy check -----------------------------------------
    if IDENTITY_ENFORCED:
        ok, why = allowed(identity, name)
        if not ok:
            policy_verdict = Verdict(
                score=1.0,
                action="block",
                reason=why,
                layer="identity",
            )
            _emit_event({
                "kind": "call",
                "tool": name,
                "direction": "call",
                "args_preview": _preview(arguments),
                "verdict": policy_verdict.as_dict(),
                "identity": identity_payload,
            })
            _emit_event({
                "kind": "blocked_call",
                "tool": name,
                "direction": "call",
                "verdict": policy_verdict.as_dict(),
                "identity": identity_payload,
            })
            log.info("identity block agent=%s tool=%s: %s",
                     identity_payload["agent_id"], name, why)
            return _sanitised_error(name, f"identity policy: {why}")

    # --- outbound (call) inspection --------------------------------------
    call_content = json.dumps(arguments, ensure_ascii=False)
    if DETECTION_ENABLED:
        call_verdict: Verdict = assess(call_content, "call", use_llm=LLM_JUDGE_CALLS)
    else:
        call_verdict = Verdict(0.0, "allow", "detection disabled", "regex")
    _emit_event({
        "kind": "call",
        "tool": name,
        "direction": "call",
        "args_preview": _preview(arguments),
        "verdict": call_verdict.as_dict(),
        "identity": identity_payload,
    })
    log.info("call  <- %s agent=%s action=%s score=%.2f", name,
             identity_payload["agent_id"], call_verdict.action, call_verdict.score)
    if call_verdict.action == "block":
        blocked = _sanitised_error(name, call_verdict.reason)
        _emit_event({
            "kind": "blocked_call",
            "tool": name,
            "direction": "call",
            "verdict": call_verdict.as_dict(),
            "identity": identity_payload,
        })
        return blocked

    # --- forward ----------------------------------------------------------
    result = await upstream.call_tool(name, arguments)

    # --- inbound (response) inspection -----------------------------------
    resp_text = _content_to_text(result.content)
    if DETECTION_ENABLED:
        resp_verdict: Verdict = assess(resp_text, "response", use_llm=LLM_JUDGE_RESPONSES)
    else:
        resp_verdict = Verdict(0.0, "allow", "detection disabled", "regex")
    _emit_event({
        "kind": "response",
        "tool": name,
        "direction": "response",
        "args_preview": _preview(resp_text),
        "verdict": resp_verdict.as_dict(),
        "is_error": bool(result.isError),
        "identity": identity_payload,
    })
    log.info("resp  -> %s agent=%s action=%s score=%.2f blocks=%d",
             name, identity_payload["agent_id"],
             resp_verdict.action, resp_verdict.score, len(result.content))
    if resp_verdict.action == "block":
        redacted = _redacted_response(result, resp_verdict.reason)
        _emit_event({
            "kind": "blocked_response",
            "tool": name,
            "direction": "response",
            "verdict": resp_verdict.as_dict(),
            "identity": identity_payload,
        })
        return redacted

    return result


# ---------------------------------------------------------------------------
# Upstream lifespan + streamable-http plumbing
# ---------------------------------------------------------------------------


@contextlib.asynccontextmanager
async def _upstream_session_lifespan():
    global upstream
    log.info("connecting to upstream %s", UPSTREAM_URL)
    async with streamablehttp_client(UPSTREAM_URL) as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()
            upstream = session
            log.info("upstream session ready (detection=%s llm_resp=%s llm_calls=%s identity=%s)",
                     DETECTION_ENABLED, LLM_JUDGE_RESPONSES, LLM_JUDGE_CALLS, IDENTITY_ENFORCED)
            try:
                yield
            finally:
                upstream = None
                log.info("upstream session closed")


session_manager = StreamableHTTPSessionManager(app=server, stateless=True)


async def handle_streamable_http(scope, receive, send) -> None:
    identity: Identity | None = None
    token = _extract_bearer(scope) if scope.get("type") == "http" else None
    if token:
        identity = verify(token)
    ctx_token = current_identity.set(identity)
    try:
        await session_manager.handle_request(scope, receive, send)
    finally:
        current_identity.reset(ctx_token)


# ---------------------------------------------------------------------------
# /events websocket + /events.json snapshot + /ui static
# ---------------------------------------------------------------------------


async def events_ws(ws: WebSocket) -> None:
    await ws.accept()
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)
    event_subscribers.add(queue)
    log.info("websocket connected (%d subscribers)", len(event_subscribers))
    # Replay the last events so a newly-connected dashboard sees recent state
    for past in list(event_log):
        queue.put_nowait(past)
    try:
        while True:
            payload = await queue.get()
            await ws.send_text(json.dumps(payload, default=str))
    except WebSocketDisconnect:
        pass
    finally:
        event_subscribers.discard(queue)
        log.info("websocket disconnected (%d subscribers)", len(event_subscribers))


async def events_snapshot(_request) -> JSONResponse:
    return JSONResponse(list(event_log))


async def dashboard(_request) -> FileResponse:
    path = os.path.join(os.path.dirname(__file__), "ui", "index.html")
    return FileResponse(path, media_type="text/html")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


@contextlib.asynccontextmanager
async def lifespan(_app: Starlette):
    async with session_manager.run():
        async with _upstream_session_lifespan():
            yield


app = Starlette(
    debug=False,
    routes=[
        Route("/", endpoint=dashboard),
        Route("/events.json", endpoint=events_snapshot),
        WebSocketRoute("/events", endpoint=events_ws),
        Mount("/mcp", app=handle_streamable_http),
    ],
    lifespan=lifespan,
)


if __name__ == "__main__":
    uvicorn.run(app, host=LISTEN_HOST, port=LISTEN_PORT, log_level="info")
