"""Prep-night sanity check: connect to server.py and call both tools.

Usage (in two terminals):

    # Terminal 1
    uv run python server.py

    # Terminal 2
    uv run python scratch/test_mcp.py

Expected output: list of tools, contents of the sample document, and
the output of `echo hello from shell_exec`.
"""
from __future__ import annotations

import asyncio

import os
import sys
from pathlib import Path

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

# scratch/ is not on sys.path by default
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import auth  # noqa: E402

DEFAULT_URL = "http://127.0.0.1:8001/mcp"
SERVER_URL = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
AGENT_ID = os.environ.get("AGENT_ID", "deploy-bot")


async def main() -> None:
    headers = {"Authorization": f"Bearer {auth.mint(AGENT_ID)}"}
    async with streamablehttp_client(SERVER_URL, headers=headers) as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("== tools ==")
            for tool in tools.tools:
                print(f"  - {tool.name}: {tool.description}")

            print("\n== read_document(sample.txt) ==")
            result = await session.call_tool("read_document", {"path": "sample.txt"})
            for block in result.content:
                print(getattr(block, "text", block))

            print("\n== shell_exec('echo hello from shell_exec') ==")
            result = await session.call_tool(
                "shell_exec", {"cmd": "echo hello from shell_exec"}
            )
            for block in result.content:
                print(getattr(block, "text", block))


if __name__ == "__main__":
    asyncio.run(main())
