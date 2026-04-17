"""Pre-warm the `fetch_github_file` cache in server.py.

Calls `fetch_github_file(repo, path)` once per path below so the MCP
server has the content in memory. After this runs, Scenario 4 of the
demo works even if the network or GitHub later become unreachable.

Usage:

    uv run python scratch/warmup_gh_cache.py
    GH_REPO=akrai37/mcp-toolkit uv run python scratch/warmup_gh_cache.py

Connects directly to the MCP server (port 8001), bypassing Argus, since
warming is internal bookkeeping — no need to spend detector cycles.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import auth  # noqa: E402

SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://127.0.0.1:8001/mcp")
GH_REPO = os.environ.get("GH_REPO", "akrai37/mcp-toolkit")
GH_BRANCH = os.environ.get("GH_BRANCH", "main")

# Files the demo will read. Add more if the pitch expands.
PATHS = [
    "CLAUDE.md",
    "README.md",
]


async def main() -> None:
    headers = {"Authorization": f"Bearer {auth.mint('deploy-bot')}"}
    async with streamablehttp_client(SERVER_URL, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for path in PATHS:
                print(f"[warmup] fetching {GH_REPO}@{GH_BRANCH}/{path}")
                try:
                    result = await session.call_tool(
                        "fetch_github_file",
                        {"repo": GH_REPO, "path": path, "branch": GH_BRANCH},
                    )
                    bytes_ = sum(len(getattr(b, "text", "") or "") for b in result.content)
                    status = "ERROR" if result.isError else f"{bytes_} bytes"
                    print(f"[warmup]   -> {status}")
                except Exception as exc:
                    print(f"[warmup]   -> FAILED: {exc}")
    print("[warmup] done.")


if __name__ == "__main__":
    asyncio.run(main())
