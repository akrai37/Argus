"""Real MCP server exposing read_document, shell_exec, fetch_github_file.

Runs on http://127.0.0.1:8001/mcp (streamable-http transport).

In the Argus demo, this is the "protected backend" — the server Argus
sits in front of. Agents do not talk to it directly; they talk to the
Argus proxy, which forwards to this server after inspection.

Run with:  uv run python server.py
"""
from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

log = logging.getLogger("argus.server")

DOCUMENTS_DIR = Path(__file__).parent / "documents"

# In-memory cache for fetch_github_file. Keyed by "owner/repo@branch/path".
# Protects the demo from GitHub rate limits (60/hr unauthenticated) and
# venue wifi flakiness. Pre-warm via scratch/warmup_gh_cache.py before
# showtime and the demo is offline-safe thereafter.
_gh_cache: dict[str, str] = {}

mcp = FastMCP(
    name="argus-demo-server",
    instructions="Demo tools for the Argus hackathon: read_document, shell_exec, fetch_github_file.",
    host="127.0.0.1",
    port=8001,
)


@mcp.tool()
def read_document(path: str) -> str:
    """Read a file from the documents/ directory and return its contents.

    Paths are resolved relative to documents/. Absolute paths and
    parent-directory traversal are rejected.
    """
    target = (DOCUMENTS_DIR / path).resolve()
    if not str(target).startswith(str(DOCUMENTS_DIR.resolve())):
        raise ValueError(f"path escapes documents/: {path}")
    if not target.exists():
        raise FileNotFoundError(f"no such document: {path}")
    return target.read_text()


@mcp.tool()
def shell_exec(cmd: str) -> str:
    """Run a shell command and return combined stdout + stderr.

    DELIBERATELY unsafe for the demo — this is the foot-gun the victim
    agent gets tricked into firing. Argus's job is to make sure the
    agent never reaches this tool with a malicious arg.
    """
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return f"[exit {result.returncode}]\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"


@mcp.tool()
def fetch_github_file(repo: str, path: str, branch: str = "main") -> str:
    """Fetch a single file from a public GitHub repo.

    Returns the raw text contents. Results are cached in memory (keyed by
    repo+branch+path); set ARGUS_GH_NO_CACHE=1 to bypass.

    repo:   "owner/name" form, e.g. "akrai37/mcp-toolkit"
    path:   file path within the repo, e.g. "CLAUDE.md"
    branch: defaults to "main"
    """
    key = f"{repo}@{branch}/{path}"
    if key in _gh_cache and not os.environ.get("ARGUS_GH_NO_CACHE"):
        log.info("fetch_github_file cache HIT %s", key)
        return _gh_cache[key]
    url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
    log.info("fetch_github_file NETWORK %s", url)
    resp = httpx.get(url, timeout=10, follow_redirects=True)
    resp.raise_for_status()
    _gh_cache[key] = resp.text
    return resp.text


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    mcp.run(transport="streamable-http")
