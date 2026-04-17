"""Lightweight identity layer for Argus.

For the hackathon demo we act as our own issuer: a shared HMAC secret
signs a JWT whose payload carries `agent_id` plus the list of tool
names that agent is allowed to call. In production the same
verification logic would swap in your IDP's JWKS (Okta, Auth0, Azure
AD, Keycloak — anything that speaks OIDC). Argus is IDP-agnostic.

The module exposes:
  * `mint(agent_id, scopes)` — issue a token (used by clients)
  * `verify(token)` — return an Identity or None (used by Argus)
  * `allowed(identity, tool)` — policy check for a tool call
  * `AGENT_POLICIES` — per-agent scope table used when minting

For the demo we ship three canonical agents:
  * `deploy-bot`     — trusted automation, all scopes
  * `onboarding-bot` — restricted to read_document, NOT shell_exec
  * `anonymous`      — no scopes, every tool call denied
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass

import jwt

ARGUS_JWT_SECRET = os.environ.get(
    "ARGUS_JWT_SECRET",
    "argus-demo-secret-change-me-before-production-9f3e2a",
)
ARGUS_JWT_ISSUER = "argus-demo-issuer"
ARGUS_JWT_ALG = "HS256"
ARGUS_JWT_TTL_SECONDS = 60 * 60  # 1 hour — plenty for a demo

# Per-agent default policy. `scopes` lists the tool names allowed.
AGENT_POLICIES: dict[str, list[str]] = {
    # Trusted automation bot — full scope.
    "deploy-bot": ["read_document", "shell_exec", "fetch_github_file"],
    # Onboarding bot — read docs only. No shell, no GitHub.
    "onboarding-bot": ["read_document"],
    # Coding assistant (Claude Code / Cursor / Windsurf analog).
    # Scoped to repo reads. Deliberately no shell_exec — a coding agent
    # shouldn't have that privilege by default; Argus enforces it.
    "coding-bot": ["fetch_github_file", "read_document"],
    # No scopes — every tool call denied.
    "anonymous": [],
}


@dataclass(frozen=True)
class Identity:
    agent_id: str
    scopes: tuple[str, ...]

    @property
    def is_anonymous(self) -> bool:
        return self.agent_id == "anonymous"


def mint(agent_id: str, scopes: list[str] | None = None) -> str:
    """Issue a signed JWT carrying agent identity + policy scopes."""
    if scopes is None:
        scopes = AGENT_POLICIES.get(agent_id, [])
    now = int(time.time())
    claims = {
        "iss": ARGUS_JWT_ISSUER,
        "sub": agent_id,
        "agent_id": agent_id,
        "scopes": list(scopes),
        "iat": now,
        "exp": now + ARGUS_JWT_TTL_SECONDS,
    }
    return jwt.encode(claims, ARGUS_JWT_SECRET, algorithm=ARGUS_JWT_ALG)


def verify(token: str) -> Identity | None:
    """Return Identity if the token is valid and well-formed, else None."""
    try:
        claims = jwt.decode(
            token,
            ARGUS_JWT_SECRET,
            algorithms=[ARGUS_JWT_ALG],
            issuer=ARGUS_JWT_ISSUER,
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.InvalidTokenError:
        return None
    agent_id = claims.get("agent_id") or claims.get("sub")
    if not isinstance(agent_id, str):
        return None
    scopes = claims.get("scopes", [])
    if not isinstance(scopes, list):
        scopes = []
    return Identity(agent_id=agent_id, scopes=tuple(str(s) for s in scopes))


def allowed(identity: Identity | None, tool: str) -> tuple[bool, str]:
    """Check whether the identity is authorised to call `tool`."""
    if identity is None:
        return False, "no valid identity presented"
    if identity.is_anonymous or not identity.scopes:
        return False, f"agent `{identity.agent_id}` has no scopes"
    if tool in identity.scopes:
        return True, "ok"
    return False, (
        f"agent `{identity.agent_id}` lacks scope for tool `{tool}` "
        f"(has: {', '.join(identity.scopes) or '—'})"
    )


if __name__ == "__main__":
    # Smoke test
    for agent in ("deploy-bot", "onboarding-bot", "anonymous"):
        tok = mint(agent)
        ident = verify(tok)
        print(f"{agent:16s} -> {ident}")
        for tool in ("read_document", "shell_exec", "unknown_tool"):
            ok, why = allowed(ident, tool)
            print(f"   {tool:14s} allowed={ok:5} ({why})")
