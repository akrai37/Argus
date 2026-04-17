#!/usr/bin/env bash
# Argus live demo orchestrator.
#
# Starts the real MCP server + Argus proxy, opens the dashboard in your
# default browser, and runs the two attack scenarios with clear narration
# pauses between them so a human can talk the judges through each phase.
#
# Stop the demo with Ctrl-C — servers are killed on exit.
#
# Requires: uv, python 3.11, ANTHROPIC_API_KEY in .env.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

SERVER_PORT=8001
PROXY_PORT=8000
GH_REPO="${GH_REPO:-akrai37/mcp-toolkit}"
GH_BRANCH="${GH_BRANCH:-main}"
LOG_DIR="$HERE/.demo-logs"
mkdir -p "$LOG_DIR"

c_reset="\033[0m"
c_bold="\033[1m"
c_cyan="\033[36m"
c_green="\033[32m"
c_red="\033[31m"
c_dim="\033[2m"

banner() {
  echo
  printf "${c_bold}${c_cyan}%s${c_reset}\n" "========================================================================"
  printf "${c_bold}${c_cyan}  %s${c_reset}\n" "$1"
  printf "${c_bold}${c_cyan}%s${c_reset}\n" "========================================================================"
  echo
}

pause() {
  local prompt="${1:-press enter to continue}"
  printf "${c_dim}>>> %s${c_reset}" "$prompt"
  read -r _
}

cleanup() {
  echo
  echo "[run_demo] shutting down..."
  [[ -n "${PROXY_PID:-}" ]]  && kill "$PROXY_PID"  2>/dev/null || true
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  echo "[run_demo] done."
}
trap cleanup EXIT INT TERM

if [[ ! -f "$HERE/.env" ]]; then
  printf "${c_red}missing .env file; copy .env.example and add your ANTHROPIC_API_KEY${c_reset}\n" >&2
  exit 1
fi

# --- start the servers --------------------------------------------------------
banner "Booting Argus demo stack"

echo "[run_demo] starting MCP server on :$SERVER_PORT..."
uv run python server.py >"$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!

echo "[run_demo] starting Argus proxy on :$PROXY_PORT..."
uv run python proxy.py >"$LOG_DIR/proxy.log" 2>&1 &
PROXY_PID=$!

# Wait for proxy to come up
for i in {1..30}; do
  if curl -sSf -o /dev/null "http://127.0.0.1:$PROXY_PORT/"; then
    break
  fi
  sleep 0.3
  if (( i == 30 )); then
    echo "[run_demo] proxy never came up; see $LOG_DIR/proxy.log" >&2
    exit 1
  fi
done

echo "[run_demo] both servers up."
echo "[run_demo]   dashboard  -> http://127.0.0.1:$PROXY_PORT/"
echo "[run_demo]   events ws  -> ws://127.0.0.1:$PROXY_PORT/events"

# Pre-warm the GitHub file cache so Scenario 4 is offline-safe.
# Non-fatal if it fails (e.g. wifi down, repo not yet created) — the
# scenario will simply hit the network at demo time instead.
echo "[run_demo] pre-warming GitHub file cache for $GH_REPO..."
GH_REPO="$GH_REPO" GH_BRANCH="$GH_BRANCH" \
  uv run python scratch/warmup_gh_cache.py >>"$LOG_DIR/warmup.log" 2>&1 \
  || echo "[run_demo] (warmup failed — see $LOG_DIR/warmup.log; demo will still work if network holds)"

# Open the dashboard
if command -v open >/dev/null 2>&1; then
  open "http://127.0.0.1:$PROXY_PORT/" || true
fi

echo
pause "Dashboard is live. Press Enter to begin."

# --- scenario 1: poisoned response -------------------------------------------
banner "Scenario 1 — poisoned document reaches the agent (Argus OFF)"

echo "An onboarding doc we'll show the agent contains fake AWS credentials."
echo "This is what happens TODAY, with no firewall: the credentials end up in"
echo "the agent's context, where they can be logged, leaked, or surfaced."
echo
pause "Press Enter to run the agent against the MCP server directly (Argus bypassed)."

echo "[run_demo] victim_agent -> http://127.0.0.1:$SERVER_PORT/mcp"
ARGUS_URL="http://127.0.0.1:$SERVER_PORT/mcp" uv run python victim_agent.py || true

echo
pause "Press Enter to re-run the same request through Argus."

# --- scenario 2: same attack, through Argus ----------------------------------
banner "Scenario 2 — same attack, through Argus"

echo "Now the agent talks to Argus. The document is unchanged, the agent is"
echo "unchanged. Watch the dashboard."
echo
pause "Press Enter to start the agent."

echo "[run_demo] victim_agent -> http://127.0.0.1:$PROXY_PORT/mcp"
uv run python victim_agent.py || true

echo
pause "Press Enter to continue to outbound-call inspection."

# --- scenario 3: outbound exfil call -----------------------------------------
banner "Scenario 3 — malicious outbound call (exfil via tool args)"

echo "Argus inspects both directions. Even if an agent is compromised and"
echo "tries to call shell_exec with an exfiltration command, Argus catches"
echo "it BEFORE it reaches the real tool."
echo
pause "Press Enter to attempt an outbound credential-exfiltration call."

echo "[run_demo] exfil attack -> http://127.0.0.1:$PROXY_PORT/mcp"
uv run python scratch/attack_exfil.py "http://127.0.0.1:$PROXY_PORT/mcp" || true

echo
pause "Press Enter to continue to the semantic-attack scenario (LLM-judge layer)."

# --- scenario 3b: LLM-judge-only semantic attack ----------------------------
banner "Scenario 3b — semantic attack (caught only by the LLM judge)"

echo "This doc has NO regex hits — no AWS keys, no 'ignore prior instructions',"
echo "no suspicious shell patterns. Just a polite request to forward company"
echo "data to an external email. Regex allows it; the LLM judge catches it."
echo "Watch the dashboard — this will show the AMBER 'llm' layer badge."
echo
pause "Press Enter to run the agent against hr_handbook.md through Argus."

echo "[run_demo] victim_agent -> hr_handbook.md (via Argus)"
DOCUMENT=hr_handbook.md uv run python victim_agent.py || true

echo
pause "Press Enter to continue to the GitHub scenario (Claude Code CVE pattern)."

# --- scenario 4: poisoned GitHub CLAUDE.md (Claude Code CVE pattern) -------
banner "Scenario 4 — poisoned GitHub repo (Claude Code CVE pattern)"

echo "This is the same shape as the Claude Code CLAUDE.md exploit disclosed"
echo "on March 31, 2026. A coding assistant (scoped identity: coding-bot)"
echo "fetches CLAUDE.md from a public repo on GitHub and tries to follow"
echo "its setup instructions."
echo
echo "Repo: https://github.com/$GH_REPO  (publicly accessible for verification)"
echo
pause "Press Enter to run the coding agent against the public GitHub repo."

echo "[run_demo] coding-bot -> $GH_REPO/CLAUDE.md (via Argus)"
AGENT_ROLE=coding AGENT_ID=coding-bot \
  GH_REPO="$GH_REPO" GH_BRANCH="$GH_BRANCH" \
  uv run python victim_agent.py || true

echo
pause "Press Enter to retry the same request with a non-privileged identity (identity-layer demo)."

echo "[run_demo] onboarding-bot -> blocked at identity layer (no fetch_github_file scope)"
AGENT_ROLE=coding AGENT_ID=onboarding-bot \
  GH_REPO="$GH_REPO" GH_BRANCH="$GH_BRANCH" \
  uv run python victim_agent.py || true

echo
banner "Demo complete"
echo "Leave the dashboard up — Ctrl-C here stops both servers."
echo "Logs live in $LOG_DIR/{server.log,proxy.log}."
# Keep processes alive until user hits Ctrl-C
wait "$PROXY_PID"
