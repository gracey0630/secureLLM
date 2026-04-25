"""
constants.py — Shared taxonomy and role definitions for the SecureLLM pipeline.

Imported by:
  pipeline/policy_engine.py  — enforcement logic
  pipeline/orchestrator.py   — Claude tool definitions must match KNOWN_TOOLS exactly
  tests/test_policy_engine.py

Design decisions (see docs/report_notes.md — Policy Engine Design Decisions):
  - Allowlist over blocklist: anything not in KNOWN_TOOLS is denied unconditionally.
  - ROLE_ALLOWLIST and Claude's function-calling tool definitions are the same set
    by construction — both derived from KNOWN_TOOLS. They cannot drift out of sync.
  - user role is deliberately conservative (read-only, local) to maximize the
    visible privilege gap between roles in the evaluation results.
"""

# ── Tool taxonomy ──────────────────────────────────────────────────────────────
#
# These are the only tool names the pipeline recognizes. Any tool name emitted
# by the LLM that is not in this set is denied with reason="unknown_tool",
# regardless of role. This set must stay in sync with the tool definitions
# passed to the Claude API in pipeline/orchestrator.py.

KNOWN_TOOLS: frozenset[str] = frozenset({
    "file_read",
    "file_write",
    "bash",
    "external_api",
    "search",
})


# ── Role allowlist ─────────────────────────────────────────────────────────────
#
# Maps each role to the set of tool names it may call.
# Any role not present here is treated as "guest" (deny all tools).
#
# guest       — read-only text queries, no tool access
# user        — local read operations only; no writes, no network, no shell
# admin       — full tool access
#
# user is intentionally conservative: external_api is excluded so that
# injection-driven data exfiltration via network calls is a caught violation,
# not a permitted behavior. This makes the privilege gap visible in evaluation.

ROLE_ALLOWLIST: dict[str, frozenset[str]] = {
    "guest": frozenset(),
    "user":  frozenset({"file_read", "search"}),
    "admin": frozenset(KNOWN_TOOLS),
}

VALID_ROLES: frozenset[str] = frozenset(ROLE_ALLOWLIST.keys())
