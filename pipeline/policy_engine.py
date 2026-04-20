"""
pipeline/policy_engine.py — Role-based access control for LLM tool calls.

WHAT IT DOES:
  Intercepts between Claude's tool call emission and actual tool execution.
  Checks whether the calling role is permitted to invoke the requested tool.
  Returns a structured result that feeds directly into logging_schema.log_request().

WHAT IT DOES NOT DO:
  - Authenticate the caller or validate the role claim (session-layer concern)
  - Inspect tool arguments (e.g., file paths) — deferred to tool_sandbox.py
  - Parse free-text LLM output — only handles structured tool call dicts

THREAT MODEL:
  Defends against LLM-initiated privilege escalation: an injected prompt causes
  the LLM to emit a tool call that the session role does not permit. Enforcement
  is at the execution layer — no prompt manipulation can bypass a dict lookup
  that runs before tools[name].execute() is called.

DESIGN DECISIONS (full reasoning in docs/report_notes.md):
  - Allowlist over blocklist: unknown tools are denied unconditionally
  - Unknown role defaults to "guest" (deny-by-default)
  - Multi-tool calls: any single violation blocks the entire response
  - Tool args are logged but never inspected at this layer
  - Toggle flag: config["policy_engine"]=False passes through for ablation runs

INPUT FORMAT (Claude API tool_use blocks):
  Each tool call dict must match Claude's function-calling response format:
  {
    "type": "tool_use",
    "id":   str,   # Claude-assigned ID — must be echoed back in tool result
    "name": str,   # tool name, e.g. "file_write"
    "input": dict  # tool arguments
  }

LOG SCHEMA OUTPUT:
  {
    "triggered":       bool,   # True = access denied
    "role":            str,
    "requested_tools": list,   # all tool names Claude attempted
    "blocked_tools":   list,   # subset that caused the block
    "tool_args":       dict,   # input of the first tool call (logged only)
    "allowed":         bool,
    "reason":          str,    # "role_permitted" | "role_violation" |
                               # "unknown_tool"   | "toggle_disabled"
    "tool_call_ids":   list,   # Claude IDs — orchestrator needs these to
  }                            # form valid tool result messages
"""

import logging
from typing import Any

from constants import KNOWN_TOOLS, ROLE_ALLOWLIST, VALID_ROLES

log = logging.getLogger(__name__)


def check_policy(
    role: str,
    tool_calls: list[dict[str, Any]],
    config: dict[str, bool],
) -> tuple[bool, dict[str, Any]]:
    """
    Evaluate whether the session role may execute the requested tool calls.

    Parameters
    ----------
    role       : session role — "guest" | "user" | "admin". Treated as a
                 trusted caller-supplied claim; not validated here.
    tool_calls : list of tool call dicts from Claude's API response, each with
                 keys "tool" (str) and "args" (dict). Usually one entry;
                 Claude can emit multiple in a single response.
    config     : pipeline toggle flags. If config["policy_engine"] is False,
                 all tool calls pass through (ablation mode).

    Returns
    -------
    (triggered, layer_result)
        triggered    : True if any tool call was denied (access blocked)
        layer_result : dict matching the policy_engine section of logging_schema
    """
    tool_call_ids      = [tc["id"]    for tc in tool_calls]
    requested_tool_names = [tc["name"]  for tc in tool_calls]
    tool_args            = tool_calls[0]["input"] if tool_calls else {}

    # ── Toggle flag — ablation passthrough ────────────────────────────────────
    if not config.get("policy_engine", True):
        return False, {
            "triggered":       False,
            "role":            role,
            "requested_tools": requested_tool_names,
            "blocked_tools":   [],
            "tool_args":       tool_args,
            "allowed":         True,
            "reason":          "toggle_disabled",
            "tool_call_ids":   tool_call_ids,
        }

    # ── Unknown role → treat as guest ─────────────────────────────────────────
    if role not in VALID_ROLES:
        log.warning(f"policy_engine: unrecognized role '{role}' — defaulting to guest")
        role = "guest"

    allowed_tools = ROLE_ALLOWLIST[role]

    # ── Check each tool call ───────────────────────────────────────────────────
    blocked: list[str] = []

    for tc in tool_calls:
        tool_name = tc["name"]

        if tool_name not in KNOWN_TOOLS:
            blocked.append(tool_name)
            log.warning(f"policy_engine: unknown tool '{tool_name}' blocked (role='{role}')")

        elif tool_name not in allowed_tools:
            blocked.append(tool_name)
            log.info(f"policy_engine: role_violation — '{role}' may not call '{tool_name}'")

    # ── Any violation blocks the entire response ───────────────────────────────
    if blocked:
        unknown = [t for t in blocked if t not in KNOWN_TOOLS]
        reason = "unknown_tool" if unknown else "role_violation"
        return True, {
            "triggered":       True,
            "role":            role,
            "requested_tools": requested_tool_names,
            "blocked_tools":   blocked,
            "tool_args":       tool_args,
            "allowed":         False,
            "reason":          reason,
            "tool_call_ids":   tool_call_ids,
        }

    return False, {
        "triggered":       False,
        "role":            role,
        "requested_tools": requested_tool_names,
        "blocked_tools":   [],
        "tool_args":       tool_args,
        "allowed":         True,
        "reason":          "role_permitted",
        "tool_call_ids":   tool_call_ids,
    }


# ── Smoke test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    config_on  = {"policy_engine": True}
    config_off = {"policy_engine": False}

    def tc(name, **input_kwargs):
        """Build a Claude-format tool_use block."""
        import uuid
        return {"type": "tool_use", "id": f"toolu_{uuid.uuid4().hex[:16]}", "name": name, "input": input_kwargs}

    cases = [
        # (role, tool_calls, config, expect_triggered, label)
        ("guest", [tc("file_read",  path="/tmp/a")],           config_on,  True,  "guest blocked from file_read"),
        ("guest", [tc("bash",       command="ls")],             config_on,  True,  "guest blocked from bash"),
        ("user",  [tc("search",     query="python")],           config_on,  False, "user permitted search"),
        ("user",  [tc("bash",       command="ls")],             config_on,  True,  "user blocked from bash"),
        ("admin", [tc("bash",       command="ls")],             config_on,  False, "admin permitted bash"),
        ("admin", [tc("file_write", path="/tmp/a")],            config_on,  False, "admin permitted file_write"),
        ("guest", [tc("magic_tool")],                           config_on,  True,  "unknown tool blocked"),
        ("ADMIN", [tc("bash",       command="ls")],             config_on,  True,  "spoofed role defaults to guest"),
        ("guest", [tc("file_write")],                           config_off, False, "toggle_disabled passthrough"),
        ("user",  [tc("file_read"), tc("bash", command="ls")],  config_on,  True,  "multi-tool: any violation blocks all"),
    ]

    print("policy_engine smoke test\n" + "─" * 50)
    passed = 0
    for role, tool_calls, config, expect_triggered, label in cases:
        triggered, result = check_policy(role, tool_calls, config)
        status = "✓" if triggered == expect_triggered else "✗ FAIL"
        if triggered == expect_triggered:
            passed += 1
        print(f"  {status}  [{result['reason']:<16}]  {label}")

    print(f"\n{passed}/{len(cases)} passed")
