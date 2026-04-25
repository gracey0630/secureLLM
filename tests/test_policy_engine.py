"""
tests/test_policy_engine.py — Schema contract tests for pipeline/policy_engine.py

These are NOT security tests. They verify that check_policy() always returns
a dict with the correct fields, types, value constraints, and logical consistency
— regardless of which internal code path was taken.

Four code paths exist in check_policy():
  Path 1: toggle disabled  → early return (toggle_disabled)
  Path 2: role violation   → blocked return (role_violation)
  Path 3: unknown tool     → blocked return (unknown_tool)
  Path 4: all permitted    → allowed return (role_permitted)

Each path constructs the result dict independently. A field missing from one
path won't be caught by behavioral tests (which only check `triggered`).
These tests check every field on every path.

Run with:
  python -m pytest tests/test_policy_engine.py -v
"""

import uuid
import pytest
from pipeline.policy_engine import check_policy

# ── Fixtures ───────────────────────────────────────────────────────────────────

REQUIRED_FIELDS = {
    "triggered",
    "role",
    "requested_tools",
    "blocked_tools",
    "tool_args",
    "allowed",
    "reason",
    "tool_call_ids",
}

VALID_REASONS = {"role_permitted", "role_violation", "unknown_tool", "toggle_disabled"}

CONFIG_ON  = {"policy_engine": True}
CONFIG_OFF = {"policy_engine": False}


def make_tool_call(name: str, **input_kwargs) -> dict:
    """Build a Claude-format tool_use block with a real-looking ID."""
    return {
        "type":  "tool_use",
        "id":    f"toolu_{uuid.uuid4().hex[:16]}",
        "name":  name,
        "input": input_kwargs,
    }


# One representative call per code path
PATH_CASES = [
    ("toggle_disabled", "guest", [make_tool_call("file_write")],          CONFIG_OFF),
    ("role_violation",  "guest", [make_tool_call("bash", command="ls")],   CONFIG_ON),
    ("unknown_tool",    "admin", [make_tool_call("magic_tool")],            CONFIG_ON),
    ("role_permitted",  "admin", [make_tool_call("bash", command="ls")],   CONFIG_ON),
]


# ── Test 1: Required fields always present ─────────────────────────────────────

@pytest.mark.parametrize("label,role,tool_calls,config", PATH_CASES)
def test_required_fields_present(label, role, tool_calls, config):
    """Every code path must return all required fields — no missing keys."""
    _, result = check_policy(role, tool_calls, config)
    missing = REQUIRED_FIELDS - result.keys()
    assert not missing, (
        f"Path '{label}' is missing fields: {missing}"
    )


@pytest.mark.parametrize("label,role,tool_calls,config", PATH_CASES)
def test_no_extra_fields(label, role, tool_calls, config):
    """No undocumented fields should appear in the result."""
    _, result = check_policy(role, tool_calls, config)
    extra = result.keys() - REQUIRED_FIELDS
    assert not extra, (
        f"Path '{label}' returned unexpected fields: {extra}"
    )


# ── Test 2: Field types are correct on every path ─────────────────────────────

@pytest.mark.parametrize("label,role,tool_calls,config", PATH_CASES)
def test_field_types(label, role, tool_calls, config):
    """
    All fields must have the exact types that log_request() and pd.read_json()
    expect. bool vs int matters — mixed types cause silent column-type issues
    in eval DataFrames.
    """
    _, result = check_policy(role, tool_calls, config)

    assert type(result["triggered"])       is bool, "triggered must be bool, not int or str"
    assert type(result["allowed"])         is bool, "allowed must be bool, not int or str"
    assert isinstance(result["role"],            str)
    assert isinstance(result["reason"],          str)
    assert isinstance(result["requested_tools"], list)
    assert isinstance(result["blocked_tools"],   list)
    assert isinstance(result["tool_call_ids"],   list)
    assert isinstance(result["tool_args"],       dict)


# ── Test 3: `reason` is always a known value ──────────────────────────────────

@pytest.mark.parametrize("label,role,tool_calls,config", PATH_CASES)
def test_reason_is_valid(label, role, tool_calls, config):
    """
    `reason` must be one of the 4 documented values. Any other string would
    silently create a new category in the eval script's groupby, producing
    a result not in the paper's table.
    """
    _, result = check_policy(role, tool_calls, config)
    assert result["reason"] in VALID_REASONS, (
        f"Path '{label}' returned undocumented reason: '{result['reason']}'"
    )


# ── Test 4: `triggered` and `allowed` are always logically inverse ─────────────

@pytest.mark.parametrize("label,role,tool_calls,config", PATH_CASES)
def test_triggered_allowed_consistent(label, role, tool_calls, config):
    """
    triggered=True must always coincide with allowed=False and vice versa.
    A record where both are True or both are False is a logical contradiction
    — the enforcement decision contradicts the permission flag in the same record.
    """
    _, result = check_policy(role, tool_calls, config)
    assert result["triggered"] != result["allowed"], (
        f"Path '{label}': triggered={result['triggered']} and "
        f"allowed={result['allowed']} must always be opposite"
    )


# ── Test 5: `tool_call_ids` round-trips correctly ─────────────────────────────

def test_tool_call_ids_roundtrip():
    """
    IDs from the input tool call dicts must appear in tool_call_ids in the
    result, in the same order. The orchestrator uses these IDs to form Claude's
    tool result messages — any drop, deduplication, or reordering causes the
    Claude API to reject the response.
    """
    tc1 = make_tool_call("file_read",  path="/tmp/a")
    tc2 = make_tool_call("search",     query="python")
    input_ids = [tc1["id"], tc2["id"]]

    _, result = check_policy("user", [tc1, tc2], CONFIG_ON)

    assert result["tool_call_ids"] == input_ids, (
        f"tool_call_ids mismatch.\n"
        f"  Expected : {input_ids}\n"
        f"  Got      : {result['tool_call_ids']}"
    )


def test_tool_call_ids_roundtrip_on_block():
    """Same round-trip check on a blocked path — IDs must still be preserved."""
    tc1 = make_tool_call("file_read", path="/tmp/a")
    tc2 = make_tool_call("bash",      command="ls")
    input_ids = [tc1["id"], tc2["id"]]

    _, result = check_policy("user", [tc1, tc2], CONFIG_ON)

    assert result["triggered"] is True
    assert result["tool_call_ids"] == input_ids, (
        f"tool_call_ids not preserved on blocked path.\n"
        f"  Expected : {input_ids}\n"
        f"  Got      : {result['tool_call_ids']}"
    )
