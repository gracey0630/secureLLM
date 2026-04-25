"""
pipeline/tool_sandbox.py — Layer 3: argument-level command validator.

The policy engine (Layer 2) controls *which tool types* a role may call.
This layer controls *what arguments* those tools may receive. Together they
form defense-in-depth: role check at the call boundary, content check at
the execution boundary.

Validates two tool types:
  bash       — blocklist: destructive commands, pipe-to-shell, external
               exfiltration, eval/backtick substitution
  file_read  — allowlist: path must be under /tmp/demo/
  file_write — allowlist: same path constraint

All other tools (search, external_api) pass through without inspection.

Attack taxonomy informed by Garak's malwaregen and encoding probe categories
(rm -rf, privilege escalation, semicolon chaining, backtick injection).
Garak itself cannot run against a Python validator — it probes LLM endpoints.
The sandbox_corpus.py covers the same taxonomy manually.
"""

import re
from pathlib import Path
from typing import Any

_ALLOWED_FILE_ROOT = Path("/tmp/demo")

# ── bash blocklist rules ──────────────────────────────────────────────────────
# Each entry: (rule_name, compiled_pattern)
# Rules are checked in order; first match wins.
_BASH_RULES: list[tuple[str, re.Pattern]] = [
    # Destructive filesystem operations
    ("destructive_command", re.compile(
        r"rm\s+-[^\s]*r|rm\s+--recursive|mkfs\b|shred\b|dd\s+if=", re.I
    )),
    # External exfiltration tools
    ("external_exfiltration", re.compile(
        r"\b(curl|wget|nc|netcat)\b", re.I
    )),
    # Pipe or chain to a shell interpreter
    ("pipe_to_shell", re.compile(
        r"\|\s*(ba)?sh\b|;\s*(ba)?sh\b", re.I
    )),
    # Semicolon command chaining (broad catch for obfuscated payloads)
    ("command_chaining", re.compile(r";")),
    # Backtick or $() command substitution
    ("command_substitution", re.compile(r"`[^`]+`|\$\([^)]+\)")),
    # eval / exec builtins
    ("eval_exec", re.compile(r"\beval\b|\bexec\b", re.I)),
    # Write redirect outside /tmp
    ("write_outside_tmp", re.compile(r">\s*(?!/tmp)[/~]")),
]


def _check_bash(command: str) -> tuple[str | None, str | None]:
    """Return (rule_violated, blocked_arg) or (None, None) if safe."""
    for rule_name, pattern in _BASH_RULES:
        if pattern.search(command):
            return rule_name, command
    return None, None


def _check_file_path(path: str) -> tuple[str | None, str | None]:
    """Return (rule_violated, blocked_arg) or (None, None) if path is safe."""
    # Reject traversal sequences before resolving
    if ".." in path:
        return "path_traversal", path
    try:
        resolved = Path(path).resolve()
    except Exception:
        return "path_traversal", path
    try:
        resolved.relative_to(_ALLOWED_FILE_ROOT.resolve())
    except ValueError:
        return "path_outside_allowed_root", path
    return None, None


# ── public API ────────────────────────────────────────────────────────────────

def check_sandbox(
    tool_name: str,
    tool_args: dict[str, Any],
    config: dict[str, bool],
) -> tuple[bool, dict[str, Any]]:
    """Validate tool arguments before execution.

    Returns (triggered, layer_result). triggered=True means block.
    Follows the same (bool, dict) contract as check_policy().
    """
    _base = {
        "triggered":     False,
        "tool_name":     tool_name,
        "rule_violated": None,
        "blocked_arg":   None,
        "allowed":       True,
        "reason":        "args_safe",
    }

    if not config.get("tool_sandbox", True):
        return False, {**_base, "reason": "toggle_disabled"}

    rule, blocked_arg = None, None

    if tool_name == "bash":
        command = tool_args.get("command", "")
        rule, blocked_arg = _check_bash(command)

    elif tool_name in ("file_read", "file_write"):
        path = tool_args.get("path", "")
        rule, blocked_arg = _check_file_path(path)

    # search / external_api — pass through
    if rule is None:
        return False, _base

    return True, {
        "triggered":     True,
        "tool_name":     tool_name,
        "rule_violated": rule,
        "blocked_arg":   blocked_arg,
        "allowed":       False,
        "reason":        rule,
    }
