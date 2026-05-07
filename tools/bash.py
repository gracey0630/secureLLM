"""
tools/bash.py — Stub bash tool. Returns hardcoded output; no real subprocess.

Intentionally a permanent stub — bash commands are validated by tool_sandbox.py
but never actually executed. This keeps the prototype safe during testing.
"""


def execute(command: str) -> str:
    return f"[bash stub] would have run: {command!r}"
