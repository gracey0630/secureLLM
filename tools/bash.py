"""
tools/bash.py — Stub bash tool. Returns hardcoded output; no real subprocess.

Real command execution and safety validation is deferred to tool_sandbox.py.
This stub exists so the orchestrator can demonstrate permitted tool calls
returning a result without accidental shell execution during testing.
"""


def execute(command: str) -> str:
    return f"[bash stub] would have run: {command!r}\n(real execution pending tool_sandbox integration)"
