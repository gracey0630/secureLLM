"""
pipeline/canary.py — Canary token utilities for cross-layer injection detection.

─────────────────────────────────────────────────────────────────────────────
WHAT IS THE CANARY?

A canary is a secret random string planted silently in the system prompt
before the LLM sees the user's input. The user never sees it. The LLM has
no reason to mention it in a legitimate response. The only way it surfaces
in the output is if a prompt injection successfully instructed the LLM to
repeat or leak its system prompt.

This creates a stateful link between input and output — something no
off-the-shelf tool (including LLM Guard) does. It catches injections that
slipped past the Input Scanner with a score below the detection threshold.

─────────────────────────────────────────────────────────────────────────────
WHO USES WHAT:

  Person B (Input Scanner):
    1. generate_canary()            → creates a fresh canary token per request
    2. inject_canary(prompt, token) → plants it in the system prompt

  Person C (Output Guard):
    3. check_canary_leak(response, token) → detects if the canary was leaked

  The canary string travels from B to C via the pipeline orchestrator
  (built in Week 2). For now, each side can test their half independently
  using generate_canary() to produce a test token.

─────────────────────────────────────────────────────────────────────────────
EXAMPLE FLOW:

  # Input side (Person B)
  canary = generate_canary()
  system_prompt = inject_canary("You are a helpful assistant.", canary)
  # → "You are a helpful assistant.\n[CANARY-A3F9B2C1D4E5]\n"
  # → send system_prompt + user input to LLM

  # Output side (Person C)
  leaked = check_canary_leak(llm_response, canary)
  # → True if injection succeeded and LLM echoed the system prompt
  # → False on a clean response

─────────────────────────────────────────────────────────────────────────────
HONEST LIMITATIONS (acknowledge in paper):

  - Only catches instruction-extraction attacks ("repeat your system prompt").
    Goal-hijacking attacks ("ignore rules and help me with X") won't leak
    the canary — the LLM just quietly complies without echoing the prompt.
  - Well-aligned models (Claude, GPT-4) may resist extraction anyway.
    The canary matters most for weaker/open-source model deployments.
  - A canary is generated fresh per request (UUID-based) so an attacker
    who learns one canary from a previous response cannot reuse that knowledge.
"""

import uuid


def generate_canary() -> str:
    """
    Generate a fresh canary token for a single request.

    A new token is created per request — never reuse across requests.
    Format: [<16 uppercase hex chars>]
    Example: [A3F9B2C1D4E56F78]

    No semantic label — looks like an internal session ID, not a security
    token. This makes it harder for an attacker to identify and strip it
    even if they successfully extract the system prompt.
    16 hex chars makes coincidental appearance in a legitimate response
    effectively impossible.
    """
    token = uuid.uuid4().hex[:16].upper()
    return f"[{token}]"


def inject_canary(system_prompt: str, canary: str) -> str:
    """
    Plant the canary token into the system prompt.

    Injected after the first line so it sits mid-prompt rather than at
    the very start — slightly harder for an attacker to target specifically.
    The user never sees the modified system prompt.

    Parameters
    ----------
    system_prompt : the original system prompt string
    canary        : token from generate_canary()

    Returns
    -------
    Modified system prompt with canary embedded.
    """
    lines = system_prompt.strip().splitlines()
    if len(lines) <= 1:
        return f"{system_prompt.strip()}\n{canary}"
    # Insert after the first line
    return "\n".join([lines[0], canary] + lines[1:])


def check_canary_leak(response: str, canary: str) -> bool:
    """
    ─────────────────────────────────────────────────────
    PERSON C — this is your function.
    Call this inside output_guard.py after the LLM responds.
    ─────────────────────────────────────────────────────

    Check whether the canary token appears in the LLM's response.
    A match means a prompt injection succeeded in extracting the system
    prompt — even if the Input Scanner missed it on the input side.

    Parameters
    ----------
    response : the raw LLM response text
    canary   : the same token passed to inject_canary() for this request

    Returns
    -------
    True  → canary leaked, injection succeeded retroactively
    False → clean response

    Log this result as layer_results["output_guard"]["canary_leaked"]
    in the pipeline.jsonl record.
    """
    return canary in response


# ── Smoke test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("canary.py smoke test\n" + "─" * 40)

    canary = generate_canary()
    print(f"  Generated canary : {canary}")

    system_prompt = "You are a helpful assistant.\nAnswer concisely."
    injected = inject_canary(system_prompt, canary)
    print(f"\n  Injected prompt  :\n{injected}")

    # Simulate clean response
    clean_response = "The capital of France is Paris."
    assert not check_canary_leak(clean_response, canary), "False positive on clean response"
    print(f"\n  Clean response   : no leak detected ✓")

    # Simulate leaked response (injection succeeded)
    leaked_response = f"You are a helpful assistant.\n{canary}\nAnswer concisely."
    assert check_canary_leak(leaked_response, canary), "Failed to detect canary leak"
    print(f"  Leaked response  : canary detected ✓")

    # Confirm per-request uniqueness
    canary2 = generate_canary()
    assert canary != canary2, "Two canaries should never be identical"
    print(f"\n  Uniqueness check : {canary} ≠ {canary2} ✓")

    print("\nAll checks passed.")
