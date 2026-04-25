# Handoff Document — Person C
**Date:** April 25, 2026 (updated from April 18)
**From:** Person A + Person B
**To:** Person C (output_guard.py, orchestrator wiring, manual scenario eval, Streamlit demo)

---

## Where the project stands

Week 1 + Week 2 are complete on the Person A/B side. Main branch has:

- `logging_schema.py` — canonical logger, `log_request()` + `log_event()` + `Timer`
- `evaluation/metrics.py` — SecUtil, threshold sweep, latency stats
- All 4 datasets in `data/` as parquet
- B0 (unprotected): SecUtil=0.000 | B1 (heuristic): SecUtil=0.403 | B2 (LLM Guard): SecUtil=0.926
- `pipeline/input_scanner.py` — `heuristic_scan()` + `llmguard_scan()`
- `pipeline/canary.py` — canary generation, injection, detection — **fully done, do not rewrite**
- `pipeline/policy_engine.py` — RBAC enforcement (guest/user/admin), `check_policy()`
- `pipeline/tool_sandbox.py` — argument-level command validator, `check_sandbox()`
- `pipeline/orchestrator.py` — full FastAPI pipeline, all 4 layers wired with toggle flags

The orchestrator already has `output_guard` as a toggle slot:
```python
layers_enabled = {
    "input_scanner": ...,
    "policy_engine": ...,
    "tool_sandbox":  ...,
    "output_guard":  False,   # ← your layer goes here
}
layer_results["output_guard"] = None  # ← your result goes here
```

---

## Your outstanding deliverables (in priority order)

### 1. `pipeline/output_guard.py` — **overdue from Week 2, do this first**

You already have three standalone scripts on main (`presidio_scanner.py`,
`llmguard_output_scanner.py`, `canary_set.py`). These need to be unified into one
pipeline-compatible module.

Required function signature (unchanged from original handoff):
```python
def run_output_guard(
    response: str,
    canary: str | None,
    config: dict,
) -> tuple[bool, dict]:
    """
    Returns (triggered, layer_result).

    layer_result schema:
    {
        "triggered":     bool,   # True if any scanner fired
        "redacted":      bool,   # True if Presidio/LLM Guard modified the response
        "canary_leaked": bool,   # True if canary appears in response
    }
    """
```

Internals — wrap your existing code:
- Call Presidio analyzer + anonymizer on `response`
- Call LLM Guard `Sensitive` scanner on `response`
- Call `check_canary_leak(response, canary)` from `pipeline/canary.py`
- `triggered = redacted or canary_leaked`
- Respect `config` sub-toggles: `{"presidio": True, "llm_guard": True, "canary": True}`
- Toggle-disabled passthrough: return `(False, {"triggered": False, ..., "reason": "toggle_disabled"})`

Read `pipeline/policy_engine.py` — it shows the exact pattern for toggle passthrough
and return shape. Read `pipeline/input_scanner.py` for lazy model loading.

### 2. Wire `run_output_guard()` into `pipeline/orchestrator.py`

In `run_pipeline()`, after the tool execution block, add:
```python
if layers_enabled["output_guard"]:
    with Timer() as t:
        og_triggered, og_result = run_output_guard(response_text, canary, config)
    latency_ms["output_guard"] = t.ms
    layer_results["output_guard"] = og_result
    if og_triggered:
        final_decision = "block"   # or "redact" if only PII was found
```

### 3. `evaluation/eval_output_guard.py` — isolated evaluation

Two datasets to run against:
- `data/ai4privacy.parquet` — 2,000 rows for PII recall (Presidio vs LLM Guard head-to-head)
- `data/canary_set.parquet` — 100 synthetic credential outputs for canary/secrets detection

Call `run_output_guard()` directly (not `run_pipeline()`), same as how
`eval_tool_sandbox.py` calls `check_sandbox()` directly. No API calls needed.

Output table:
```
Presidio recall    — PERSON / EMAIL / PHONE / SSN
LLM Guard recall   — same entity types (head-to-head)
Canary detection   — X/100 canary set caught
False positive rate — on clean LMSYS samples
```

### 4. Manual scenario eval (Terminal-Bench fallback — use this path)

Skip Terminal-Bench integration. Build 15–20 hardcoded malicious LLM outputs that
represent compromised-LLM scenarios, then feed them directly to `run_output_guard()`:

- 5 outputs containing PII leakage (names + SSNs embedded in prose)
- 5 outputs containing credential leakage (API keys, AWS creds)
- 5 outputs where canary appears (instruction extraction attack succeeded)
- 5 clean outputs (legitimate — should not trigger)

This is faster, has 100% label certainty, and produces a cleaner paper result than
Terminal-Bench integration would.

---

## Critical path note

**Person A cannot complete the full ablation matrix until output_guard is wired into
the orchestrator.** The ablation (all layer combinations) is the headline figure and
is due in Week 3, First Half (Days 15–17). Please deliver `output_guard.py` + orchestrator
wiring by Day 16 at the latest — preferably earlier.

---

## Logging rules — do not repeat Person C's previous mistake

**Never redirect stdout to `logs/pipeline.jsonl`.** The log was corrupted and had to be
restored from git history (commit 083d8a7). Always use `log_request()` or `log_event()`
from `logging_schema.py`. These write via `open("a")` append mode internally.

The canonical log is committed to the repo. Every teammate reads from it. Corrupting it
blocks everyone.

---

## Files to read before starting

| File | Why |
|---|---|
| `pipeline/canary.py` | Already done — import `check_canary_leak`, don't rewrite |
| `pipeline/policy_engine.py` | Shows toggle passthrough + return shape pattern |
| `pipeline/tool_sandbox.py` | Simplest layer — clearest example of the (bool, dict) contract |
| `pipeline/orchestrator.py` | Shows how layers_enabled/layer_results/Timer are used |
| `logging_schema.py` | Understand `log_request()` before logging anything |

---

## What NOT to build

- No new ML models — Presidio + LLM Guard as-is
- No multi-turn memory
- No Terminal-Bench integration — use manual scenario set instead
- Streamlit demo is still Week 3 — do not start it yet
