# Handoff Document — Person C
**Date:** April 18, 2026
**From:** Person A
**To:** Person C (output_guard.py, canary loop, Streamlit demo)

---

## Where the project stands

Week 1 is complete. The evaluation harness is fully built and tested:

- `logging_schema.py` — canonical logger, use `log_request()` for every pipeline request
- `evaluation/metrics.py` — SecUtil, threshold sweep, latency stats
- `evaluation/_report.py` — shared `print_summary()` used by all eval scripts
- All 4 datasets cleaned and saved to `data/` as parquet
- B0 (unprotected): 2,324 rows, SecUtil=0.000
- B1 (heuristic):   2,334 rows, SecUtil=0.403, TPR=0.297, FPR=0.091
- B2 (LLM Guard):   2,334 rows, SecUtil=0.926, TPR=1.000, FPR=0.061

Baselines are split into runner + eval pairs:
```
baselines/b0_unprotected.py  →  evaluation/eval_b0.py
baselines/b1_heuristic.py    →  evaluation/eval_b1.py
baselines/b2_llmguard.py     →  evaluation/eval_b2.py  (+ logs/b2_sweep.csv)
```

Person B has completed:
- `pipeline/input_scanner.py` — `heuristic_scan()` and `llmguard_scan()`, both working
- `pipeline/canary.py` — canary generation and detection, **fully implemented and tested**

---

## Your immediate task: `pipeline/output_guard.py`

This is the last unbuilt Week 1 deliverable. It has three sub-components:

### 1. Presidio PII scanner
Detects and redacts PII (names, emails, phone numbers, SSNs) in LLM responses.

```python
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

analyzer  = AnalyzerEngine()
anonymizer = AnonymizerEngine()

results   = analyzer.analyze(text=response, language="en")
redacted  = anonymizer.anonymize(text=response, analyzer_results=results)
```

Test it against `data/ai4privacy.parquet` — that dataset has 2,000 rows of
real text containing PII. Your goal: measure recall (what % of PII does Presidio catch?)

```python
import pandas as pd
df = pd.read_parquet("data/ai4privacy.parquet")
# df["text"] contains unmasked text with real PII
```

### 2. LLM Guard output scanners
Two scanners complement Presidio:

```python
from llm_guard.output_scanners import Sensitive, Secrets

sensitive_scanner = Sensitive()
secrets_scanner   = Secrets()

_, is_valid_sensitive, score = sensitive_scanner.scan(prompt="", output=response)
_, is_valid_secrets,   score = secrets_scanner.scan(prompt="", output=response)
```

Run both on the same `ai4privacy` samples as Presidio. The head-to-head comparison
(Presidio vs LLM Guard recall) is a reported finding in the paper.

### 3. Canary leak detection
Already implemented in `pipeline/canary.py`. Just import and call it:

```python
from pipeline.canary import check_canary_leak

leaked = check_canary_leak(response=llm_response, canary=canary_token)
```

The `canary_token` travels from the Input Scanner (Person B) through the pipeline
orchestrator to your Output Guard. For isolated testing, generate your own:

```python
from pipeline.canary import generate_canary
canary = generate_canary()   # e.g. "[A3F9B2C1D4E56F78]"
```

---

## Required function signature

Every pipeline component uses the toggle flag pattern. Your function must look like this:

```python
def output_guard(
    response: str,
    canary: str | None,
    config: dict,          # toggle flags — {"presidio": True, "llm_guard": True, "canary": True}
) -> tuple[bool, dict]:
    """
    Returns
    -------
    (triggered, layer_result)

    layer_result must match the canonical schema:
    {
        "triggered":     bool,   # True if any scanner fired
        "redacted":      bool,   # True if Presidio/LLM Guard redacted anything
        "canary_leaked": bool,   # True if canary appeared in response
    }
    """
```

The `layer_result` dict gets passed directly to `log_request()` as
`layer_results["output_guard"]`. See `logging_schema.py` for the full schema.

---

## Logging — how to plug into the harness

Every request must log via `log_request()`. During **isolated development**
(before the full pipeline orchestrator exists in Week 2), use `log_event()` for
per-request debug lines. See `logging_schema.py` — it has clear docstrings.

Example of what your layer_result should look like in `pipeline.jsonl`:

```json
"output_guard": {
    "triggered": true,
    "redacted": true,
    "canary_leaked": false
}
```

---

## File to create

**`pipeline/output_guard.py`** — mirrors the structure of `pipeline/input_scanner.py`.
Read that file first — it shows the exact pattern (stateless functions, lazy model
loading, smoke test in `__main__`).

---

## Week 1 deliverable

By end of Week 1 (today):
- [ ] Presidio installed and tested on `ai4privacy.parquet` — record recall numbers
- [ ] LLM Guard `Sensitive` + `Secrets` scanners tested on same data
- [ ] `output_guard()` function stubbed with correct signature and toggle flags
- [ ] `check_canary_leak()` wired in from `canary.py`

Evaluation script for output_guard will be `evaluation/eval_output_guard.py` —
follow the same pattern as `evaluation/eval_b0.py` (read pipeline.jsonl, call
`print_summary()` from `evaluation/_report.py`).

---

## Install dependencies

```bash
pip install presidio-analyzer presidio-anonymizer
python -m spacy download en_core_web_lg   # required by Presidio
```

LLM Guard is already installed (used by input_scanner.py).

---

## Key files to read before starting

| File | Why |
|---|---|
| `pipeline/canary.py` | Canary is fully done — just import, don't rewrite |
| `pipeline/input_scanner.py` | Shows the exact code pattern to follow |
| `logging_schema.py` | Understand `log_request()` before logging anything |
| `docs/claude.md` | Project scope boundaries and design decisions |
| `docs/report_notes.md` | Running log of findings worth noting in the paper |

---

## What NOT to build (scope boundaries)

- Do not build a true content moderation system — Presidio + LLM Guard as-is
- Do not add ML models beyond what LLM Guard ships with
- Do not implement multi-turn memory or session tracking
- Streamlit demo is Week 3 — do not start it yet
