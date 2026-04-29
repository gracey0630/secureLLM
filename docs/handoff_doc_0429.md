# Handoff Document — All Team Members
**Date:** April 29, 2026
**From:** Person C
**To:** Person A, Person B, Person C
**Context:** Week 3 First Half begins. All 4 pipeline layers are wired and functional.
Full ablation is unblocked. Presentation May 7. Paper due May 10.

---

## Current repo state (main + output-guard branch, PR open)

All pipeline layers implemented and wired into `pipeline/orchestrator.py`:

| Component | File | Status |
|---|---|---|
| Input Scanner | `pipeline/input_scanner.py` | ✓ Done |
| Policy Engine | `pipeline/policy_engine.py` | ✓ Done |
| Tool Sandbox | `pipeline/tool_sandbox.py` | ✓ Done |
| Output Guard | `pipeline/output_guard.py` | ✓ Done — PR open (`output-guard` branch) |
| Orchestrator | `pipeline/orchestrator.py` | ✓ All 5 layers wired |
| Canary loop | `pipeline/canary.py` | ✓ Done |

Eval scripts:

| Script | Status |
|---|---|
| `evaluation/eval_b0.py` | ✓ Done — SecUtil=0.000 |
| `evaluation/eval_b1.py` | ✓ Done — SecUtil=0.403 |
| `evaluation/eval_b2.py` | ✓ Done — SecUtil=0.926 |
| `evaluation/eval_policy.py` | ✓ Done — 19/19 blocked, <1ms |
| `evaluation/eval_tool_sandbox.py` | ✓ Done — 14/14 blocked, p95=0.280ms |
| `evaluation/eval_output_guard.py` | ✓ Done — TP=9 TN=9 FP=0 FN=2 (manual scenarios) |

Datasets: all 4 parquet files committed in `data/`. Logs: `logs/pipeline.jsonl` is canonical.

---

## Key results so far

| Config | SecUtil | TPR | FPR |
|---|---|---|---|
| B0 — unprotected | 0.000 | 0.000 | 0.000 |
| B1 — heuristic only | 0.403 | 0.297 | 0.091 |
| B2 — LLM Guard standalone | 0.926 | 1.000 | 0.061 |
| Full pipeline | **TBD — Person A** | — | — |

Output Guard isolated eval (manual scenarios, n=20): TP=9, TN=9, FP=0, FN=2.
FNs are AWS key and OpenAI key formats — neither Presidio nor LLM Guard Sensitive covers these.
Document as limitations; credential scanner (detect-secrets) is future work.

---

## Action items by person — Week 3 (now through May 2)

### Person A — HIGHEST PRIORITY

The ablation matrix is the headline figure. It has been blocked since Week 2 waiting for
`output_guard.py`. That is now delivered and merged into the `output-guard` branch.

**Immediate steps:**
1. Merge the `output-guard` PR so main has all 4 layers
2. Run end-to-end pipeline smoke test: `python -m pipeline.orchestrator`
3. Run full ablation matrix — all layer combination configs:
   - Input Scanner only
   - Policy Engine only
   - Output Guard only
   - Input Scanner + Policy Engine
   - Input Scanner + Output Guard
   - All layers enabled
4. Run threshold sweep on Input Scanner (LLM Guard confidence 0.3→0.9) — this is the SecUtil curve
5. Measure latency p50/p95 per layer (production-volume run, ~500 rows minimum)

To run Output Guard in the pipeline, set `config["output_guard"] = True`. Both Presidio
and LLM Guard Sensitive will lazy-load on first call (~30s on first run, cached after).

**Toggle flags for ablation configs:**
```python
# Example: input scanner only
config = {"input_scanner": True, "policy_engine": False, "tool_sandbox": False, "output_guard": False}

# Example: full pipeline
config = {"input_scanner": True, "policy_engine": True, "tool_sandbox": True, "output_guard": True}
```

**Deliverable by ~May 2:** All quantitative results final. SecUtil tradeoff curve plots ready.

---

### Person B — case studies

The pipeline is fully functional. Run the orchestrator live to capture real traces for the case studies.

**Case studies needed (3–5, pick the most compelling):**

1. **Canary loop catch** — find a HackAPrompt prompt that scores below the Input Scanner
   threshold (slips through), reaches Claude, and produces a response where the canary leaks.
   This is the key case that justifies the canary architecture.
   - Run with `config = {"input_scanner": True, "output_guard": True, "policy_engine": False}`
   - Use a prompt from HackAPrompt level 5–9 that B1 misses (TPR=0.297 means ~70% slip through B1)

2. **Tool Sandbox block** — prompt that causes Claude to emit a bash command blocked by the
   sandbox. Use guest role + injection prompt. Trace should show: policy engine passes (tool type
   permitted), sandbox blocks (argument unsafe).

3. **False positive on legitimate query** — a clean LMSYS query that triggers a layer. Document
   which layer, why, and what the FPR cost is. Use `ground_truth_label="legitimate"` in the run.

4. **Full pipeline end-to-end trace** — one HackAPrompt level-9 attack through all layers enabled.
   Show the per-layer decision and final block.

To capture a trace, inspect the dict returned by `run_pipeline()` — it contains the full
`layer_results` breakdown.

**Deliverable by ~May 2:** Case study write-ups complete.

---

### Person C — Streamlit demo

Start the core UI now. Do not wait for Person A's final numbers — the demo only needs
the live pipeline to respond, not final eval results.

**Architecture:**
- Streamlit app calls `POST /run` on the FastAPI server (start with `uvicorn pipeline.orchestrator:app --reload`)
- Do not import pipeline code directly into Streamlit — go through the API so the demo
  matches what the paper describes

**Core UI (build this first, Days 15–17):**
```
[Role dropdown: guest / user / admin]
[Layer toggle checkboxes: Input Scanner | Policy Engine | Tool Sandbox | Output Guard]
[Text input: "Enter a message..."]
[Submit button]

--- Results ---
Layer trace:
  Input Scanner   ✓ pass  (score: 0.03, method: heuristic)
  Policy Engine   ✗ BLOCK (bash not permitted for guest)
  Tool Sandbox    — skipped
  Output Guard    — skipped

Final decision: BLOCK
Response: [redacted text or denial message]
Latency: 142ms total
```

**Polish + deploy (Days 18–21):**
- Highlight redacted spans in the response text (Presidio entity markers)
- Add latency bar per layer
- Deploy to Streamlit Cloud: `streamlit deploy app.py` after pushing to a public repo

**Note on Output Guard latency:** First call loads Presidio + LLM Guard (~30s). Subsequent
calls are fast. Either lazy-load in a `@st.cache_resource` wrapper or add a "warm up" note
in the demo UI so the audience isn't surprised by the first-call delay.

**Deliverable by May 5:** Demo publicly accessible via URL (before rehearsal).

---

## Critical path to May 7 presentation

```
Apr 29–May 2  Person A: ablation matrix + tradeoff curves (BLOCKING slides)
Apr 29–May 2  Person B: case studies
Apr 29–May 3  Person C: demo functional (core UI + API wiring)
May 2–May 5   All: report draft — Abstract, Methodology, Results sections
May 5         Person C: demo deployed to Streamlit Cloud
May 5–May 6   Person B+C: slides built (figures from Person A's results)
May 7         PRESENTATION
May 7–May 10  Final report polish + submission
```

---

## Do NOT

- Redirect stdout to `logs/pipeline.jsonl` — use `log_request()` / `log_event()` only.
  The log was corrupted once already (commit 083d8a7) and had to be restored from git history.
- Import pipeline modules directly in Streamlit — go through FastAPI.
- Run `eval_output_guard.py` Section 1 (ai4privacy, 200 rows) without `--skip-pii` unless you
  have 10+ minutes; the LLM Guard model load + 200 inference passes takes a while.
