# CLAUDE.md — SecureLLM Runtime

## What This Project Is

SecureLLM is a layered security middleware for LLM applications. It wraps existing
tools (LLM Guard, Presidio) into a unified, toggleable 4-layer pipeline and contributes
a novel evaluation framework (SecUtil metric) measuring security AND usability jointly.

This is a course project (STAT GR5293 GenAI). Code quality, reproducibility, and
evaluation rigor matter more than architectural complexity.

**Hard deadlines: Presentation May 7 · Paper due May 10**

---

## Current Repo State

```
secureLLM/
├── data/                        # parquet files — COMMITTED (teammates skip re-download)
│   ├── hackaprompt.parquet      # 1583 attack rows, 200/level cap (done)
│   ├── deepset.parquet          # 546 rows, mixed labels (done)
│   ├── lmsys.parquet            # 731 legitimate rows (done)
│   └── ai4privacy.parquet       # 2000 rows for PII eval (done)
├── logs/
│   ├── pipeline.jsonl           # COMMITTED — canonical eval log (teammates skip B0 re-run)
│   └── b2_*.csv                 # gitignored — derived scores, re-generate with b2_llmguard.py
├── results/                     # eval outputs (gitignored)
├── baselines/
│   ├── b0_unprotected.py        # done — 2324 rows, SecUtil=0.000
│   ├── b1_heuristic.py          # done — 2334 rows, SecUtil=0.403
│   └── b2_llmguard.py           # done — 2334 rows, SecUtil=0.926
├── evaluation/
│   ├── _report.py               # shared print_summary() for all eval scripts
│   ├── metrics.py               # SecUtil, threshold_sweep, latency stats
│   ├── plots.py                 # tradeoff curve figures (Week 3)
│   ├── eval_b0.py               # B0 metrics
│   ├── eval_b1.py               # B1 metrics
│   └── eval_b2.py               # B2 metrics + threshold sweep
├── pipeline/
│   ├── input_scanner.py         # done — heuristic_scan() + llmguard_scan()
│   ├── canary.py                # done — generate, inject, detect canary
│   └── b0_server.py             # FastAPI server for B0 (demo use)
├── load_datasets.py             # done
├── logging_schema.py            # done — log_request() + log_event() + Timer
├── handoff_doc_0418.md          # Person C handoff instructions
├── report_notes.md              # running findings log for paper
├── requirements.txt
├── Dockerfile
└── README.md
```

Not yet built: `pipeline/output_guard.py`, `pipeline/policy_engine.py`,
`pipeline/tool_sandbox.py`, `tests/`

---

## Architecture (Fixed Scope)

Four independently toggleable layers around a test LLM assistant:

```
User Input
    │
    ▼
[1] Input Scanner        ← heuristic regex + LLM Guard PromptInjection scanner
    │                      (deepset/deberta-v3-base-injection underneath)
    ▼
[2] Policy Engine        ← custom RBAC decorator (guest/user/admin roles)
    │
    ▼
[3] LLM Assistant        ← Claude or GPT-3.5 via API
    │
    ▼
[4] Tool Sandbox         ← command allowlist/blocklist validator + LLM Guard BanCode
    │
    ▼
[5] Output Guard         ← Presidio + LLM Guard Sensitive/Secrets + canary check
    │
    ▼
Response to User
```

**Canary loop (key novelty):** Input Scanner plants a secret string in the system
prompt. Output Guard checks if it appears in the LLM response. This catches injections
that bypassed input-side scanning. B and C must agree on canary format before
implementing their respective halves.

**Toggle flags:** Every layer must be independently enable/disable-able via a config
dict or YAML. This is not a product feature — it enables the ablation experiment.

---

## What We Are NOT Building

- A new ML model or scanner (we use LLM Guard and Presidio as-is)
- A true execution sandbox (Tool Sandbox = command validator only)
- Multi-turn session memory
- GCP deployment (Streamlit Cloud or HuggingFace Spaces is sufficient)

---

## Primary Scientific Contribution

**SecUtil metric:**
```
SecUtil = F1_attack × (1 - FPR_legitimate)
```

Sweep Input Scanner confidence threshold 0.3→0.9. At each threshold, compute SecUtil.
Plot as a tradeoff curve. Do this for: heuristic-only, LLM Guard standalone, each
isolated layer, full pipeline. This plot is the headline result — no existing tool
produces it because none has a toggleable layered architecture.

---

## Datasets

| Dataset | HuggingFace ID | Use | Access |
|---------|---------------|-----|--------|
| HackAPrompt | `hackaprompt/hackaprompt-dataset` | Attack corpus — filter `correct=True`, stratify by `level` | Public |
| Deepset | `deepset/prompt-injections` | FPR measurement (has legitimate examples) | Public |
| LMSYS-Chat-1M | `lmsys/lmsys-chat-1m` | Legitimate query FPR ground truth (sample 500-1000) | Gated — needs HF_TOKEN |
| ai4privacy | `ai4privacy/pii-masking-200k` | Output Guard PII recall | Public |
| Synthetic canary | generated via `faker` | 50-100 outputs with fake API keys, SSNs, credentials | Self-generated |
| Garak probes | `pip install garak` | Tool Sandbox adversarial probes | CLI tool |

**Critical:** Do NOT evaluate LLM Guard's PromptInjection scanner on Deepset —
it was trained on that dataset. Use HackAPrompt for the LLM Guard comparison.

---

## Baselines (3 external, not 8)

| ID | What | Purpose |
|----|------|---------|
| B0 | Unprotected assistant | Vulnerability floor |
| B1 | Heuristic-only filter | Cheap-defense lower bound |
| B2 | LLM Guard standalone | Best existing single-tool reference |

B1-B4 in the v2 doc are **ablations of our own system**, not external baselines.
Call them ablations in code and in the report.

---

## Logging Schema (logging_schema.py — build this first)

Every request through the pipeline must log:
```json
{
  "request_id": "uuid",
  "timestamp": "ISO8601",
  "input_text": "...",
  "layers_enabled": {"input_scanner": true, "policy_engine": true, ...},
  "layer_results": {
    "input_scanner": {"triggered": false, "score": 0.12, "method": "llm_guard"},
    "policy_engine": {"triggered": false, "role": "user"},
    "tool_sandbox": {"triggered": false, "command": null},
    "output_guard": {"triggered": false, "redacted": false, "canary_leaked": false}
  },
  "final_decision": "pass",
  "latency_ms": {"input_scanner": 42, "policy_engine": 1, "tool_sandbox": 5, "output_guard": 38, "total": 86},
  "dataset_source": "hackaprompt",
  "ground_truth_label": "attack"
}
```

---

## Metrics (evaluation/metrics.py — build this first)

```python
# Implemented in evaluation/metrics.py
def compute_secutil(f1_attack: float, fpr_legitimate: float) -> float
def compute_classification_metrics(y_true, y_pred) -> dict  # TPR, FPR, precision, F1
def threshold_sweep(scorer, inputs, labels, thresholds) -> pd.DataFrame
def compute_latency_stats(latency_list) -> dict  # p50, p95
```

---

## Team Responsibilities

- **Person A** — `load_datasets.py`, `logging_schema.py`, `evaluation/metrics.py`,
  B0 unprotected assistant, all baseline runs, figures, report Introduction + Related Work
- **Person B** — `pipeline/input_scanner.py`, `pipeline/policy_engine.py`,
  `pipeline/tool_sandbox.py`, case studies, presentation slides
- **Person C** — `pipeline/output_guard.py`, canary loop, Streamlit demo,
  deployment to Streamlit Cloud or HuggingFace Spaces

---

## Schedule

```
Week 1 (Apr 12 – Apr 18):
  [DONE] logging_schema.py + metrics.py + evaluation/_report.py (Person A)
  [DONE] load_datasets.py — all 4 datasets cleaned to parquet (Person A)
  [DONE] B0 evaluated — 2324 rows, SecUtil=0.000 (Person A)
  [DONE] B1 evaluated — 2334 rows, SecUtil=0.403, TPR=0.297, FPR=0.091 (Person A)
  [DONE] B2 evaluated — 2334 rows, SecUtil=0.926, TPR=1.000, FPR=0.061 (Person A)
  [DONE] input_scanner.py — heuristic_scan() + llmguard_scan() (Person B)
  [DONE] canary.py — canary format agreed, generate/inject/detect implemented (Person B)
  [PENDING] output_guard.py skeleton + Presidio test (Person C)

Week 2 (Apr 19 – Apr 25):
  - FastAPI pipeline with toggle flags (Person A)
  - policy_engine.py — RBAC decorator, 3 roles (Person B)
  - Output Guard integrated, isolated eval complete (Person C)
  - tool_sandbox.py — command validator + Garak eval (Person B)
  - Terminal-Bench attempt — 2-day cap, fallback to manual scenarios (Person C)
  - First complete ablation matrix run (Person A)

Week 3 (Apr 26 – May 2):
  - Full threshold sweep + SecUtil curves (Person A)
  - All latency measurements (Person A)
  - Case studies written (Person B)
  - Streamlit demo built and deployed (Person C)
  - Report: Introduction + Related Work + Methodology drafted (all)

Week 4 (May 3 – May 10):
  - Results + Analysis + Limitations written (all)
  - Figures finalized, repo cleaned (Person A)
  - Slides built (Person B + C)               ← Presentation May 7
  - Full rehearsal + paper submission (all)    ← Paper due May 10
```

---

## Key Libraries

```
llm-guard>=0.3.6           # Input Scanner + Output Guard scanners
presidio-analyzer>=2.2.0   # PII detection
presidio-anonymizer>=2.2.0 # PII redaction
garak>=0.9.0               # Tool Sandbox adversarial probes
spacy>=3.7.0               # Presidio dependency (+ en_core_web_lg)
transformers>=4.36.0       # LLM Guard underlying model
fastapi>=0.110.0           # Pipeline API
streamlit>=1.32.0          # Demo UI
datasets>=2.17.0           # HuggingFace dataset loading
scikit-learn>=1.4.0        # Metrics
faker>=23.0.0              # Synthetic canary generation
loguru>=0.7.0              # Structured logging
```

---

## Design Decisions Already Made (Do Not Revisit Without Good Reason)

1. **LLM Guard is a component AND a baseline.** Comparison is LLM Guard standalone
   vs. full SecureLLM runtime. We do not claim our individual scanners beat LLM Guard's.

2. **Tool Sandbox is a command validator, not a true sandbox.** Scope was deliberately
   reduced for feasibility. Do not attempt Docker-in-Docker or seccomp.

3. **Rebuff is NOT a live baseline.** It is archived (May 2025), requires Pinecone +
   Supabase, and is cited as prior art only.

4. **SecUtil is the headline metric.** All implementation decisions should be
   evaluable through this lens.

5. **Logging harness is built before any component.** Nothing gets implemented without
   immediately plugging into the logger.

6. **B2 TPR=1.0 is real, not contamination.** HackAPrompt is confirmed NOT in
   deberta-v3's training data. The score distribution is perfectly binary (all attacks
   score 1.0). The pipeline's value over B2 is coverage breadth (indirect injection,
   tool-call attacks, PII leakage) — not SecUtil improvement on text injection.
   See report_notes.md for full discussion.

---

## How to Work With This Codebase

When I ask you to implement something:
- Check this file first for scope boundaries
- Prefer simple, testable functions over clever abstractions
- Every new component must accept the toggle flag pattern
- Every evaluation run must produce a log entry matching logging_schema.py
- If a design decision seems wrong, flag it and propose an alternative — don't
  silently work around it
- If the schedule needs to shift, say so explicitly with a reason

When I ask you to help think through a design:
- Be critical and realistic about feasibility
- Reference the SecUtil metric as the primary evaluation lens
- Flag if a proposed change conflicts with the baseline/ablation structure
