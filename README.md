# SecureLLM

A 4-layer security pipeline for a tool-using corporate LLM assistant, built to detect and contain prompt injection, privilege escalation, and PII/credential leakage. Each layer is independently toggleable — enabling targeted QA and ablation testing to identify exactly which threats each component catches.

**Course:** STAT GR5293 — Generative AI, Columbia University  
**Team:** Grace Yoon, Selina Park, Kanchan Bhale

---

## Pipeline Architecture

The pipeline wraps Claude Haiku and intercepts requests at four enforcement points. Security is enforced at the execution layer — not the model layer — so it works regardless of model alignment.

| Layer | Threat addressed | Key technology | Default |
|---|---|---|---|
| Input Scanner | Prompt injection | LLM Guard DeBERTa + InvisibleText | On |
| Policy Engine | Privilege escalation | RBAC allowlist (guest / user / admin) | On |
| Tool Sandbox | Unsafe command arguments | Regex + bashlex AST | Off |
| Output Guard | PII and credential leakage | Presidio + LLM Guard Sensitive + detect-secrets | Off |

All four layers share a common toggle interface (`config` dict), so any subset can be enabled independently for ablation or targeted testing.

---

## Key Results

### Input Scanner — prompt injection detection (n=2,314)

We evaluate using **SecUtil = F1_attack × (1 − FPR_legitimate)** rather than accuracy or F1 alone. Standard metrics don't penalize a scanner that blocks everything — SecUtil does, by requiring that attack detection comes without excessive false positives on legitimate traffic. A system that blocks all users achieves SecUtil=0.

| Baseline | TPR | FPR | SecUtil |
|---|---|---|---|
| B0 — unprotected | 0.000 | 0.000 | 0.000 |
| B1 — heuristic regex | 0.298 | 0.089 | 0.406 |
| B2 — LLM Guard DeBERTa | **1.000** | 0.045 | **0.945** |

B2 achieves TPR=1.0 across all thresholds 0.30→0.95, showing that a semantic classifier far outperforms regex for injection detection. The remaining 4.5% FPR represents a real usability tradeoff — one in twenty legitimate messages is blocked — which motivates combining B2 with role-based access control rather than relying on the scanner alone.

### Policy Engine — privilege escalation (n=22 attack cases)

- Containment rate: **100%** (all injections blocked or refused)
- False positive rate: **0%** on legitimate requests
- Median enforcement latency: **0.015 ms**

100% containment with zero false positives demonstrates that deterministic allowlist enforcement is both highly reliable and essentially free in latency. This validates the core design decision: rule-based execution-layer enforcement is a stronger and more predictable guarantee than relying on model refusals alone.

### Tool Sandbox — unsafe argument validation (n=14 attack cases)

- Containment rate: **100%** (direct + obfuscated violations)
- False positive rate: **0%**
- Two-stage validation: regex (fast path) + bashlex AST (semantic)

The sandbox catches obfuscated attacks (e.g. shell metacharacter injection, semicolon-chained commands) that pass a regex-only check, showing that AST-level validation meaningfully extends coverage beyond pattern matching. The corpus is hand-crafted and small — broader evaluation against a larger attack corpus remains future work.

### Output Guard — PII recall (n=200)

- Presidio recall: 0.755 — LLM Guard Sensitive recall: 0.210
- Combined recall: **0.795**
- Manual end-to-end accuracy: **0.958** (13/14 threats caught, 0 false positives)

Presidio carries most of the detection load; LLM Guard Sensitive adds modest incremental coverage. A combined recall of 0.795 means roughly 1 in 5 PII-containing responses still leak — a meaningful limitation for production use, and a signal that output-side detection alone is insufficient without upstream data access controls.

---

## Repository Structure

```
secureLLM/
├── pipeline/
│   ├── orchestrator.py     # Full pipeline — run_pipeline() + FastAPI endpoint
│   ├── input_scanner.py    # Heuristic + LLM Guard prompt injection scanners
│   ├── policy_engine.py    # RBAC enforcement
│   ├── tool_sandbox.py     # Argument-level validation (regex + AST)
│   ├── sandbox_ast.py      # bashlex AST stage of tool sandbox
│   ├── output_guard.py     # PII redaction + credential + canary detection
│   ├── canary.py           # Per-request canary token injection + leak check
│   └── b0_server.py        # Unprotected baseline server
├── tools/
│   ├── bash.py             # Bash stub (validated but not executed)
│   ├── file_read.py
│   ├── file_write.py
│   └── search.py
├── evaluation/
│   ├── eval_b0.py                  # B0 baseline eval
│   ├── eval_b1.py                  # B1 heuristic eval
│   ├── eval_b2.py                  # B2 LLM Guard eval + threshold sweep
│   ├── eval_combined.py            # Combined scanner comparison
│   ├── eval_policy.py              # Policy engine eval
│   ├── eval_tool_sandbox.py        # Sandbox unit eval (direct check_sandbox() calls)
│   ├── eval_tool_sandbox_e2e.py    # Sandbox end-to-end eval (full pipeline)
│   ├── eval_garak_sandbox.py       # Sandbox eval against garak adversarial probes
│   ├── eval_garak_e2e.py           # End-to-end adversarial probes (garak)
│   ├── eval_output_guard.py        # Output guard eval
│   ├── compile_results.py          # Aggregates all results → results/paper_results.json
│   ├── metrics.py                  # SecUtil + shared metric helpers
│   ├── plots.py                    # Result visualizations
│   ├── policy_corpus.py            # Policy engine test corpus
│   ├── sandbox_corpus.py           # Tool sandbox test corpus
│   ├── run_latency.py              # Latency measurement
│   └── setup_latency_fixtures.py   # Creates stub files for latency eval
├── baselines/              # B0/B1/B2 baseline implementations
├── results/                # Pre-computed eval outputs (committed)
├── docs/
│   └── report_notes.md     # Paper section reference and methodology notes
├── tests/
│   ├── test_policy_engine.py
│   └── test_policy_integration.py
├── logs/
│   └── pipeline.jsonl      # Canonical request log (8,858 rows)
├── data/                   # Dataset parquet files (gitignored — regenerate below)
├── app.py                  # Streamlit demo interface
├── constants.py            # Tool taxonomy + role allowlist
├── logging_schema.py       # Shared logging schema
├── load_datasets.py        # Downloads and caches all datasets
└── requirements.txt
```

---

## Setup

**Requirements:** Python 3.11, an Anthropic API key.

```bash
# 1. Clone and enter repo
git clone https://github.com/gracey0630/secureLLM && cd secureLLM

# 2. Create virtual environment
python3.11 -m venv .venv && source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_lg

# 4. Set your API key
echo "ANTHROPIC_API_KEY=your_key_here" > .env

# 5. Load datasets (downloads HackAPrompt, deepset, lmsys, ai4privacy)
python load_datasets.py

# 6. Run tests
pytest tests/
```

> **Note:** lmsys/lmsys-chat-1m is gated on Hugging Face. Request access at [huggingface.co/datasets/lmsys/lmsys-chat-1m](https://huggingface.co/datasets/lmsys/lmsys-chat-1m) and set `HF_TOKEN` in your `.env`.

---

## Run the Demo

```bash
streamlit run app.py
```

The demo lets you select a role (guest / user / admin), toggle each security layer independently, and send messages to observe how the pipeline responds to both legitimate requests and injection attempts.

---

## Reproducing Results

All pre-computed results are already committed in `results/`. To reproduce from scratch:

```bash
# Input scanner baselines and threshold sweep
python -m evaluation.eval_b0
python -m evaluation.eval_b1
python -m evaluation.eval_b2
python -m evaluation.eval_combined

# Policy engine
python -m evaluation.eval_policy

# Tool sandbox (unit, end-to-end, and garak adversarial probes)
python -m evaluation.eval_tool_sandbox
python -m evaluation.eval_tool_sandbox_e2e
python -m evaluation.eval_garak_sandbox

# Output guard
python -m evaluation.eval_output_guard

# End-to-end adversarial probes (garak)
python -m evaluation.eval_garak_e2e

# Aggregate all results into one file
python -m evaluation.compile_results
# → results/paper_results.json
```

Each script reads from `data/` (generated by `load_datasets.py`) and writes its output to `results/`.
