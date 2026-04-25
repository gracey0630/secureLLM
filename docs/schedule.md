## Immediate Action Items (Do This Week)

### Person A — Evaluation Harness + Datasets

**Action 1: Set up project repository and shared environment**
- Initialize GitHub repo with branch structure, `requirements.txt`, Docker skeleton
- Libraries: `Python 3.10+`, `fastapi`, `uvicorn`, `docker`, `pytest`
- Establish logging schema immediately: every request logs `input`, `layer_triggered`, `decision`, `latency_ms`, `timestamp`

**Action 2: Load and preprocess all datasets**
- HackAPrompt: `from datasets import load_dataset; load_dataset("hackaprompt/hackaprompt-dataset")` — filter `correct=True`, stratify by `level`
- Deepset: `load_dataset("deepset/prompt-injections")` — separate injection vs. legitimate splits
- LMSYS-Chat-1M: request access at `huggingface.co/datasets/lmsys/lmsys-chat-1m`, sample 500–1000 English prompts with no injection content
- `ai4privacy/pii-masking-200k`: load directly, no access required
- Deliverable: four clean pandas DataFrames saved as parquet, labeled with `text`, `label` (attack/legitimate), `source`, `difficulty` where available

**Action 3: Build evaluation harness skeleton**
- Implement the SecUtil metric: `SecUtil = F1_attack × (1 − FPR_legitimate)`
- Implement per-layer result logger: TPR, FPR, precision, F1, latency p50/p95
- Build threshold sweep function: takes a scorer and sweeps confidence threshold 0.3→0.9, outputs tradeoff curve data
- Libraries: `scikit-learn` (metrics), `numpy`, `pandas`, `matplotlib`/`seaborn` (plots)

**Action 4: Build and evaluate unprotected baseline assistant (B0)**
- Wrap a Claude or GPT-3.5 API call in a simple FastAPI endpoint with no security
- Run all attack datasets through it, log results into harness
- This is your vulnerability floor — the most dramatic number in the paper
- Libraries: `anthropic` or `openai` SDK, `fastapi`

---

### Person B — Input Scanner + Policy Engine

**Action 1: Implement heuristic pre-filter**
- Write regex patterns covering: instruction override phrases ("ignore previous instructions", "disregard above"), role-play triggers ("you are now", "act as"), delimiter attacks (`----`, `###SYSTEM`)
- Reference: HackAPrompt 29-technique taxonomy (Schulhoff et al., 2023, EMNLP) — use this to ensure pattern coverage across known attack categories
- Deliverable: a standalone function `heuristic_scan(text) → (bool, match_reason)`

**Action 2: Integrate LLM Guard PromptInjection scanner**
- `pip install llm-guard`
- Wrap `from llm_guard.input_scanners import PromptInjection` in your pipeline interface
- Expose confidence threshold as a tunable parameter — this drives the tradeoff curve
- Libraries: `llm-guard`, `transformers` (underlying model: `deepset/deberta-v3-base-injection`)
- Reference: LLM Guard docs at `protectai.github.io/llm-guard`

**Action 3: Design Policy Engine RBAC structure**
- Define three roles: `guest` (read-only, no tools), `user` (limited tools), `admin` (full tool access)
- Implement as a Python decorator that checks role before any tool call executes
- Define allowlist of safe tool calls per role — file reads allowed for `user`, no writes; bash execution only for `admin`
- Reference: OPA (Open Policy Agent) documentation for production framing in report, even though you implement a lighter version

**Action 4: Run Input Scanner against B0 baseline on datasets**
- Run heuristic-only, LLM Guard standalone, and heuristic+LLM Guard combined against HackAPrompt and Deepset
- Log all results into Person A's harness immediately
- This gives you early ablation numbers by end of week 1/start of week 2

---

### Person C — Output Guard + Demo Interface Planning

**Action 1: Set up Presidio**
- `pip install presidio-analyzer presidio-anonymizer`
- Run `python -m spacy download en_core_web_lg` (Presidio dependency)
- Test on `ai4privacy/pii-masking-200k` samples — establish baseline recall on name, email, phone, SSN entity types
- Libraries: `presidio-analyzer`, `presidio-anonymizer`, `spacy`
- Reference: Microsoft Presidio docs at `microsoft.github.io/presidio`

**Action 2: Set up LLM Guard output scanners**
- Integrate `from llm_guard.output_scanners import Sensitive, Secrets`
- Run both scanners on same `ai4privacy` samples as Presidio — this head-to-head is an evaluation result
- Libraries: `llm-guard`

**Action 3: Design and generate synthetic canary set**
- Generate 50–100 synthetic outputs containing: fake API keys (`sk-` + random 48-char string), fake AWS credentials (`AKIA` format), fake SSNs, fake connection strings
- Half should be clearly formatted, half embedded in natural language ("here is your key: sk-...")
- This is your ground-truth leakage detection test — 100% label certainty
- Libraries: `faker` (synthetic PII generation), `re` for pattern validation

**Action 4: Plan demo interface**
- Sketch the UI layout: input box → pipeline trace (layer by layer, green/red) → final output with redactions visible
- Decide on framework: Streamlit is fastest (2–3 days to build), Gradio is comparable
- Do not build yet — plan only this week, build in week 3
- Reference: Streamlit docs at `docs.streamlit.io`, Gradio at `gradio.app`

---

## Detailed Project Schedule

---

### Week 1, First Half (Days 1–3): Foundation ✓ COMPLETE

**Person A** ✓
- Finalize repo structure, Docker skeleton, shared `requirements.txt`
- Load all four datasets, clean and save as labeled parquet files
- Implement SecUtil metric function and threshold sweep function
- Deploy unprotected assistant (B0) and run all attack datasets through it
- *Deliverable: B0 results logged, datasets ready, metrics functions tested*

**Person B** ✓
- Implement heuristic pre-filter with pattern coverage across HackAPrompt taxonomy
- Install and wrap LLM Guard `PromptInjection` scanner with tunable threshold
- *Deliverable: both Input Scanner components functional as standalone modules*

**Person C** ✓
- Install and test Presidio on ai4privacy dataset, record entity-level recall
- Install and test LLM Guard `Sensitive`/`Secrets` scanners on same data
- Generate synthetic canary set (50–100 examples)
- *Deliverable: Output Guard components functional, canary set ready*

---

### Week 1, Second Half (Days 4–7): First Integration + Early Results ✓ COMPLETE

**Person A** ✓
- Integrate B0 results into harness, verify logging pipeline end-to-end
- Run heuristic-only evaluation against HackAPrompt and Deepset, log results
- Begin threshold sweep for heuristic-only — first tradeoff curve data
- *Deliverable: heuristic-only baseline (B1) numbers complete*

**Person B** ✓
- Run LLM Guard standalone against HackAPrompt and Deepset — this is external baseline B2
- Run combined heuristic + LLM Guard Input Scanner, log results
- *Deliverable: B2 (LLM Guard standalone) results complete, Input Scanner ablation started*

**Person C** ✓
- Implement canary injection logic on input side (planting the secret in system prompt)
- Implement canary detection logic on output side (checking if secret appears in response)
- *Deliverable: canary loop functional end-to-end, even if not yet integrated into full pipeline*

---

### Week 2, First Half (Days 8–10): Policy Engine + Pipeline Integration ✓ COMPLETE (A+B); ⚠ PENDING (C)

**Person A** ✓
- Begin integrating all components into unified FastAPI pipeline with toggle flags per layer
- Verify each layer can be independently enabled/disabled via config
- Run Input Scanner (full) evaluation with all results feeding into harness
- *Deliverable: pipeline accepts toggle config, Input Scanner results complete*

**Person B** ✓
- Implement Policy Engine RBAC — role definitions, decorator, allowlist per role
- Write 29 adversarial integration tests (Groups A–D); policy corpus reused for eval
- Run Policy Engine in isolation: 19/19 injection cases caught or model_refused, <1ms latency
- *Deliverable: Policy Engine functional, isolated evaluation complete*

**Person C** ⚠ PENDING
- ~~Integrate Presidio + LLM Guard output scanners + canary check into unified Output Guard module~~
- ~~Run Output Guard in isolation against synthetic canary set and ai4privacy data~~
- ~~Compare Presidio vs. LLM Guard recall head-to-head~~
- *Status: standalone scripts exist (presidio_scanner.py, llmguard_output_scanner.py, canary_set.py) but output_guard.py not yet written*

---

### Week 2, Second Half (Days 11–14): Tool Sandbox + Full Pipeline First Run ✓ COMPLETE (B); ⚠ PENDING (A+C)

**Person A** ⚠ PENDING — blocked on output_guard.py
- ~~Run full pipeline (all four layers) for the first time end-to-end~~
- ~~Run full ablation matrix: each layer in isolation, then all combinations~~
- ~~Begin compiling results table: B0, B1, B2, four isolated layers, full pipeline~~
- *Status: can run 3-layer configs now; full ablation blocked until Person C delivers output_guard.py*

**Person B** ✓
- Tool Sandbox command validator implemented: bash blocklist + file path allowlist
- 20-case adversarial corpus (Groups A/B/C) — attack taxonomy from Garak malwaregen/encoding probes
- Eval results: 14/14 attacks blocked, 0/6 false positives, p95=0.280ms
- *Note: Garak runs against LLM endpoints, not Python validators — manual corpus used instead*

**Person C** ⚠ PENDING
- Terminal-Bench integration: **skip** — use manual scenario set (faster, cleaner results)
- *Immediate next action: deliver output_guard.py + orchestrator wiring (see handoff_doc_0418.md)*

---

### Week 3, First Half (Days 15–17): Evaluation Completion + Tradeoff Curves

**Person A**
- Run complete threshold sweep across Input Scanner and Output Guard
- Generate SecUtil tradeoff curves for each layer configuration
- Finalize all quantitative results: TPR, FPR, F1, SecUtil per configuration
- Measure and log latency p50/p95 per layer using production-volume request runs
- *Deliverable: all quantitative results final, tradeoff curve plots ready*

**Person B**
- Write three to five case studies:
  - Canary loop catch (injection bypasses Input Scanner, caught by Output Guard)
  - Tool Sandbox block (unsafe bash command not flagged by any scanner)
  - False positive on legitimate query (document which layer triggered and why)
  - At minimum one HackAPrompt level-5 attack trace end-to-end
- *Deliverable: case study write-ups complete*

**Person C**
- Begin building Streamlit demo interface
- Core UI: text input → per-layer trace (green/red indicator per layer) → final output with redactions highlighted
- Wire to live pipeline via FastAPI calls
- *Deliverable: demo UI functional with real pipeline responses*
- Libraries: `streamlit`, `requests` (API calls to FastAPI backend)

---

### Week 3, Second Half (Days 18–21): Demo Polish + Report Draft

**Person A**
- Begin report: Abstract, Introduction, Related Work sections
- Related work must cover: LLM Guard, Rebuff (as prior art), Yi Liu et al. 2023, HackAPrompt paper (Schulhoff et al. 2023), Garak
- Compile figures: tradeoff curves, ablation table, latency bar chart
- *Deliverable: report Introduction + Related Work drafted*

**Person B**
- Write report Methodology section: system architecture, each component design decision, dataset curation, evaluation protocol
- Write error analysis: categorize false negatives by HackAPrompt attack type taxonomy
- *Deliverable: Methodology + Error Analysis drafted*

**Person C**
- Polish demo: add layer toggle controls so demo audience can enable/disable layers live
- Add latency display per request
- Deploy to Streamlit Cloud or HuggingFace Spaces
- *Deliverable: demo publicly accessible via URL*

---

### Week 4, First Half (Days 22–24): Report Completion

**All three together**
- Write Results and Analysis section collaboratively — one person per results axis (security coverage, SecUtil curves, latency)
- Write Limitations and Future Work: HackAPrompt recency gap, command-validator scope of Sandbox, multi-turn session memory as future work
- Write Conclusion

**Person A**
- Final pass on all figures and tables — consistent formatting, labeled axes, confidence intervals shown
- Finalize GitHub repo: clean README with one-command setup, requirements, dataset download instructions, how to reproduce each result

**Person B + C**
- Prepare presentation slides — structure follows Section 4 rubric exactly:
  - Problem Statement (slides 1–3)
  - Major Contributions (slides 4–6)
  - Evaluation results with figures (slides 7–10)
  - Case studies (slides 11–12)
  - Limitations and future work (slide 13)

---

### Week 4, Second Half (Days 25–28): Rehearsal + Submission

**All three together**
- Full presentation rehearsal — time each section, ensure demo runs live without errors
- Prepare for Q&A: anticipate "how is this different from LLM Guard," "what does SecUtil add," "why not a real sandbox"
- Final report proofreading pass — grammar, citation formatting, figure references
- Submit report, repo link, and demo URL

---

## Critical Path Summary

The items that block everything else if delayed:

```
Day 1–3:  Evaluation harness + dataset loading (Person A) — nothing can be evaluated without this
Day 4–7:  B0 + B2 baseline results — establishes your reference points early
Day 11–14: Full pipeline first run — if integration issues exist, find them here not in week 4
Day 15–17: Tradeoff curves + latency — these are the headline figures, need time to look right
Day 22–24: Report draft — do not leave this entirely to the last 3 days
```