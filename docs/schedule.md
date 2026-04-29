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

### Week 2, First Half (Days 8–10): Policy Engine + Pipeline Integration ✓ COMPLETE

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

**Person C** ✓
- Implemented `pipeline/output_guard.py` — Presidio + LLM Guard Sensitive + canary check, lazy loading, toggle passthrough
- Wired into `pipeline/orchestrator.py` — Layer 5 block, "redact" vs "block" decision, NameError-safe final_response handling
- Implemented `evaluation/eval_output_guard.py` — 3 sections: PII recall (ai4privacy), secrets recall (canary_set), 20 manual scenarios grounded in Greshake 2023 + Liu 2023
- Manual scenario run: TP=9, TN=9, FP=0, FN=2 (AWS/OpenAI key formats not covered by Presidio or LLM Guard)
- *Deliverable: Output Guard functional, wired, isolated eval complete*

---

### Week 2, Second Half (Days 11–14): Tool Sandbox + Full Pipeline First Run ✓ COMPLETE (B+C); ⚠ PENDING (A)

**Person A** ⚠ PENDING — output_guard.py now delivered, ablation unblocked
- ~~Run full pipeline (all four layers) for the first time end-to-end~~
- ~~Run full ablation matrix: each layer in isolation, then all combinations~~
- ~~Begin compiling results table: B0, B1, B2, four isolated layers, full pipeline~~
- *Status: all layers are wired and togglable — Person A can now run full ablation*

**Person B** ✓
- Tool Sandbox command validator implemented: bash blocklist + file path allowlist
- 20-case adversarial corpus (Groups A/B/C) — attack taxonomy from Garak malwaregen/encoding probes
- Eval results: 14/14 attacks blocked, 0/6 false positives, p95=0.280ms
- *Note: Garak runs against LLM endpoints, not Python validators — manual corpus used instead*

**Person C** ✓
- Terminal-Bench integration: **skipped** — manual scenario set used instead (cleaner, scoped)
- output_guard.py + orchestrator wiring delivered (was the immediate blocker)

---

### Week 3, First Half (Days 15–17): Evaluation Completion + Tradeoff Curves ← CURRENT WEEK

**Person A** ⚠ IN PROGRESS — ablation unblocked as of Apr 29
- Run complete threshold sweep across Input Scanner and Output Guard
- Generate SecUtil tradeoff curves for each layer configuration
- Finalize all quantitative results: TPR, FPR, F1, SecUtil per configuration
- Measure and log latency p50/p95 per layer using production-volume request runs
- *Deliverable: all quantitative results final, tradeoff curve plots ready*

**Person B** ⚠ IN PROGRESS
- Write three to five case studies:
  - Canary loop catch (injection bypasses Input Scanner, caught by Output Guard)
  - Tool Sandbox block (unsafe bash command not flagged by any scanner)
  - False positive on legitimate query (document which layer triggered and why)
  - At minimum one HackAPrompt level-5 attack trace end-to-end
- *Deliverable: case study write-ups complete*

**Person C** ⚠ IN PROGRESS — starting Streamlit demo
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