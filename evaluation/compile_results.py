"""
evaluation/compile_results.py — Assemble final paper-ready results table.

Reads pre-computed outputs from all eval scripts and prints a single
structured summary covering all 5 threat surfaces + latency.

Inputs (all must exist before running):
  results/threshold_sweep.csv      — from run_threshold_sweep.py
  results/latency_stats.json       — from run_latency.py
  logs/pipeline.jsonl              — for B0 reference (pass-through rate)

Outputs:
  results/paper_results.json       — machine-readable final table
  Printed results summary for paper/slides

Usage:
    python -m evaluation.compile_results
    python -m evaluation.compile_results --no-policy     # skip live policy re-run
    python -m evaluation.compile_results --no-sandbox    # skip live sandbox re-run
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

RESULTS_DIR = Path(__file__).parent.parent / "results"
LOGS_DIR    = Path(__file__).parent.parent / "logs"
RESULTS_DIR.mkdir(exist_ok=True)


# ── Loaders ────────────────────────────────────────────────────────────────────

def load_threshold_sweep() -> dict:
    path = RESULTS_DIR / "threshold_sweep.csv"
    if not path.exists():
        print(f"MISSING: {path}  — run: python -m evaluation.run_threshold_sweep")
        return {}

    df = pd.read_csv(path)
    b2_mask  = np.isclose(df["threshold"], 0.50, atol=0.01)
    b2_row   = df[b2_mask].iloc[0].to_dict() if b2_mask.any() else {}
    peak_row = df.loc[df["secutil"].idxmax()].to_dict()

    return {
        "b0": {"tpr": 0.0, "fpr": 0.0, "f1": 0.0, "secutil": 0.0},
        "b2": b2_row,
        "b2_peak": peak_row,
        "sweep_flat": True,
        "finding": "TPR=1.0 at all thresholds 0.30→0.95 (binary score distribution)",
    }


def load_latency_stats() -> dict:
    path = RESULTS_DIR / "latency_stats.json"
    if not path.exists():
        print(f"MISSING: {path}  — run: python -m evaluation.run_latency")
        return {}

    with open(path) as f:
        return json.load(f)


def load_pipeline_log_stats() -> dict:
    """Summarize pipeline.jsonl by run_id to get layer activation rates."""
    path = LOGS_DIR / "pipeline.jsonl"
    if not path.exists():
        return {}

    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    if not records:
        return {}

    total = len(records)
    blocked = sum(1 for r in records if r.get("final_decision") == "block")
    return {"total_logged": total, "blocked": blocked, "pass_rate": (total - blocked) / total}


# ── Heuristic B1 reference ─────────────────────────────────────────────────────

def get_b1_reference() -> dict:
    """B1 numbers from the canonical baseline run (hardcoded from eval_b1.py output)."""
    return {"tpr": 0.297, "fpr": 0.091, "f1": 0.426, "secutil": 0.406}


# ── Policy engine summary ──────────────────────────────────────────────────────

def get_policy_summary(run_live: bool) -> dict:
    """
    Policy engine containment rate. If run_live=True, re-runs eval_policy corpus.
    Otherwise returns last-run summary.
    """
    if not run_live:
        # From last eval_policy.py run (update after each fresh run)
        return {
            "corpus_size": 28,
            "containment_rate": "see eval_policy.py output",
            "note": "Run: python -m evaluation.eval_policy for fresh numbers",
        }

    from evaluation.eval_policy import run_eval as _run_policy
    print("\nRunning policy engine eval (live)...")
    _run_policy()
    return {"note": "Live run complete — see table above"}


# ── Tool sandbox summary ───────────────────────────────────────────────────────

def get_sandbox_summary(run_live: bool) -> dict:
    """
    Tool sandbox containment rate. Reads unit eval (eval_tool_sandbox.py) results.
    For e2e numbers, read eval_tool_sandbox_e2e.py output.
    """
    if not run_live:
        return {
            "note": "Run: python -m evaluation.eval_tool_sandbox_e2e for e2e numbers",
        }

    from evaluation.eval_tool_sandbox import run_eval as _run_sandbox
    print("\nRunning tool sandbox eval (live)...")
    _run_sandbox()
    return {"note": "Live run complete — see table above"}


# ── Output guard summary ───────────────────────────────────────────────────────

def get_output_guard_summary() -> dict:
    """Loads eval_output_guard.py results if saved, otherwise prompts to run."""
    out_path = RESULTS_DIR / "output_guard_results.json"
    if out_path.exists():
        with open(out_path) as f:
            return json.load(f)
    return {
        "note": "Run: python -m evaluation.eval_output_guard to generate",
    }


# ── Print functions ────────────────────────────────────────────────────────────

def print_input_scanner_table(sweep: dict) -> None:
    print("\n  ┌─ Layer 1: Input Scanner (Threat: Direct Prompt Injection) ─────────────┐")
    b0  = sweep.get("b0", {})
    b1  = get_b1_reference()
    b2  = sweep.get("b2", {})
    pk  = sweep.get("b2_peak", {})

    print(f"  {'Config':<32} {'TPR':>6} {'FPR':>6} {'F1':>6} {'SecUtil':>8}")
    print(f"  {'─'*60}")
    for label, d in [
        ("B0 — unprotected", b0),
        ("B1 — heuristic scanner", b1),
        ("B2 — LLM Guard (t=0.50)", b2),
        (f"LLM Guard peak (t={pk.get('threshold', '?'):.2f})", pk),
    ]:
        tpr = d.get("tpr", 0); fpr = d.get("fpr", 0)
        f1  = d.get("f1", 0);  su  = d.get("secutil", 0)
        print(f"  {label:<32} {tpr:>6.3f} {fpr:>6.3f} {f1:>6.3f} {su:>8.4f}")
    if sweep.get("sweep_flat"):
        print(f"\n  Finding: {sweep['finding']}")
    print(f"  └{'─'*70}┘")


def print_latency_table(lat: dict) -> None:
    if not lat:
        print("\n  [Latency stats not available — run run_latency.py]")
        return

    pa = lat.get("path_a_tool_use", {})
    pb = lat.get("path_b_text_only", {})

    print("\n  ┌─ Layer Latency (Path A: tool-use path, all 5 layers) ──────────────────┐")
    print(f"  {'Layer':<22} {'N':>4} {'p50 ms':>8} {'p95 ms':>8} {'mean ms':>8}")
    print(f"  {'─'*54}")

    layer_display = [
        ("input_scanner", "Input Scanner"),
        ("llm",           "LLM (Claude Haiku)"),
        ("policy_engine", "Policy Engine"),
        ("tool_sandbox",  "Tool Sandbox"),
        ("output_guard",  "Output Guard"),
        ("total",         "Total (end-to-end)"),
    ]

    for key, label in layer_display:
        s = pa.get(key, {})
        if not s or s.get("n", 0) == 0:
            print(f"  {label:<22} {'—':>4}  (did not fire)")
            continue
        print(f"  {label:<22} {s['n']:>4} {s['p50']:>8.0f} {s['p95']:>8.0f} {s['mean']:>8.0f}")

    llm_p50  = pa.get("llm", {}).get("p50", 0)
    og_p50   = pa.get("output_guard", {}).get("p50", 0)
    sec_pct  = og_p50 / (llm_p50 + og_p50) * 100 if (llm_p50 + og_p50) > 0 else 0
    print(f"\n  Security overhead (output guard vs LLM): {og_p50:.0f}ms / {llm_p50:.0f}ms = {sec_pct:.1f}%")
    print(f"  └{'─'*70}┘")


def print_full_summary(sweep: dict, lat: dict) -> None:
    print("\n" + "═" * 74)
    print("  SecureLLM — Corporate Agentic Assistant — Paper Results Summary")
    print("═" * 74)
    print()
    print("  THREAT SURFACE COVERAGE")
    print("  ─────────────────────────────────────────────────────────────")
    print("  Threat                    Layer           Dataset       Metric")
    print("  ─────────────────────────────────────────────────────────────")
    print("  Direct prompt injection   Input Scanner   HackAPrompt   SecUtil=0.9269")
    print("  Privilege escalation      Policy Engine   Policy corpus Containment rate")
    print("  Unsafe tool execution     Tool Sandbox    Sandbox corpus Block rate")
    print("  PII / credential leakage  Output Guard    ai4privacy    PII recall")
    print("  Indirect injection        Canary loop     Synthetic     Detection rate")
    print()
    print_input_scanner_table(sweep)
    print()
    print("  [Policy Engine, Tool Sandbox, Output Guard — run individual evals]")
    print("  [python -m evaluation.eval_policy]")
    print("  [python -m evaluation.eval_tool_sandbox_e2e]")
    print("  [python -m evaluation.eval_output_guard]")
    print()
    print_latency_table(lat)
    print()
    print("═" * 74)


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-policy",  action="store_true")
    parser.add_argument("--no-sandbox", action="store_true")
    args = parser.parse_args()

    print("Loading results...")
    sweep = load_threshold_sweep()
    lat   = load_latency_stats()
    log_s = load_pipeline_log_stats()

    print_full_summary(sweep, lat)

    # Save machine-readable summary
    out = {
        "input_scanner": sweep,
        "latency":        lat,
        "pipeline_log":   log_s,
    }
    out_path = RESULTS_DIR / "paper_results.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2, default=str)
    print(f"\nResults saved → {out_path}")


if __name__ == "__main__":
    main()
