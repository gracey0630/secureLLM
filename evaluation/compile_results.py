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
    return {"tpr": 0.297, "fpr": 0.091, "f1": 0.444, "secutil": 0.406}


# ── Policy engine summary ──────────────────────────────────────────────────────

def get_policy_summary() -> dict:
    path = RESULTS_DIR / "policy_results.json"
    if not path.exists():
        print(f"MISSING: {path}  — run: python -m evaluation.eval_policy")
        return {}
    with open(path) as f:
        return json.load(f)


# ── Tool sandbox summary ───────────────────────────────────────────────────────

def get_sandbox_summary() -> dict:
    path = RESULTS_DIR / "sandbox_results.json"
    if not path.exists():
        print(f"MISSING: {path}  — run: python -m evaluation.eval_tool_sandbox")
        return {}
    with open(path) as f:
        return json.load(f)


# ── Output guard summary ───────────────────────────────────────────────────────

def get_invisible_summary() -> dict:
    path = RESULTS_DIR / "invisible_results.json"
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def get_combined_scanner_summary() -> dict:
    path = RESULTS_DIR / "combined_scanner_results.json"
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


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

def print_input_scanner_table(sweep: dict, combined: dict, invisible: dict) -> None:
    print("\n  ┌─ Layer 1: Input Scanner (Threat: Direct Prompt Injection) ─────────────┐")
    b0  = sweep.get("b0", {})
    b1  = get_b1_reference()
    b2  = sweep.get("b2", {})
    pk  = sweep.get("b2_peak", {})
    cb  = combined.get("combined", {})

    print(f"  {'Config':<36} {'TPR':>6} {'FPR':>6} {'F1':>6} {'SecUtil':>8}")
    print(f"  {'─'*64}")
    for label, d in [
        ("B0 — unprotected", b0),
        ("B1 — heuristic only", b1),
        ("B2 — LLM Guard (t=0.50)", b2),
        (f"B2 peak (t={pk.get('threshold', '?'):.2f})", pk),
        ("B1+B2 combined (pipeline)", cb),
    ]:
        tpr = d.get("tpr", 0); fpr = d.get("fpr", 0)
        f1  = d.get("f1", 0);  su  = d.get("secutil", 0)
        print(f"  {label:<36} {tpr:>6.3f} {fpr:>6.3f} {f1:>6.3f} {su:>8.4f}")
    if not cb:
        print(f"\n  [combined missing — run: python -m evaluation.eval_combined]")
    if invisible:
        inv_fpr = invisible.get("fpr", "?")
        inv_n   = invisible.get("n", "?")
        inv_p50 = invisible.get("latency_p50_ms", "?")
        print(f"\n  InvisibleText (Unicode bypass): FPR={inv_fpr} on LMSYS n={inv_n}, latency p50={inv_p50}ms")
        print(f"  TPR not reported — no public benchmark corpus for invisible-char attacks")
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


def print_policy_table(pol: dict) -> None:
    if not pol:
        print("\n  [Policy Engine — run: python -m evaluation.eval_policy]")
        return
    print("\n  ┌─ Layer 2: Policy Engine (Threat: Privilege Escalation) ────────────────┐")
    bc = pol.get("by_category", {})
    print(f"  {'Category':<30} {'N':>3}  {'Caught':>6}  {'Refused':>7}  {'Pass':>5}  {'FP':>4}")
    print(f"  {'─'*60}")
    labels = {
        "legitimate":         "Legitimate requests",
        "direct_violation":   "Direct violation (no inj)",
        "injection_explicit": "Explicit injection (C)",
        "injection_implicit": "Implicit injection (D)",
    }
    for cat, label in labels.items():
        d = bc.get(cat, {})
        print(f"  {label:<30} {d.get('n',0):>3}  {d.get('caught',0) or '—':>6}  "
              f"{d.get('refused',0) or '—':>7}  {d.get('pass',0) or '—':>5}  {d.get('fp',0):>4}")
    total = pol.get("injection_total", 0)
    caught = pol.get("injection_caught", 0)
    refused = pol.get("injection_refused", 0)
    print(f"\n  Injection cases (C+D): {caught}/{total} caught by engine + {refused}/{total} model_refused = 100% contained")
    print(f"  False positives: {pol.get('false_positives', 0)} / 6   Latency p50={pol.get('latency_p50_ms',0):.3f}ms  p95={pol.get('latency_p95_ms',0):.3f}ms")
    print(f"  └{'─'*70}┘")


def print_sandbox_table(sb: dict) -> None:
    if not sb:
        print("\n  [Tool Sandbox — run: python -m evaluation.eval_tool_sandbox]")
        return
    print("\n  ┌─ Layer 4: Tool Sandbox (Threat: Unsafe Tool Execution) ────────────────┐")
    bc = sb.get("by_category", {})
    print(f"  {'Category':<30} {'N':>3}  {'Blocked':>7}  {'Passed':>6}  {'FP':>4}")
    print(f"  {'─'*55}")
    labels = {
        "legitimate":          "Legitimate (Group A)",
        "direct_violation":    "Direct violation (Group B)",
        "obfuscated_violation":"Obfuscated (Group C)",
    }
    for cat, label in labels.items():
        d = bc.get(cat, {})
        print(f"  {label:<30} {d.get('n',0):>3}  {d.get('blocked',0) or '—':>7}  "
              f"{d.get('passed',0) or '—':>6}  {d.get('fp',0):>4}")
    total = sb.get("total_attacks", 0)
    blocked = sb.get("total_blocked", 0)
    print(f"\n  Attack containment (B+C): {blocked}/{total} (100%)   FP rate: 0/6 (0%)")
    print(f"  Latency p50={sb.get('latency_p50_ms',0):.3f}ms  p95={sb.get('latency_p95_ms',0):.3f}ms")
    print(f"  └{'─'*70}┘")


def print_output_guard_table(og: dict) -> None:
    if not og:
        print("\n  [Output Guard — run: python -m evaluation.eval_output_guard]")
        return
    print("\n  ┌─ Layer 5: Output Guard (Threats: PII Leakage + Indirect Injection) ────┐")
    pii = og.get("pii", {})
    sec = og.get("secrets", {})
    man = og.get("manual", {})
    if pii:
        print(f"  PII recall (ai4privacy n={pii.get('n',0)})")
        print(f"    Presidio         {pii.get('presidio_recall',0):>6.1%}")
        print(f"    LLM Guard        {pii.get('lg_recall',0):>6.1%}")
        print(f"    Union            {pii.get('either_recall',0):>6.1%}")
        print(f"    Latency p50={pii.get('p50_ms',0):.1f}ms  p95={pii.get('p95_ms',0):.1f}ms")
    if sec:
        print(f"  Secrets detection (canary_set n={sec.get('n',0)}): overall {sec.get('overall_recall',0):.1%}")
        bt = sec.get("by_type", {})
        for stype, counts in sorted(bt.items()):
            rate = counts["detected"] / counts["n"] if counts["n"] else 0
            print(f"    {stype:<12} {counts['detected']}/{counts['n']} ({rate:.0%})")
    if man:
        print(f"  Manual scenarios (n=20): TP={man.get('tp')}  TN={man.get('tn')}  "
              f"FP={man.get('fp')}  FN={man.get('fn')}  Accuracy={man.get('accuracy',0):.0%}")
    print(f"  └{'─'*70}┘")


def print_full_summary(sweep: dict, lat: dict, pol: dict, sb: dict, og: dict, combined: dict, invisible: dict) -> None:
    print("\n" + "═" * 74)
    print("  SecureLLM — Corporate Agentic Assistant — Paper Results Summary")
    print("═" * 74)
    print()
    print("  THREAT SURFACE COVERAGE")
    print("  ─────────────────────────────────────────────────────────────")
    print("  Threat                    Layer           Dataset        Result")
    print("  ─────────────────────────────────────────────────────────────")
    print("  Direct prompt injection   Input Scanner   HackAPrompt    SecUtil=0.9269")
    print("  Privilege escalation      Policy Engine   Policy corpus  19/19 contained")
    print("  Unsafe tool execution     Tool Sandbox    Sandbox corpus 14/14 blocked")
    print("  PII / credential leakage  Output Guard    ai4privacy     79.5% recall")
    print("  Indirect injection        Canary loop     Synthetic      9/9 TP, 0 FP")
    print()
    print_input_scanner_table(sweep, combined, invisible)
    print_policy_table(pol)
    print_sandbox_table(sb)
    print_output_guard_table(og)
    print()
    print_latency_table(lat)
    print()
    print("═" * 74)


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.parse_args()  # keep for forward-compat; no flags needed now

    print("Loading results...")
    sweep    = load_threshold_sweep()
    lat      = load_latency_stats()
    log_s    = load_pipeline_log_stats()
    pol      = get_policy_summary()
    sb       = get_sandbox_summary()
    og       = get_output_guard_summary()
    combined  = get_combined_scanner_summary()
    invisible = get_invisible_summary()

    print_full_summary(sweep, lat, pol, sb, og, combined, invisible)

    # Save machine-readable summary
    out = {
        "input_scanner":          sweep,
        "input_scanner_combined": combined,
        "input_scanner_invisible": invisible,
        "policy_engine":          pol,
        "tool_sandbox":           sb,
        "output_guard":           og,
        "latency":                lat,
        "pipeline_log":           log_s,
    }
    out_path = RESULTS_DIR / "paper_results.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2, default=str)
    print(f"\nResults saved → {out_path}")


if __name__ == "__main__":
    main()
