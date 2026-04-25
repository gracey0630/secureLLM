"""
evaluation/eval_tool_sandbox.py — Tool sandbox containment rate measurement.

Calls check_sandbox() directly for each corpus case — no Claude API calls,
no HTTP overhead. Runs in under 1 second.

Output:
  - Containment rate table by group (A/B/C)
  - Latency stats (should be <1ms — pure regex matching)

Usage:
  python -m evaluation.eval_tool_sandbox
"""

import sys
import time
from pathlib import Path
from statistics import median, quantiles

sys.path.insert(0, str(Path(__file__).parent.parent))

from pipeline.tool_sandbox import check_sandbox
from evaluation.sandbox_corpus import CORPUS, GROUND_TRUTH

CONFIG = {"tool_sandbox": True}

CATEGORY_LABELS = {
    "legitimate":           "Legitimate (Group A)      ",
    "direct_violation":     "Direct violation (Group B)",
    "obfuscated_violation": "Obfuscated (Group C)      ",
}


def classify(triggered: bool, category: str) -> str:
    expected_block = GROUND_TRUTH[category] == "block"
    if expected_block:
        return "blocked" if triggered else "missed"
    else:
        return "passed" if not triggered else "false_block"


def run_eval() -> None:
    results = []
    latencies = []

    print("Running sandbox corpus (no API calls)...")
    print(f"  {len(CORPUS)} cases\n")

    for case in CORPUS:
        label     = case["label"]
        category  = case["category"]
        tool_name = case["tool_name"]
        tool_args = case["tool_args"]

        t0 = time.perf_counter()
        triggered, result = check_sandbox(tool_name, tool_args, CONFIG)
        latency_ms = (time.perf_counter() - t0) * 1000

        latencies.append(latency_ms)
        outcome = classify(triggered, category)
        results.append({**case, "outcome": outcome, "result": result})

        status = "BLOCK" if triggered else "pass "
        print(f"  [{label}] {tool_name:<12} {status}  ({outcome})  — {case['note']}")

    _print_table(results, latencies)


def _print_table(results: list, latencies: list) -> None:
    categories = ["legitimate", "direct_violation", "obfuscated_violation"]

    print("\n" + "═" * 65)
    print("  Tool Sandbox — Containment Rate Table")
    print("═" * 65)
    print(f"  {'Category':<28} {'N':>3}  {'Blocked':>7}  {'Passed':>6}  {'Missed':>6}  {'FP':>4}")
    print("  " + "─" * 61)

    for cat in categories:
        rows    = [r for r in results if r["category"] == cat]
        n       = len(rows)
        blocked = sum(1 for r in rows if r["outcome"] == "blocked")
        passed  = sum(1 for r in rows if r["outcome"] == "passed")
        missed  = sum(1 for r in rows if r["outcome"] == "missed")
        fp      = sum(1 for r in rows if r["outcome"] == "false_block")
        label   = CATEGORY_LABELS[cat]
        print(f"  {label} {n:>3}  {blocked:>7}  {passed:>6}  {missed:>6}  {fp:>4}")

    print("  " + "─" * 61)

    # Summary rates
    attack_rows = [r for r in results if r["category"] != "legitimate"]
    if attack_rows:
        total_attacks = len(attack_rows)
        total_blocked = sum(1 for r in attack_rows if r["outcome"] == "blocked")
        total_missed  = sum(1 for r in attack_rows if r["outcome"] == "missed")
        print(f"\n  Attack containment (B + C): {total_blocked} / {total_attacks}  ({total_blocked/total_attacks:.0%})")
        if total_missed:
            print(f"  Missed (expected finding): {total_missed} cases — document in limitations")

    legit_rows = [r for r in results if r["category"] == "legitimate"]
    if legit_rows:
        fp_count = sum(1 for r in legit_rows if r["outcome"] == "false_block")
        print(f"  False positive rate: {fp_count} / {len(legit_rows)}  ({fp_count/len(legit_rows):.0%})")

    # Latency
    if latencies:
        p50 = median(latencies)
        p95 = quantiles(latencies, n=20)[18] if len(latencies) >= 20 else max(latencies)
        print(f"\n  Sandbox decision latency (regex matching — sub-millisecond)")
        print(f"    p50 : {p50:.3f}ms")
        print(f"    p95 : {p95:.3f}ms")

    print("\n" + "═" * 65)


if __name__ == "__main__":
    run_eval()
