"""
evaluation/eval_combined.py — Combined B1+B2 input scanner metrics.

Loads pre-computed LLM Guard scores (logs/b2_scores.csv, produced by b2_llmguard.py)
and runs heuristic_scan live on the same rows. For each row, applies the same
two-stage logic as orchestrator.py Layer 1:

  1. Run heuristic_scan() — if triggered, block (LLM Guard score not consulted).
  2. If heuristic passes, check LLM Guard score >= threshold — if true, block.

The combined FPR is not simply max(FPR_b1, FPR_b2) — it is measured directly
because heuristic and LLM Guard are not perfectly correlated on legitimate inputs.
Stacking B1 on B2 can only increase or maintain FPR relative to B2 alone.

Usage:
    python -m evaluation.eval_combined
    python -m evaluation.eval_combined --threshold 0.92  # default

Requires:
    logs/b2_scores.csv  — run: python baselines/b2_llmguard.py (loads DeBERTa model)

Output:
    results/combined_scanner_results.json
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

from evaluation.metrics import compute_classification_metrics, compute_secutil
from pipeline.input_scanner import heuristic_scan

SCORES_PATH = Path(__file__).parent.parent / "logs" / "b2_scores.csv"
RESULTS_DIR = Path(__file__).parent.parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", type=float, default=0.92,
                        help="LLM Guard threshold for stage-2 decision (default 0.92)")
    args = parser.parse_args()

    if not SCORES_PATH.exists():
        print(f"MISSING: {SCORES_PATH}\nRun: python baselines/b2_llmguard.py")
        sys.exit(1)

    df = pd.read_csv(SCORES_PATH)
    print(f"Loaded {len(df)} rows from b2_scores.csv")
    print(f"  attacks={(df['label']==1).sum()}  legit={(df['label']==0).sum()}")

    y_true       = []
    y_pred_b1    = []   # heuristic only
    y_pred_b2    = []   # LLM Guard only (pre-computed score)
    y_pred_comb  = []   # two-stage sequential
    method_counts = {"heuristic": 0, "llmguard": 0, "pass": 0}

    for _, row in df.iterrows():
        text  = str(row["text"])
        label = int(row["label"])
        score = float(row["score"])

        # Stage 1: heuristic
        h_trig, _ = heuristic_scan(text)
        # Stage 2: LLM Guard (score already computed — no model call)
        lg_trig   = score >= args.threshold

        # Combined sequential decision
        if h_trig:
            comb_trig = True
            method_counts["heuristic"] += 1
        elif lg_trig:
            comb_trig = True
            method_counts["llmguard"] += 1
        else:
            comb_trig = False
            method_counts["pass"] += 1

        y_true.append(label)
        y_pred_b1.append(1 if h_trig   else 0)
        y_pred_b2.append(1 if lg_trig  else 0)
        y_pred_comb.append(1 if comb_trig else 0)

    def _m(y_pred: list[int]) -> dict:
        m  = compute_classification_metrics(np.array(y_true), np.array(y_pred))
        su = compute_secutil(m["f1"], m["fpr"])
        return {**m, "secutil": round(su, 4)}

    b1   = _m(y_pred_b1)
    b2   = _m(y_pred_b2)
    comb = _m(y_pred_comb)
    comb["method_counts"] = method_counts
    comb["lg_threshold"]  = args.threshold

    print(f"\n{'Variant':<28} {'TPR':>6} {'FPR':>6} {'F1':>6} {'SecUtil':>8}")
    print("─" * 56)
    for label, m in [
        ("B1  heuristic only",         b1),
        (f"B2  LLM Guard (t={args.threshold})", b2),
        ("B1+B2 combined (pipeline)",  comb),
    ]:
        print(f"{label:<28} {m['tpr']:>6.3f} {m['fpr']:>6.3f} {m['f1']:>6.3f} {m['secutil']:>8.4f}")

    total     = sum(method_counts.values())
    delta_fpr = comb["fpr"] - b2["fpr"]
    delta_su  = comb["secutil"] - b2["secutil"]
    print(f"\nCombined vs B2 standalone:  FPR delta={delta_fpr:+.3f}  SecUtil delta={delta_su:+.4f}")
    print(f"Blocked by: heuristic={method_counts['heuristic']} ({method_counts['heuristic']/total:.1%})  "
          f"llmguard={method_counts['llmguard']} ({method_counts['llmguard']/total:.1%})  "
          f"neither={method_counts['pass']} ({method_counts['pass']/total:.1%})")

    out = {"b1": b1, "b2": b2, "combined": comb}
    out_path = RESULTS_DIR / "combined_scanner_results.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2, default=str)
    print(f"\nResults saved → {out_path}")


if __name__ == "__main__":
    main()
