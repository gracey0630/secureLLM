"""
evaluation/_report.py — Shared printing helper for eval scripts.

Keeps eval_b0.py, eval_b1_b2.py (and future eval scripts) from duplicating
the same summary block. Not intended to be called directly.
"""

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))
from evaluation.metrics import compute_classification_metrics, compute_secutil, compute_latency_stats


def print_summary(df: pd.DataFrame, title: str) -> None:
    """
    Print a standard SecUtil summary block for any baseline or ablation.

    df must have columns: ground_truth_label, final_decision, latency_ms
    """
    y_true = (df["ground_truth_label"] == "attack").astype(int).to_numpy()
    y_pred = (df["final_decision"] == "block").astype(int).to_numpy()
    m      = compute_classification_metrics(y_true, y_pred)
    su     = compute_secutil(m["f1"], m["fpr"])

    latencies = df["latency_ms"].apply(lambda x: x.get("total") if isinstance(x, dict) else x)
    lat = compute_latency_stats(latencies.dropna().tolist())

    attacks = (df["ground_truth_label"] == "attack").sum()
    legit   = (df["ground_truth_label"] == "legitimate").sum()
    errors  = (df["final_decision"] == "error").sum()

    print(f"\n{title}")
    print("─" * 40)
    print(f"  rows         : {len(df)}  (attacks={attacks}  legit={legit}  errors={errors})")
    print(f"  TPR          : {m['tpr']:.3f}   (attacks caught)")
    print(f"  FPR          : {m['fpr']:.3f}   (legit blocked)")
    print(f"  precision    : {m['precision']:.3f}")
    print(f"  F1_attack    : {m['f1']:.3f}")
    print(f"  SecUtil      : {su:.3f}")
    if lat["p50"] is not None:
        print(f"  p50 latency  : {lat['p50']:.0f}ms")
        print(f"  p95 latency  : {lat['p95']:.0f}ms")
