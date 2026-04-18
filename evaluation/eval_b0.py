"""
evaluation/eval_b0.py — Compute and print SecUtil metrics for B0 (unprotected assistant).

Reads logs/pipeline.jsonl, isolates B0 rows (all layers disabled), and runs the
full logging → metrics pipeline to confirm the harness works end-to-end.

Usage:
    python evaluation/eval_b0.py
    python evaluation/eval_b0.py --log logs/pipeline.jsonl  # explicit path
"""

import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))
from evaluation.metrics import (
    compute_classification_metrics,
    compute_secutil,
    compute_latency_stats,
)

LOG_PATH = Path(__file__).parent.parent / "logs" / "pipeline.jsonl"


def load_b0_rows(log_path: Path) -> pd.DataFrame:
    """
    Load pipeline.jsonl and return only B0 rows.
    B0 rows are identified by all layers_enabled values being False —
    this keeps eval correct even when B1/B2 logs land in the same file.
    """
    df = pd.read_json(log_path, lines=True)

    # Expand layers_enabled dict column into individual boolean columns
    layers = pd.json_normalize(df["layers_enabled"])
    is_b0 = (layers == False).all(axis=1)

    b0 = df[is_b0].copy()
    if len(b0) == 0:
        print("No B0 rows found in pipeline.jsonl — has b0_unprotected.py finished?")
        sys.exit(1)
    return b0


def print_summary(df: pd.DataFrame) -> None:
    attacks = df[df["ground_truth_label"] == "attack"]
    legit   = df[df["ground_truth_label"] == "legitimate"]

    # y_true: 1=attack, 0=legitimate
    # y_pred: 1=block, 0=pass — B0 always passes so y_pred is always 0
    y_true = (df["ground_truth_label"] == "attack").astype(int).to_numpy()
    y_pred = (df["final_decision"] == "block").astype(int).to_numpy()

    m       = compute_classification_metrics(y_true, y_pred)
    secutil = compute_secutil(m["f1"], m["fpr"])

    latencies = df["latency_ms"].apply(lambda x: x.get("total") if isinstance(x, dict) else x)
    lat = compute_latency_stats(latencies.dropna().tolist())

    print()
    print("B0 — Unprotected Assistant")
    print("─" * 36)
    print(f"  rows         : {len(df)}  (attacks={len(attacks)}  legit={len(legit)})")
    print(f"  errors       : {(df['final_decision'] == 'error').sum()}")
    print()
    print(f"  TPR          : {m['tpr']:.3f}   (attacks caught)")
    print(f"  FPR          : {m['fpr']:.3f}   (legit blocked)")
    print(f"  precision    : {m['precision']:.3f}")
    print(f"  F1_attack    : {m['f1']:.3f}")
    print(f"  SecUtil      : {secutil:.3f}")
    print()
    print(f"  p50 latency  : {lat['p50']:.0f}ms")
    print(f"  p95 latency  : {lat['p95']:.0f}ms")
    print(f"  mean latency : {lat['mean']:.0f}ms")
    print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=Path, default=LOG_PATH,
                        help="Path to pipeline.jsonl")
    args = parser.parse_args()

    if not args.log.exists():
        print(f"Log file not found: {args.log}")
        sys.exit(1)

    df = load_b0_rows(args.log)
    print_summary(df)


if __name__ == "__main__":
    main()
