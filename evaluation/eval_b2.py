"""
evaluation/eval_b2.py — Print SecUtil metrics for B2 (LLM Guard standalone).

Prints point estimate at threshold=0.5, then runs threshold sweep (0.3→0.9)
from pre-computed scores in logs/b2_scores.csv (produced by b2_llmguard.py).

Usage:
    python evaluation/eval_b2.py
    python evaluation/eval_b2.py --log logs/pipeline.jsonl
"""

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))
from evaluation._report import print_summary
from evaluation.metrics import threshold_sweep

LOG_PATH    = Path(__file__).parent.parent / "logs" / "pipeline.jsonl"
SCORES_PATH = Path(__file__).parent.parent / "logs" / "b2_scores.csv"


def load_b2_rows(log_path: Path) -> pd.DataFrame:
    df = pd.read_json(log_path, lines=True)

    def get_method(row):
        try:
            return row["layer_results"]["input_scanner"]["method"]
        except (TypeError, KeyError):
            return None

    df["method"] = df.apply(get_method, axis=1)
    b2 = df[df["method"] == "llm_guard"].copy()

    if len(b2) == 0:
        print("No B2 rows found — run: python baselines/b2_llmguard.py")
        sys.exit(1)
    return b2


def print_sweep(scores_path: Path) -> None:
    if not scores_path.exists():
        print(f"\n[sweep skipped] {scores_path} not found — run b2_llmguard.py first")
        return

    scores_df  = pd.read_csv(scores_path)
    score_map  = dict(zip(scores_df["text"].tolist(), scores_df["score"].tolist()))
    texts      = scores_df["text"].tolist()
    labels     = scores_df["label"].tolist()
    thresholds = np.linspace(0.3, 0.9, 13)

    sweep_df   = threshold_sweep(lambda t: score_map.get(t, 0.0), texts, labels, thresholds)
    sweep_path = scores_path.parent / "b2_sweep.csv"
    sweep_df.to_csv(sweep_path, index=False)

    best = sweep_df.loc[sweep_df["secutil"].idxmax()]

    print(f"\nB2 — Threshold sweep (saved to {sweep_path})")
    print("─" * 55)
    print(sweep_df[["threshold", "tpr", "fpr", "f1", "secutil"]].to_string(index=False))
    print(f"\n  Peak SecUtil: {best['secutil']:.3f} at threshold={best['threshold']:.2f}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=Path, default=LOG_PATH)
    args = parser.parse_args()

    if not args.log.exists():
        print(f"Log not found: {args.log}")
        sys.exit(1)

    print_summary(load_b2_rows(args.log), "B2 — LLM Guard (threshold=0.5)")
    print_sweep(SCORES_PATH)


if __name__ == "__main__":
    main()
