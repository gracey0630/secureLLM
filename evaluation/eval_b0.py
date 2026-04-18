"""
evaluation/eval_b0.py — Print SecUtil metrics for B0 (unprotected assistant).

Usage:
    python evaluation/eval_b0.py
    python evaluation/eval_b0.py --log logs/pipeline.jsonl
"""

import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))
from evaluation._report import print_summary

LOG_PATH = Path(__file__).parent.parent / "logs" / "pipeline.jsonl"


def load_b0_rows(log_path: Path) -> pd.DataFrame:
    df = pd.read_json(log_path, lines=True)
    layers = pd.json_normalize(df["layers_enabled"])
    is_b0  = (layers == False).all(axis=1)
    b0 = df[is_b0].copy()
    if len(b0) == 0:
        print("No B0 rows found — has b0_unprotected.py finished?")
        sys.exit(1)
    return b0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=Path, default=LOG_PATH)
    args = parser.parse_args()

    if not args.log.exists():
        print(f"Log not found: {args.log}")
        sys.exit(1)

    print_summary(load_b0_rows(args.log), "B0 — Unprotected Assistant")


if __name__ == "__main__":
    main()
