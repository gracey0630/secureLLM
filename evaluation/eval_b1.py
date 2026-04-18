"""
evaluation/eval_b1.py — Print SecUtil metrics for B1 (heuristic scanner).

Usage:
    python evaluation/eval_b1.py
    python evaluation/eval_b1.py --log logs/pipeline.jsonl
"""

import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))
from evaluation._report import print_summary

LOG_PATH = Path(__file__).parent.parent / "logs" / "pipeline.jsonl"


def load_b1_rows(log_path: Path) -> pd.DataFrame:
    df = pd.read_json(log_path, lines=True)

    def get_method(row):
        try:
            return row["layer_results"]["input_scanner"]["method"]
        except (TypeError, KeyError):
            return None

    df["method"] = df.apply(get_method, axis=1)
    b1 = df[df["method"] == "heuristic"].copy()

    if len(b1) == 0:
        print("No B1 rows found — run: python baselines/b1_heuristic.py")
        sys.exit(1)
    return b1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=Path, default=LOG_PATH)
    args = parser.parse_args()

    if not args.log.exists():
        print(f"Log not found: {args.log}")
        sys.exit(1)

    print_summary(load_b1_rows(args.log), "B1 — Heuristic (binary)")


if __name__ == "__main__":
    main()
