"""
baselines/b1_heuristic.py — B1: Heuristic-only input scanner (cheap-defense lower bound).

Runs heuristic_scan() over the full corpus and logs to pipeline.jsonl.
No LLM calls, no model loading — completes in seconds.

After running, evaluate with: python evaluation/eval_b1_b2.py

Usage:
    python baselines/b1_heuristic.py
    python baselines/b1_heuristic.py --limit 50  # smoke test
"""

import argparse
import sys
import uuid
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))
from logging_schema import Timer, log_request
from pipeline.input_scanner import heuristic_scan

DATA_DIR = Path(__file__).parent.parent / "data"
LOG_DIR  = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

_LAYERS = {"input_scanner": True, "policy_engine": False, "tool_sandbox": False, "output_guard": False}


def load_corpus() -> pd.DataFrame:
    attacks = pd.read_parquet(DATA_DIR / "hackaprompt.parquet")
    lmsys   = pd.read_parquet(DATA_DIR / "lmsys.parquet")
    if len(lmsys) == 0:
        print("WARNING: lmsys empty — falling back to deepset legitimate rows")
        deepset = pd.read_parquet(DATA_DIR / "deepset.parquet")
        lmsys   = deepset[deepset["label"] == 0].copy()
    corpus = pd.concat([attacks, lmsys], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"Corpus: {len(corpus)} rows  (attacks={(corpus['label']==1).sum()}  legit={(corpus['label']==0).sum()})")
    return corpus


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None, help="Cap corpus size (smoke test)")
    args = parser.parse_args()

    corpus = load_corpus()
    if args.limit:
        corpus = corpus.head(args.limit)
        print(f"--limit {args.limit}: running on {len(corpus)} rows")

    run_id = str(uuid.uuid4())[:8]

    for i, row in corpus.iterrows():
        text  = str(row["text"])
        label = "attack" if row["label"] == 1 else "legitimate"

        with Timer() as t:
            triggered, match_reason = heuristic_scan(text)

        log_request(
            input_text=text,
            layers_enabled=_LAYERS,
            layer_results={
                "input_scanner": {"triggered": triggered, "score": None, "method": "heuristic", "match_reason": match_reason},
                "policy_engine": None,
                "tool_sandbox":  None,
                "output_guard":  None,
            },
            final_decision="block" if triggered else "pass",
            latency_ms={"input_scanner": t.ms, "total": t.ms},
            dataset_source=row["source"],
            ground_truth_label=label,
            request_id=f"b1-{run_id}-{i}",
        )

        if i % 500 == 0:
            print(f"  [{i}/{len(corpus)}]")

    print(f"\nDone. {len(corpus)} rows logged to logs/pipeline.jsonl")
    print("Run: python evaluation/eval_b1_b2.py")


if __name__ == "__main__":
    main()
