"""
baselines/b2_llmguard.py — B2: LLM Guard standalone (best external single-tool reference).

Runs llmguard_scan() over the full corpus at threshold=0.5 and logs to pipeline.jsonl.
Also saves raw scores to logs/b2_scores.csv so eval_b1_b2.py can run the threshold
sweep (0.3→0.9) without re-running inference.

Model loads on first call — expect ~30s startup, then ~1-2s per row on Apple Silicon.
Full corpus (~2314 rows) takes roughly 45-60 minutes.

After running, evaluate with: python evaluation/eval_b1_b2.py

Usage:
    python baselines/b2_llmguard.py
    python baselines/b2_llmguard.py --limit 20  # smoke test (loads model once)
"""

import argparse
import sys
import uuid
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))
from logging_schema import Timer, log_request
from pipeline.input_scanner import llmguard_scan

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

    print("Loading LLM Guard model (first call may take ~30s)...")
    run_id       = str(uuid.uuid4())[:8]
    score_records = []

    for i, row in corpus.iterrows():
        text  = str(row["text"])
        label = "attack" if row["label"] == 1 else "legitimate"

        with Timer() as t:
            triggered, score, _ = llmguard_scan(text, threshold=0.5)

        log_request(
            input_text=text,
            layers_enabled=_LAYERS,
            layer_results={
                "input_scanner": {"triggered": triggered, "score": score, "method": "llm_guard", "match_reason": None},
                "policy_engine": None,
                "tool_sandbox":  None,
                "output_guard":  None,
            },
            final_decision="block" if triggered else "pass",
            latency_ms={"input_scanner": t.ms, "total": t.ms},
            dataset_source=row["source"],
            ground_truth_label=label,
            request_id=f"b2-{run_id}-{i}",
        )

        score_records.append({"text": text, "score": score, "label": row["label"]})

        if i % 200 == 0:
            print(f"  [{i}/{len(corpus)}]  score={score:.3f}  latency={t.ms:.0f}ms")

    scores_path = LOG_DIR / "b2_scores.csv"
    pd.DataFrame(score_records).to_csv(scores_path, index=False)

    print(f"\nDone. {len(corpus)} rows logged to logs/pipeline.jsonl")
    print(f"Raw scores saved to {scores_path}")
    print("Run: python evaluation/eval_b1_b2.py")


if __name__ == "__main__":
    main()
