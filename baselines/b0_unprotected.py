"""
baselines/b0_unprotected.py — B0: Unprotected assistant (vulnerability floor).

Loops over the attack corpus (hackaprompt) and legitimate queries (deepset label=0
or lmsys if available), sends each to Claude Haiku with zero protection, and logs
every request via log_request() with all layers disabled.

Expected result: SecUtil = 0 — the pipeline detects nothing because there is no
pipeline. This is the floor that B1, B2, and ablations are measured against.

Usage:
    python baselines/b0_unprotected.py
    python baselines/b0_unprotected.py --dry-run   # prints first 5 rows, no API calls
    python baselines/b0_unprotected.py --limit 50  # run on first N rows (smoke test)
"""

import argparse
import os
import sys
import time
import uuid
from pathlib import Path

import anthropic
import pandas as pd
from dotenv import load_dotenv

# Allow imports from repo root
sys.path.insert(0, str(Path(__file__).parent.parent))
from logging_schema import Timer, log_request

load_dotenv()

MODEL      = "claude-haiku-4-5-20251001"  # cheapest Claude; B0 doesn't need quality
DATA_DIR   = Path(__file__).parent.parent / "data"

# All layers are off for B0 — this dict is reused for every log_request call
LAYERS_OFF = {
    "input_scanner": False,
    "policy_engine": False,
    "tool_sandbox":  False,
    "output_guard":  False,
}
RESULTS_OFF = {
    "input_scanner": None,
    "policy_engine": None,
    "tool_sandbox":  None,
    "output_guard":  None,
}


def load_eval_corpus() -> pd.DataFrame:
    """
    Build the eval corpus for B0:
      - hackaprompt  (all rows, label=1, attack)
      - lmsys        (label=0, legitimate) if non-empty, else deepset label=0 rows

    Deepset is the fallback for legitimate queries because lmsys requires gated
    HF access. Once lmsys is loaded, it takes precedence as the larger, cleaner set.
    """
    attacks = pd.read_parquet(DATA_DIR / "hackaprompt.parquet")

    lmsys = pd.read_parquet(DATA_DIR / "lmsys.parquet")
    if len(lmsys) > 0:
        legit = lmsys
        print(f"Using lmsys for legitimate queries ({len(legit)} rows)")
    else:
        deepset = pd.read_parquet(DATA_DIR / "deepset.parquet")
        legit = deepset[deepset["label"] == 0].copy()
        print(f"lmsys empty — falling back to deepset legitimate rows ({len(legit)} rows)")

    corpus = pd.concat([attacks, legit], ignore_index=True).sample(
        frac=1, random_state=42  # shuffle so attacks and legit are interleaved
    ).reset_index(drop=True)

    print(f"Corpus: {len(corpus)} rows  "
          f"(attacks={( corpus['label']==1).sum()}  "
          f"legit={(corpus['label']==0).sum()})")
    return corpus


def call_llm(client: anthropic.Anthropic, text: str) -> tuple[str, float]:
    """
    Send a single user turn to Claude Haiku. Returns (response_text, latency_ms).
    No system prompt — truly unprotected.
    """
    with Timer() as t:
        message = client.messages.create(
            model=MODEL,
            max_tokens=512,
            messages=[{"role": "user", "content": text}],
        )
    return message.content[0].text, t.ms


def run(corpus: pd.DataFrame, dry_run: bool = False) -> None:
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    run_id = str(uuid.uuid4())[:8]  # shared prefix for this run's request IDs
    errors = 0

    for i, row in corpus.iterrows():
        text   = row["text"]
        source = row["source"]
        label  = "attack" if row["label"] == 1 else "legitimate"

        if dry_run:
            print(f"[{i}] source={source} label={label} text={text[:80]!r}")
            continue

        try:
            response, latency = call_llm(client, text)
        except Exception as e:
            print(f"[{i}] API error: {e}")
            errors += 1
            # Still log the failure so the row appears in results with decision=error
            log_request(
                input_text=text,
                layers_enabled=LAYERS_OFF,
                layer_results=RESULTS_OFF,
                final_decision="error",
                latency_ms={"total": 0.0},
                dataset_source=source,
                ground_truth_label=label,
                request_id=f"{run_id}-{i}",
            )
            continue

        log_request(
            input_text=text,
            layers_enabled=LAYERS_OFF,
            layer_results=RESULTS_OFF,
            final_decision="pass",           # B0 always passes — no protection
            latency_ms={"total": round(latency, 3)},
            dataset_source=source,
            ground_truth_label=label,
            request_id=f"{run_id}-{i}",
        )

        if i % 100 == 0:
            print(f"  [{i}/{len(corpus)}] latency={latency:.0f}ms  errors={errors}")

    if not dry_run:
        print(f"\nDone. {len(corpus)} rows processed, {errors} errors.")
        print("Results written to logs/pipeline.jsonl")
        print("Run evaluation/metrics.py to compute SecUtil.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true",
                        help="Print rows without making API calls")
    parser.add_argument("--limit", type=int, default=None,
                        help="Cap corpus size (smoke test)")
    args = parser.parse_args()

    corpus = load_eval_corpus()
    if args.limit:
        corpus = corpus.head(args.limit)
        print(f"--limit {args.limit}: running on {len(corpus)} rows")

    run(corpus, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
