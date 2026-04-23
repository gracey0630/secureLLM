"""
pipeline/presidio_scanner.py — Person C, Action 1: Set up Presidio.

Runs Microsoft Presidio on ai4privacy/pii-masking-200k samples and computes
entity-level recall for the four target entity types:
  PERSON, EMAIL_ADDRESS, PHONE_NUMBER, US_SSN

Ground truth comes from the dataset's privacy_mask column, which contains
character-span annotations for every PII entity in each text.

Usage:
    python pipeline/presidio_scanner.py

Outputs:
    results/presidio_baseline.json   — recall + precision per entity type
    results/presidio_samples.csv     — per-sample predictions for harness
    logs/pipeline.jsonl              — structured event log (via logging_schema)
"""

import json
import sys
import time
from pathlib import Path
from typing import Optional

import pandas as pd
from datasets import load_dataset
from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine

# Project root on path so we can import shared modules
sys.path.insert(0, str(Path(__file__).parent.parent))
from logging_schema import log_event, Timer

RESULTS_DIR = Path(__file__).parent.parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)

# ── Entity mapping ────────────────────────────────────────────────────────────
# ai4privacy label  →  Presidio entity type
AI4PRIVACY_TO_PRESIDIO: dict[str, str] = {
    "FIRSTNAME":   "PERSON",
    "LASTNAME":    "PERSON",
    "MIDDLENAME":  "PERSON",
    "EMAIL":       "EMAIL_ADDRESS",
    "PHONENUMBER": "PHONE_NUMBER",
    "SSN":         "US_SSN",
}

TARGET_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN"]

N_SAMPLES    = 300   # rows to pull from HuggingFace (English, with ≥1 target entity)
SCORE_THRESH = 0.5   # Presidio confidence threshold


# ── Presidio setup ────────────────────────────────────────────────────────────

def build_analyzer() -> AnalyzerEngine:
    """
    Build and return a Presidio AnalyzerEngine.
    Uses the default NLP engine (spacy en_core_web_lg must be installed).
    """
    return AnalyzerEngine()


# ── Ground-truth helpers ──────────────────────────────────────────────────────

def extract_gt_entities(privacy_mask) -> dict[str, list[tuple[int, int]]]:
    """
    Parse the privacy_mask field from ai4privacy into a dict mapping each
    Presidio entity type to a list of (start, end) character spans.

    Only target entities are kept; everything else is ignored.
    """
    if isinstance(privacy_mask, str):
        try:
            privacy_mask = json.loads(privacy_mask)
        except json.JSONDecodeError:
            return {}

    gt: dict[str, list[tuple[int, int]]] = {e: [] for e in TARGET_ENTITIES}
    for ann in privacy_mask:
        presidio_type = AI4PRIVACY_TO_PRESIDIO.get(ann.get("label", ""))
        if presidio_type:
            gt[presidio_type].append((ann["start"], ann["end"]))
    return gt


def spans_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    """True if two character spans overlap by at least one character."""
    return a_start < b_end and b_start < a_end


def match_prediction_to_gt(
    pred_results: list[RecognizerResult],
    gt: dict[str, list[tuple[int, int]]],
) -> dict[str, dict]:
    """
    For each target entity type, count:
      tp: ground-truth spans matched by at least one prediction of the same type
      fn: ground-truth spans with no matching prediction
      fp: predictions with no matching ground-truth span

    Returns a dict keyed by entity type.
    """
    stats: dict[str, dict] = {
        e: {"tp": 0, "fn": 0, "fp": 0} for e in TARGET_ENTITIES
    }

    for entity in TARGET_ENTITIES:
        gt_spans  = gt.get(entity, [])
        preds     = [r for r in pred_results if r.entity_type == entity
                     and r.score >= SCORE_THRESH]

        matched_gt   = set()
        matched_pred = set()

        for gi, (gs, ge) in enumerate(gt_spans):
            for pi, pred in enumerate(preds):
                if spans_overlap(pred.start, pred.end, gs, ge):
                    matched_gt.add(gi)
                    matched_pred.add(pi)

        stats[entity]["tp"] = len(matched_gt)
        stats[entity]["fn"] = len(gt_spans) - len(matched_gt)
        stats[entity]["fp"] = len(preds) - len(matched_pred)

    return stats


# ── Dataset loading ───────────────────────────────────────────────────────────

def load_ai4privacy_with_gt(n: int = N_SAMPLES) -> list[dict]:
    """
    Stream ai4privacy from HuggingFace and return the first `n` English rows
    that contain at least one target entity.

    Each returned dict has keys: text, privacy_mask (raw), gt (parsed).
    """
    print(f"Streaming ai4privacy/pii-masking-200k (target: {n} English rows with target PII)...")

    ds = load_dataset(
        "ai4privacy/pii-masking-200k",
        split="train",
        streaming=True,
    )

    rows: list[dict] = []
    seen = 0
    for example in ds:
        seen += 1
        if example.get("language", "en") != "en":
            continue
        gt = extract_gt_entities(example.get("privacy_mask", "[]"))
        # Only keep rows that have at least one target entity
        if not any(gt[e] for e in TARGET_ENTITIES):
            continue
        rows.append({
            "text":         example["source_text"],
            "privacy_mask": example.get("privacy_mask", "[]"),
            "gt":           gt,
        })
        if len(rows) >= n:
            break

    print(f"  Collected {len(rows)} usable rows (scanned {seen} total)")
    return rows


# ── Evaluation ────────────────────────────────────────────────────────────────

def evaluate_presidio(
    analyzer: AnalyzerEngine,
    rows: list[dict],
) -> tuple[pd.DataFrame, dict]:
    """
    Run Presidio on every row and accumulate TP/FN/FP per entity type.

    Returns
    -------
    samples_df : per-sample DataFrame (for harness / CSV export)
    summary    : aggregate recall, precision, F1 per entity type
    """
    agg: dict[str, dict] = {e: {"tp": 0, "fn": 0, "fp": 0} for e in TARGET_ENTITIES}
    sample_rows = []

    print(f"\nRunning Presidio on {len(rows)} samples...")
    for i, row in enumerate(rows):
        text = row["text"]
        gt   = row["gt"]

        with Timer() as t:
            results = analyzer.analyze(
                text=text,
                entities=TARGET_ENTITIES,
                language="en",
            )
        latency = t.ms

        stats = match_prediction_to_gt(results, gt)

        # Accumulate
        for entity, s in stats.items():
            agg[entity]["tp"] += s["tp"]
            agg[entity]["fn"] += s["fn"]
            agg[entity]["fp"] += s["fp"]

        # Log to pipeline
        detected = [r.entity_type for r in results if r.score >= SCORE_THRESH]
        gt_present = [e for e in TARGET_ENTITIES if gt[e]]
        log_event(
            input_text=text,
            layer_triggered="output_guard_presidio",
            decision="redact" if detected else "allow",
            latency_ms=latency,
            extra={
                "entities_detected": detected,
                "entities_gt":       gt_present,
                "tp": sum(s["tp"] for s in stats.values()),
                "fn": sum(s["fn"] for s in stats.values()),
                "fp": sum(s["fp"] for s in stats.values()),
            },
        )

        sample_rows.append({
            "text":             text[:200],
            "gt_entities":      str(gt_present),
            "detected_entities": str(list(set(detected))),
            "tp":               sum(s["tp"] for s in stats.values()),
            "fn":               sum(s["fn"] for s in stats.values()),
            "fp":               sum(s["fp"] for s in stats.values()),
            "latency_ms":       round(latency, 2),
        })

        if (i + 1) % 50 == 0:
            print(f"  [{i+1}/{len(rows)}] done")

    # Compute recall, precision, F1 per entity
    summary: dict[str, dict] = {}
    for entity, s in agg.items():
        tp, fn, fp = s["tp"], s["fn"], s["fp"]
        recall    = tp / (tp + fn) if (tp + fn) > 0 else None
        precision = tp / (tp + fp) if (tp + fp) > 0 else None
        if recall is not None and precision is not None and (precision + recall) > 0:
            f1 = 2 * precision * recall / (precision + recall)
        else:
            f1 = None
        summary[entity] = {
            "tp": tp, "fn": fn, "fp": fp,
            "recall":    round(recall,    4) if recall    is not None else None,
            "precision": round(precision, 4) if precision is not None else None,
            "f1":        round(f1,        4) if f1        is not None else None,
            "gt_count":  tp + fn,
        }

    return pd.DataFrame(sample_rows), summary


# ── Report ────────────────────────────────────────────────────────────────────

def print_report(summary: dict) -> None:
    print("\n" + "=" * 62)
    print("PRESIDIO BASELINE RECALL — ai4privacy/pii-masking-200k")
    print("=" * 62)
    print(f"  {'Entity':<20} {'GT count':>8} {'Recall':>8} {'Precision':>10} {'F1':>8}")
    print(f"  {'-'*20} {'-'*8} {'-'*8} {'-'*10} {'-'*8}")
    for entity, s in summary.items():
        recall    = f"{s['recall']:.3f}"    if s['recall']    is not None else "  N/A"
        precision = f"{s['precision']:.3f}" if s['precision'] is not None else "  N/A"
        f1        = f"{s['f1']:.3f}"        if s['f1']        is not None else "  N/A"
        print(f"  {entity:<20} {s['gt_count']:>8} {recall:>8} {precision:>10} {f1:>8}")
    print("=" * 62)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("Person C — Action 1: Presidio Baseline Evaluation")
    print("=" * 62)

    analyzer = build_analyzer()
    print("Presidio AnalyzerEngine ready.")

    rows = load_ai4privacy_with_gt(n=N_SAMPLES)
    if not rows:
        print("No rows loaded — check HuggingFace connectivity.")
        return

    samples_df, summary = evaluate_presidio(analyzer, rows)

    # Save outputs
    out_json = RESULTS_DIR / "presidio_baseline.json"
    out_csv  = RESULTS_DIR / "presidio_samples.csv"

    with open(out_json, "w") as f:
        json.dump({"n_samples": len(rows), "results": summary}, f, indent=2)

    samples_df.to_csv(out_csv, index=False)

    print_report(summary)
    print(f"\n  → {out_json}")
    print(f"  → {out_csv}")
    print(f"  → logs/pipeline.jsonl")


if __name__ == "__main__":
    main()
