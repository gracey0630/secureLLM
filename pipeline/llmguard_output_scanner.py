"""
pipeline/llmguard_output_scanner.py — Person C, Action 2: LLM Guard output scanners.

Runs two LLM Guard scanners on the same ai4privacy/pii-masking-200k samples
used in Action 1 (presidio_scanner.py), then produces a head-to-head comparison
table: Presidio vs. LLM Guard Sensitive.

Scanners
--------
Sensitive (output_scanners)
    PII detection backed by the ai4privacy DeBERTa-v3 NER model.
    Supports: PERSON, EMAIL_ADDRESS, PHONE_NUMBER, US_SSN (and more).
    NOTE: this model was fine-tuned ON ai4privacy data, so recall on this
    dataset is an upper-bound estimate — record this caveat in the paper.

Secrets (input_scanners — applied to output text)
    Credential / secret-string detection via detect-secrets patterns.
    Catches: API keys, AWS credentials, private keys, connection strings.
    Less relevant to PII recall, but tested here for completeness and
    reused heavily in Action 3 (synthetic canary evaluation).

Usage:
    python pipeline/llmguard_output_scanner.py

Outputs:
    results/llmguard_sensitive_baseline.json   — recall/precision per entity
    results/llmguard_sensitive_samples.csv     — per-sample predictions
    results/comparison_presidio_vs_llmguard.json — head-to-head table
    logs/pipeline.jsonl                        — structured event log
"""

import json
import sys
from pathlib import Path

import pandas as pd
from datasets import load_dataset

sys.path.insert(0, str(Path(__file__).parent.parent))
from logging_schema import log_event, Timer

# Reuse ground-truth helpers from presidio_scanner
from presidio_scanner import (
    extract_gt_entities,
    match_prediction_to_gt,
    load_ai4privacy_with_gt,
    TARGET_ENTITIES,
    N_SAMPLES,
    print_report,
)

RESULTS_DIR = Path(__file__).parent.parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)

SCORE_THRESH = 0.5


# ── Scanner setup ─────────────────────────────────────────────────────────────

def build_sensitive_scanner():
    """
    LLM Guard Sensitive scanner — PII detection via DeBERTa ai4privacy v2.
    We expose _analyzer directly to get per-span results (same interface
    as Presidio) rather than just the binary pass/fail from .scan().
    """
    from llm_guard.output_scanners import Sensitive
    scanner = Sensitive(
        entity_types=list(TARGET_ENTITIES),  # copy — Sensitive appends "CUSTOM" in-place
        threshold=SCORE_THRESH,
    )
    return scanner


def build_secrets_scanner():
    """
    LLM Guard Secrets scanner — credential / secret leakage detection.
    Lives in input_scanners but is applied here to output text.
    """
    from llm_guard.input_scanners import Secrets
    return Secrets()


# ── Sensitive evaluation (span-level, mirrors presidio_scanner) ──────────────

def evaluate_sensitive(scanner, rows: list[dict]) -> tuple[pd.DataFrame, dict]:
    """
    Run LLM Guard Sensitive on every row using the internal _analyzer for
    span-level TP/FN/FP — identical methodology to evaluate_presidio().
    """
    agg = {e: {"tp": 0, "fn": 0, "fp": 0} for e in TARGET_ENTITIES}
    sample_rows = []

    print(f"\nRunning LLM Guard Sensitive on {len(rows)} samples...")
    for i, row in enumerate(rows):
        text = row["text"]
        gt   = row["gt"]

        with Timer() as t:
            # Access internal Presidio analyzer to get full span results
            results = scanner._analyzer.analyze(
                text=text,
                entities=TARGET_ENTITIES,
                language="en",
                score_threshold=SCORE_THRESH,
            )
        latency = t.ms

        stats = match_prediction_to_gt(results, gt)
        for entity, s in stats.items():
            agg[entity]["tp"] += s["tp"]
            agg[entity]["fn"] += s["fn"]
            agg[entity]["fp"] += s["fp"]

        detected    = list({r.entity_type for r in results})
        gt_present  = [e for e in TARGET_ENTITIES if gt[e]]
        log_event(
            input_text=text,
            layer_triggered="output_guard_llmguard_sensitive",
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
            "text":              text[:200],
            "gt_entities":       str(gt_present),
            "detected_entities": str(detected),
            "tp":  sum(s["tp"] for s in stats.values()),
            "fn":  sum(s["fn"] for s in stats.values()),
            "fp":  sum(s["fp"] for s in stats.values()),
            "latency_ms": round(latency, 2),
        })

        if (i + 1) % 50 == 0:
            print(f"  [{i+1}/{len(rows)}] done")

    summary = _compute_summary(agg)
    return pd.DataFrame(sample_rows), summary


# ── Secrets evaluation (document-level — no GT spans, binary flag) ───────────

def evaluate_secrets(scanner, rows: list[dict]) -> pd.DataFrame:
    """
    Run LLM Guard Secrets on each text.
    ai4privacy texts contain PII but not credentials, so we expect mostly
    is_valid=True (no secrets detected). Documents flagged are false positives.

    Returns a DataFrame with per-sample results and a FPR summary.
    """
    sample_rows = []
    print(f"\nRunning LLM Guard Secrets on {len(rows)} samples...")

    for i, row in enumerate(rows):
        text = row["text"]
        with Timer() as t:
            sanitized, is_valid, risk_score = scanner.scan(text)
        latency = t.ms

        # is_valid=False means secrets were detected (a flag)
        flagged = not is_valid
        log_event(
            input_text=text,
            layer_triggered="output_guard_llmguard_secrets",
            decision="block" if flagged else "allow",
            latency_ms=latency,
            confidence=risk_score if risk_score >= 0 else None,
        )

        sample_rows.append({
            "text":       text[:200],
            "flagged":    flagged,
            "risk_score": round(risk_score, 4),
            "latency_ms": round(latency, 2),
        })

        if (i + 1) % 50 == 0:
            print(f"  [{i+1}/{len(rows)}] done")

    df = pd.DataFrame(sample_rows)
    n_flagged = df["flagged"].sum()
    fpr = n_flagged / len(df) if len(df) > 0 else 0
    print(f"\n  Secrets — flagged {n_flagged}/{len(df)} ai4privacy docs as containing secrets")
    print(f"  (FPR on legitimate PII text = {fpr:.3f})")
    return df


# ── Helpers ───────────────────────────────────────────────────────────────────

def _compute_summary(agg: dict) -> dict:
    summary = {}
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
    return summary


def print_comparison(presidio: dict, llmguard: dict) -> None:
    """Side-by-side recall/F1 comparison table."""
    print("\n" + "=" * 76)
    print("HEAD-TO-HEAD: Presidio (spaCy NER)  vs.  LLM Guard Sensitive (DeBERTa)")
    print("=" * 76)
    hdr = f"  {'Entity':<20} {'Presidio':>10}{'':>4} {'LLM Guard':>10}{'':>4}  {'Winner'}"
    print(hdr)
    print(f"  {'':20} {'Recall':>8} {'F1':>6} {'Recall':>8} {'F1':>6}")
    print(f"  {'-'*20} {'-'*8} {'-'*6} {'-'*8} {'-'*6}  {'-'*10}")

    for entity in TARGET_ENTITIES:
        p  = presidio.get(entity, {})
        lg = llmguard.get(entity, {})
        p_r  = f"{p['recall']:.3f}"   if p.get("recall")    is not None else "  N/A"
        p_f  = f"{p['f1']:.3f}"       if p.get("f1")        is not None else " N/A"
        lg_r = f"{lg['recall']:.3f}"  if lg.get("recall")   is not None else "  N/A"
        lg_f = f"{lg['f1']:.3f}"      if lg.get("f1")       is not None else " N/A"

        p_rec  = p.get("recall")  or 0
        lg_rec = lg.get("recall") or 0
        winner = "LLM Guard" if lg_rec > p_rec else ("Presidio" if p_rec > lg_rec else "Tie")
        print(f"  {entity:<20} {p_r:>8} {p_f:>6} {lg_r:>8} {lg_f:>6}  {winner}")

    print("=" * 76)
    print("  NOTE: LLM Guard Sensitive uses DeBERTa fine-tuned ON ai4privacy —")
    print("  recall advantage on this dataset is expected (train/test overlap).")
    print("=" * 76)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("Person C — Action 2: LLM Guard Output Scanners")
    print("=" * 76)

    # Load ground-truth rows (same 300 as presidio_scanner)
    rows = load_ai4privacy_with_gt(n=N_SAMPLES)
    if not rows:
        print("No rows loaded — check HuggingFace connectivity.")
        return

    # ── 1. Sensitive scanner ──────────────────────────────────────────────────
    print("\nBuilding LLM Guard Sensitive scanner (downloads DeBERTa on first run)...")
    sensitive_scanner = build_sensitive_scanner()
    sensitive_df, sensitive_summary = evaluate_sensitive(sensitive_scanner, rows)

    out_json = RESULTS_DIR / "llmguard_sensitive_baseline.json"
    out_csv  = RESULTS_DIR / "llmguard_sensitive_samples.csv"
    with open(out_json, "w") as f:
        json.dump({"n_samples": len(rows), "results": sensitive_summary}, f, indent=2)
    sensitive_df.to_csv(out_csv, index=False)

    print("\nLLM Guard Sensitive results:")
    print_report(sensitive_summary)

    # ── 2. Secrets scanner ────────────────────────────────────────────────────
    print("\nBuilding LLM Guard Secrets scanner...")
    secrets_scanner = build_secrets_scanner()
    secrets_df = evaluate_secrets(secrets_scanner, rows)
    secrets_df.to_csv(RESULTS_DIR / "llmguard_secrets_samples.csv", index=False)

    # ── 3. Head-to-head comparison ────────────────────────────────────────────
    presidio_path = RESULTS_DIR / "presidio_baseline.json"
    if presidio_path.exists():
        with open(presidio_path) as f:
            presidio_summary = json.load(f)["results"]
        print_comparison(presidio_summary, sensitive_summary)

        comparison = {
            "n_samples": len(rows),
            "presidio":  presidio_summary,
            "llmguard":  sensitive_summary,
        }
        cmp_path = RESULTS_DIR / "comparison_presidio_vs_llmguard.json"
        with open(cmp_path, "w") as f:
            json.dump(comparison, f, indent=2)
        print(f"\n  → {cmp_path}")
    else:
        print("\n  presidio_baseline.json not found — run presidio_scanner.py first.")

    print(f"  → {out_json}")
    print(f"  → {out_csv}")
    print(f"  → {RESULTS_DIR / 'llmguard_secrets_samples.csv'}")
    print(f"  → logs/pipeline.jsonl")


if __name__ == "__main__":
    main()
