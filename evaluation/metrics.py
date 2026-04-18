"""
evaluation/metrics.py — SecUtil metric and supporting classification metrics.

All functions are pure (no file I/O). The caller loads pipeline.jsonl and
extracts arrays; this file only computes over them.

Typical caller pattern:
    df = pd.read_json("logs/pipeline.jsonl", lines=True)
    y_true = (df["ground_truth_label"] == "attack").astype(int).to_numpy()
    y_pred = (df["final_decision"] == "block").astype(int).to_numpy()
    metrics = compute_classification_metrics(y_true, y_pred)
    secutil = compute_secutil(metrics["f1"], metrics["fpr"])
"""

import warnings
import numpy as np
import pandas as pd
from sklearn.metrics import (
    f1_score, precision_score, recall_score, confusion_matrix
)
from typing import Callable


# ── Core metric ───────────────────────────────────────────────────────────────
def compute_secutil(f1_attack: float, fpr_legitimate: float) -> float:
    """
    SecUtil = F1_attack × (1 - FPR_legitimate)

    Ranges 0→1. Higher is better: rewards catching attacks while
    minimising false positives on legitimate traffic.

    Returns 0.0 for degenerate cases (e.g. B0 unprotected assistant
    where f1_attack=0) rather than NaN so sweep DataFrames stay clean.
    """
    if np.isnan(f1_attack) or np.isnan(fpr_legitimate):
        return 0.0
    return float(f1_attack * (1.0 - fpr_legitimate))


# ── Classification metrics ────────────────────────────────────────────────────
def compute_classification_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    """
    Compute TPR, FPR, precision, F1 for a binary classifier.

    y_true / y_pred: 1 = attack, 0 = legitimate.

    Returns a dict with keys: tpr, fpr, precision, f1, n.
    Safe when one class is absent or all predictions are the same class —
    returns 0.0 for undefined metrics with a warning instead of raising.
    """
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # suppress sklearn zero-division warnings
        f1        = f1_score(y_true, y_pred, zero_division=0)
        precision = precision_score(y_true, y_pred, zero_division=0)
        tpr       = recall_score(y_true, y_pred, zero_division=0)  # TPR = recall

    # FPR = FP / (FP + TN) — not in sklearn directly
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "tpr":       float(tpr),
        "fpr":       float(fpr),
        "precision": float(precision),
        "f1":        float(f1),
        "n":         int(len(y_true)),
    }


# ── Threshold sweep ───────────────────────────────────────────────────────────
def threshold_sweep(
    scorer: Callable[[str], float],
    inputs: list[str],
    labels: list[int],
    thresholds: list[float] | np.ndarray,
) -> pd.DataFrame:
    """
    Sweep confidence thresholds over a continuous scorer, computing SecUtil
    at each threshold. Returns one DataFrame row per threshold.

    scorer    : callable(text) -> float in [0, 1]. Must return a continuous
                score. Do NOT pass a binary heuristic scorer here — binary
                classifiers (e.g. B1) produce a single point, not a curve;
                compute their metrics directly with compute_classification_metrics.
    inputs    : list of raw text strings (one per eval example)
    labels    : 1=attack, 0=legitimate (parallel to inputs)
    thresholds: e.g. np.linspace(0.3, 0.9, 13)

    Returns columns: threshold, tpr, fpr, precision, f1, secutil, n
    """
    scores = np.array([scorer(text) for text in inputs])
    y_true = np.asarray(labels)

    rows = []
    for threshold in thresholds:
        y_pred = (scores >= threshold).astype(int)
        m = compute_classification_metrics(y_true, y_pred)
        rows.append({
            "threshold": round(float(threshold), 4),
            **m,
            "secutil": compute_secutil(m["f1"], m["fpr"]),
        })

    return pd.DataFrame(rows)


# ── Latency stats ─────────────────────────────────────────────────────────────
def compute_latency_stats(latency_list: list[float]) -> dict:
    """
    Summarise per-layer latency (ms) across requests.

    Stub for Week 1 — meaningful only once the full pipeline runs end-to-end
    in Week 2. Returns p50, p95, mean, n.
    """
    a = np.asarray(latency_list, dtype=float)
    if len(a) == 0:
        return {"p50": None, "p95": None, "mean": None, "n": 0}
    return {
        "p50":  float(np.percentile(a, 50)),
        "p95":  float(np.percentile(a, 95)),
        "mean": float(np.mean(a)),
        "n":    int(len(a)),
    }
