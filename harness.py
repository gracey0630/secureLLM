"""
harness.py — Action 3: Evaluation harness skeleton.

Implements:
  - SecUtil metric:        SecUtil = F1_attack × (1 − FPR_legitimate)
  - per_layer_metrics():   TPR, FPR, precision, F1, latency p50/p95
  - threshold_sweep():     sweeps confidence 0.3→0.9, outputs tradeoff curve
  - plot_tradeoff_curve(): saves a PNG for the paper

Usage:
    from harness import compute_metrics, threshold_sweep, plot_tradeoff_curve
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Callable

from sklearn.metrics import (
    f1_score, precision_score, recall_score, confusion_matrix
)
import matplotlib
matplotlib.use("Agg")  # non-interactive backend (safe for servers)
import matplotlib.pyplot as plt
import seaborn as sns

RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)


# ════════════════════════════════════════════════════════════
# 1. Core metric dataclass
# ════════════════════════════════════════════════════════════

@dataclass
class LayerMetrics:
    layer:        str
    threshold:    float
    n_samples:    int
    # Detection metrics (attack class)
    TPR:          float   # True Positive Rate  = recall on attacks
    FPR:          float   # False Positive Rate on legitimate samples
    precision:    float
    F1:           float
    # SecUtil
    SecUtil:      float   # F1_attack × (1 − FPR_legitimate)
    # Latency
    latency_p50:  float   # ms
    latency_p95:  float   # ms

    def __str__(self):
        return (
            f"[{self.layer} @ threshold={self.threshold:.2f}] "
            f"TPR={self.TPR:.3f}  FPR={self.FPR:.3f}  "
            f"F1={self.F1:.3f}  SecUtil={self.SecUtil:.3f}  "
            f"p50={self.latency_p50:.1f}ms  p95={self.latency_p95:.1f}ms"
        )


# ════════════════════════════════════════════════════════════
# 2. SecUtil metric
# ════════════════════════════════════════════════════════════

def secutil(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """
    SecUtil = F1_attack × (1 − FPR_legitimate)

    Rewards high attack detection while penalising false positives
    on legitimate traffic. Range: [0, 1].

    Parameters
    ----------
    y_true : ground-truth labels  (1=attack, 0=legitimate)
    y_pred : predicted labels     (1=attack, 0=legitimate)
    """
    f1_attack = f1_score(y_true, y_pred, pos_label=1, zero_division=0)

    # FPR = FP / (FP + TN)  — computed on legitimate class
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return float(f1_attack * (1 - fpr))


# ════════════════════════════════════════════════════════════
# 3. Per-layer metrics
# ════════════════════════════════════════════════════════════

def compute_metrics(
    layer: str,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    latencies_ms: np.ndarray,
    threshold: float = 0.5,
) -> LayerMetrics:
    """
    Compute and return all metrics for one layer at one threshold.

    Parameters
    ----------
    layer        : layer name e.g. "input_scanner", "output_guard"
    y_true       : ground-truth binary labels
    y_pred       : predicted binary labels (already thresholded)
    latencies_ms : per-sample latency array
    threshold    : confidence threshold used to produce y_pred
    """
    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    latencies_ms = np.array(latencies_ms)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    tpr       = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    precision = precision_score(y_true, y_pred, pos_label=1, zero_division=0)
    f1        = f1_score(y_true, y_pred, pos_label=1, zero_division=0)
    su        = secutil(y_true, y_pred)

    m = LayerMetrics(
        layer       = layer,
        threshold   = threshold,
        n_samples   = len(y_true),
        TPR         = round(tpr, 4),
        FPR         = round(fpr, 4),
        precision   = round(float(precision), 4),
        F1          = round(float(f1), 4),
        SecUtil     = round(su, 4),
        latency_p50 = round(float(np.percentile(latencies_ms, 50)), 3),
        latency_p95 = round(float(np.percentile(latencies_ms, 95)), 3),
    )
    print(m)
    return m


# ════════════════════════════════════════════════════════════
# 4. Result logger  (appends to results/metrics.jsonl)
# ════════════════════════════════════════════════════════════

METRICS_LOG = RESULTS_DIR / "metrics.jsonl"

def log_metrics(m: LayerMetrics) -> None:
    """Append a LayerMetrics record to results/metrics.jsonl."""
    with open(METRICS_LOG, "a") as f:
        f.write(json.dumps(asdict(m)) + "\n")


def load_metrics_log() -> pd.DataFrame:
    """Load all logged metrics as a DataFrame."""
    if not METRICS_LOG.exists():
        return pd.DataFrame()
    rows = [json.loads(l) for l in METRICS_LOG.read_text().strip().splitlines()]
    return pd.DataFrame(rows)


# ════════════════════════════════════════════════════════════
# 5. Threshold sweep
# ════════════════════════════════════════════════════════════

def threshold_sweep(
    layer: str,
    scorer: Callable[[str], float],
    df: pd.DataFrame,
    thresholds: np.ndarray = np.arange(0.3, 0.91, 0.05),
    text_col: str = "text",
    label_col: str = "label",
) -> pd.DataFrame:
    """
    Sweep confidence threshold from 0.3→0.9 and compute metrics at each point.

    Parameters
    ----------
    layer     : layer name for logging
    scorer    : function  text -> float confidence score (higher = more suspicious)
    df        : DataFrame with text_col and label_col columns
    thresholds: array of thresholds to sweep

    Returns
    -------
    DataFrame with one row per threshold containing all LayerMetrics fields.
    """
    print(f"\nRunning threshold sweep for [{layer}] over {len(df)} samples...")

    # Score all samples once (expensive — don't repeat per threshold)
    import time
    scores = []
    latencies = []
    for text in df[text_col]:
        t0 = time.perf_counter()
        score = scorer(str(text))
        latencies.append((time.perf_counter() - t0) * 1000)
        scores.append(score)

    scores    = np.array(scores)
    latencies = np.array(latencies)
    y_true    = df[label_col].values

    rows = []
    for thresh in thresholds:
        y_pred = (scores >= thresh).astype(int)
        m = compute_metrics(layer, y_true, y_pred, latencies, threshold=float(round(thresh, 2)))
        log_metrics(m)
        rows.append(asdict(m))

    sweep_df = pd.DataFrame(rows)

    # Save sweep results
    out_path = RESULTS_DIR / f"sweep_{layer}.csv"
    sweep_df.to_csv(out_path, index=False)
    print(f"  → Sweep saved to {out_path}")

    return sweep_df


# ════════════════════════════════════════════════════════════
# 6. Tradeoff curve plot
# ════════════════════════════════════════════════════════════

def plot_tradeoff_curve(
    sweep_df: pd.DataFrame,
    layer: str,
    save: bool = True,
) -> None:
    """
    Plot SecUtil, F1, TPR, FPR vs threshold — the headline figure for the paper.
    """
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle(f"Threshold Tradeoff — {layer}", fontsize=14, fontweight="bold")

    # Left: SecUtil and F1 vs threshold
    ax = axes[0]
    ax.plot(sweep_df["threshold"], sweep_df["SecUtil"], marker="o", label="SecUtil", linewidth=2)
    ax.plot(sweep_df["threshold"], sweep_df["F1"],      marker="s", label="F1 (attack)", linewidth=2, linestyle="--")
    ax.set_xlabel("Confidence Threshold")
    ax.set_ylabel("Score")
    ax.set_title("SecUtil & F1 vs Threshold")
    ax.legend()
    ax.set_ylim(0, 1)
    ax.grid(True, alpha=0.3)

    # Right: TPR and FPR vs threshold (ROC-style)
    ax = axes[1]
    ax.plot(sweep_df["threshold"], sweep_df["TPR"], marker="o", label="TPR (sensitivity)", linewidth=2)
    ax.plot(sweep_df["threshold"], sweep_df["FPR"], marker="s", label="FPR (false alarm)", linewidth=2, linestyle="--", color="red")
    ax.set_xlabel("Confidence Threshold")
    ax.set_ylabel("Rate")
    ax.set_title("TPR & FPR vs Threshold")
    ax.legend()
    ax.set_ylim(0, 1)
    ax.grid(True, alpha=0.3)

    plt.tight_layout()

    if save:
        out_path = RESULTS_DIR / f"tradeoff_{layer}.png"
        plt.savefig(out_path, dpi=150, bbox_inches="tight")
        print(f"  → Plot saved to {out_path}")

    plt.close()


# ════════════════════════════════════════════════════════════
# 7. Quick smoke test
# ════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("Running harness smoke test...\n")

    # Fake data: 100 attacks + 100 legitimate
    rng = np.random.default_rng(42)
    n = 200
    y_true = np.array([1]*100 + [0]*100)
    # Simulate a scorer that's decent but not perfect
    scores  = np.where(y_true == 1,
                       rng.beta(5, 2, n),   # attacks score high
                       rng.beta(2, 5, n))   # legit scores low
    latencies = rng.uniform(10, 50, n)

    # Test compute_metrics at fixed threshold
    y_pred = (scores >= 0.5).astype(int)
    m = compute_metrics("smoke_test", y_true, y_pred, latencies, threshold=0.5)
    log_metrics(m)

    # Test threshold sweep with a dummy scorer
    df = pd.DataFrame({"text": [f"sample {i}" for i in range(n)], "label": y_true})
    score_map = {f"sample {i}": float(scores[i]) for i in range(n)}
    dummy_scorer = lambda text: score_map.get(text, 0.5)

    sweep = threshold_sweep("smoke_test_sweep", dummy_scorer, df)

    # Plot
    plot_tradeoff_curve(sweep, "smoke_test_sweep")

    print("\n✅ Harness smoke test complete.")
    print(f"   metrics.jsonl  → {METRICS_LOG}")
    print(f"   tradeoff plot  → {RESULTS_DIR / 'tradeoff_smoke_test_sweep.png'}")