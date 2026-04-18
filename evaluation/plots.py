"""
evaluation/plots.py — Tradeoff curve figures for the paper.

Usage:
    from evaluation.plots import plot_tradeoff_curve
    sweep_df = threshold_sweep(...)
    plot_tradeoff_curve(sweep_df, layer="input_scanner")
"""

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

RESULTS_DIR = Path(__file__).parent.parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)


def plot_tradeoff_curve(sweep_df: pd.DataFrame, layer: str, save: bool = True) -> None:
    """
    Plot SecUtil, F1, TPR, FPR vs threshold.
    sweep_df must have columns: threshold, secutil, f1, tpr, fpr
    (output of evaluation/metrics.py threshold_sweep).
    """
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle(f"Threshold Tradeoff — {layer}", fontsize=14, fontweight="bold")

    ax = axes[0]
    ax.plot(sweep_df["threshold"], sweep_df["secutil"], marker="o", label="SecUtil", linewidth=2)
    ax.plot(sweep_df["threshold"], sweep_df["f1"],      marker="s", label="F1 (attack)", linewidth=2, linestyle="--")
    ax.set_xlabel("Confidence Threshold")
    ax.set_ylabel("Score")
    ax.set_title("SecUtil & F1 vs Threshold")
    ax.legend()
    ax.set_ylim(0, 1)
    ax.grid(True, alpha=0.3)

    ax = axes[1]
    ax.plot(sweep_df["threshold"], sweep_df["tpr"], marker="o", label="TPR (sensitivity)", linewidth=2)
    ax.plot(sweep_df["threshold"], sweep_df["fpr"], marker="s", label="FPR (false alarm)", linewidth=2, linestyle="--", color="red")
    ax.set_xlabel("Confidence Threshold")
    ax.set_ylabel("Rate")
    ax.set_title("TPR & FPR vs Threshold")
    ax.legend()
    ax.set_ylim(0, 1)
    ax.grid(True, alpha=0.3)

    plt.tight_layout()

    if save:
        out = RESULTS_DIR / f"tradeoff_{layer}.png"
        plt.savefig(out, dpi=150, bbox_inches="tight")
        print(f"  → Plot saved to {out}")

    plt.close()
