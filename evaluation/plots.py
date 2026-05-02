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


def plot_secutil_comparison(
    sweep_df: pd.DataFrame,
    b0: dict,
    b1: dict,
    b2: dict,
    save: bool = True,
) -> None:
    """
    Plot the LLM Guard threshold sweep with B0/B1/B2 overlaid as reference points.

    sweep_df : output of run_threshold_sweep.run_sweep() — columns threshold,
               tpr, fpr, secutil
    b0/b1/b2 : dicts with keys tpr, fpr, secutil

    Left panel  — SecUtil vs threshold: sweep curve + B0/B1/B2 horizontal lines.
    Right panel — FPR vs threshold: the only dimension that varies on the flat curve
                  (TPR=1.0 throughout), showing the operational tradeoff that exists.

    The flat sweep is presented as a finding: LLM Guard's binary score distribution
    on HackAPrompt means threshold choice has minimal impact. The B0→B1→B2 SecUtil
    progression is the meaningful comparison.
    """
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle("SecUtil Analysis — Input Scanner Comparison", fontsize=13, fontweight="bold")

    # ── Left: SecUtil vs threshold ─────────────────────────────────────────────
    ax = axes[0]
    ax.plot(sweep_df["threshold"], sweep_df["secutil"],
            marker="o", linewidth=2, label="LLM Guard (sweep)", color="steelblue")

    # B0/B1/B2 as horizontal reference lines with point markers at x=midpoint
    x_mid = sweep_df["threshold"].median()
    for ref, label, color, ls in [
        (b0, f"B0 — unprotected  (SecUtil={b0['secutil']:.3f})",  "red",    "--"),
        (b1, f"B1 — heuristic    (SecUtil={b1['secutil']:.3f})",  "orange", "--"),
        (b2, f"B2 — LLM Guard t=0.5 (SecUtil={b2['secutil']:.3f})", "green", ":"),
    ]:
        ax.axhline(ref["secutil"], color=color, linestyle=ls, linewidth=1.5, label=label)

    ax.set_xlabel("Confidence Threshold")
    ax.set_ylabel("SecUtil  =  F1_attack × (1 − FPR)")
    ax.set_title("SecUtil vs Threshold\n(curve flat → threshold choice has minimal impact)")
    ax.legend(fontsize=8)
    ax.set_ylim(-0.05, 1.05)
    ax.grid(True, alpha=0.3)

    # ── Right: FPR vs threshold ────────────────────────────────────────────────
    # TPR is constant at 1.0 across the sweep — FPR is the only moving dimension.
    ax = axes[1]
    ax.plot(sweep_df["threshold"], sweep_df["fpr"],
            marker="s", linewidth=2, color="red", label="LLM Guard FPR")

    ax.axhline(b1["fpr"], color="orange", linestyle="--", linewidth=1.5,
               label=f"B1 heuristic FPR={b1['fpr']:.3f}")
    ax.axhline(b0["fpr"], color="gray",   linestyle=":",  linewidth=1.2,
               label=f"B0 unprotected FPR={b0['fpr']:.3f}")

    ax.set_xlabel("Confidence Threshold")
    ax.set_ylabel("False Positive Rate (legitimate queries blocked)")
    ax.set_title("FPR vs Threshold\n(only dimension varying — TPR=1.0 throughout)")
    ax.legend(fontsize=8)
    ax.set_ylim(-0.01, 0.20)
    ax.grid(True, alpha=0.3)

    plt.tight_layout()

    if save:
        out = RESULTS_DIR / "tradeoff_llmguard.png"
        plt.savefig(out, dpi=150, bbox_inches="tight")
        print(f"  → Plot saved to {out}")

    plt.close()
