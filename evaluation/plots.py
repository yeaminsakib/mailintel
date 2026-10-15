"""
evaluation/plots.py
===================
Generates publication-quality evaluation figures and charts (300 DPI PNG & SVG):
- Score distribution histograms and boxplots (Phishing vs Ham)
- Receiver Operating Characteristic (ROC) curves with AUROC
- Precision-Recall (PR) curves with Average Precision
- IOC extraction precision, recall, and F1 across categories
- Top logistic regression feature coefficients (explainability)
"""
from __future__ import annotations

import logging
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # Headless backend
import matplotlib.pyplot as plt
import numpy as np

from .ioc_evaluator import IocEvaluationResult
from .ml_baseline import MLComparisonResult
from .scoring_evaluator import ScoringEvaluationResult

logger = logging.getLogger(__name__)

# Set clean scientific publication style
plt.rcParams.update({
    "font.sans-serif": ["DejaVu Sans", "Helvetica", "Arial"],
    "font.family": "sans-serif",
    "figure.autolayout": True,
    "axes.edgecolor": "#94a3b8",
    "axes.linewidth": 0.8,
    "grid.color": "#e2e8f0",
    "grid.linestyle": "--",
    "grid.linewidth": 0.5,
})


def generate_all_plots(
    scoring_res: ScoringEvaluationResult,
    ioc_res: IocEvaluationResult,
    ml_res: MLComparisonResult,
    output_dir: Path,
) -> list[Path]:
    """Generate and save all publication figures to output_dir.

    Returns
    -------
    list[Path]
        Paths of generated figure files.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    generated: list[Path] = []

    p1 = plot_score_distribution(scoring_res, output_dir)
    generated.append(p1)

    p2 = plot_roc_curves(scoring_res, ml_res, output_dir)
    generated.append(p2)

    p3 = plot_pr_curves(scoring_res, ml_res, output_dir)
    generated.append(p3)

    p4 = plot_ioc_metrics(ioc_res, output_dir)
    generated.append(p4)

    p5 = plot_feature_importance(ml_res, output_dir)
    generated.append(p5)

    return generated


def plot_score_distribution(scoring_res: ScoringEvaluationResult, output_dir: Path) -> Path:
    """Plot risk score distribution comparison: Histogram + KDE and Boxplot."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5), dpi=300)

    phish_scores = [s for s, y in zip(scoring_res.all_scores, scoring_res.all_labels, strict=False) if y == 1]
    ham_scores = [s for s, y in zip(scoring_res.all_scores, scoring_res.all_labels, strict=False) if y == 0]

    bins = np.linspace(0, 100, 21)

    # 1. Left: Histogram overlay
    ax1.hist(
        ham_scores,
        bins=bins,
        alpha=0.65,
        color="#0284c7",
        edgecolor="#0369a1",
        label=f"SpamAssassin Ham (n={len(ham_scores)})",
        density=True,
    )
    ax1.hist(
        phish_scores,
        bins=bins,
        alpha=0.65,
        color="#dc2626",
        edgecolor="#b91c1c",
        label=f"Phishing_pot (n={len(phish_scores)})",
        density=True,
    )

    ax1.axvline(
        scoring_res.optimal_threshold,
        color="#16a34a",
        linestyle="--",
        linewidth=1.8,
        label=f"Optimal Threshold ({scoring_res.optimal_threshold:.1f})",
    )
    ax1.axvline(
        50.0,
        color="#d97706",
        linestyle=":",
        linewidth=1.5,
        label="Default SOC Threshold (50.0)",
    )

    ax1.set_title("Risk Score Probability Density", fontsize=12, fontweight="bold", pad=10)
    ax1.set_xlabel("MailIntel Risk Score (0–100)", fontsize=10)
    ax1.set_ylabel("Density", fontsize=10)
    ax1.grid(True)
    ax1.legend(loc="upper center", frameon=True, fontsize=9)
    ax1.set_xlim(0, 100)

    bp = ax2.boxplot(
        [ham_scores, phish_scores],
        patch_artist=True,
        widths=0.5,
        medianprops={"color": "black", "linewidth": 2},
    )
    ax2.set_xticks([1, 2])
    ax2.set_xticklabels(["SpamAssassin Ham", "Phishing_pot"], fontsize=10)
    colors = ["#38bdf8", "#f87171"]
    for patch, c in zip(bp["boxes"], colors, strict=False):
        patch.set_facecolor(c)
        patch.set_alpha(0.85)

    ax2.set_title("Score Quartile Separation", fontsize=12, fontweight="bold", pad=10)
    ax2.set_ylabel("Risk Score (0–100)", fontsize=10)
    ax2.grid(True, axis="y")
    ax2.set_ylim(-2, 105)

    # Annotate summary means
    ax2.text(1, scoring_res.ham_stats.mean + 3, f"μ={scoring_res.ham_stats.mean:.1f}\nmed={scoring_res.ham_stats.median:.1f}", ha="center", fontsize=9, fontweight="bold")
    ax2.text(2, scoring_res.phishing_stats.mean + 3, f"μ={scoring_res.phishing_stats.mean:.1f}\nmed={scoring_res.phishing_stats.median:.1f}", ha="center", fontsize=9, fontweight="bold")

    out_file = output_dir / "score_distribution.png"
    plt.savefig(out_file, bbox_inches="tight")
    plt.close()
    return out_file


def plot_roc_curves(scoring_res: ScoringEvaluationResult, ml_res: MLComparisonResult, output_dir: Path) -> Path:
    """Plot multi-model Receiver Operating Characteristic (ROC) curves."""
    fig, ax = plt.subplots(figsize=(7, 6), dpi=300)

    # 1. Rule-based model curve
    ax.plot(
        scoring_res.fpr_values,
        scoring_res.tpr_values,
        color="#2563eb",
        linewidth=2.2,
        label=f"MailIntel Rule-Based (AUC = {scoring_res.roc_auc:.4f})",
    )

    # 2. ML Baseline curve
    ax.plot(
        ml_res.ml_fpr,
        ml_res.ml_tpr,
        color="#7c3aed",
        linewidth=2.0,
        linestyle="-.",
        label=f"TF-IDF + Header Logistic Reg (AUC = {ml_res.ml_baseline_metrics.roc_auc:.4f})",
    )

    # 3. Random chance diagonal
    ax.plot([0, 1], [0, 1], color="#94a3b8", linestyle="--", linewidth=1.2, label="Random Guess (AUC = 0.5000)")

    # Mark optimal threshold operating point
    opt_fpr = 1.0 - scoring_res.optimal_metrics.specificity
    opt_tpr = scoring_res.optimal_metrics.recall
    ax.scatter(
        [opt_fpr],
        [opt_tpr],
        color="#dc2626",
        s=90,
        zorder=5,
        label=f"Optimal Operating Point (Score={scoring_res.optimal_threshold:.1f})",
    )

    ax.set_title("Receiver Operating Characteristic (ROC) Comparison", fontsize=12, fontweight="bold", pad=10)
    ax.set_xlabel("False Positive Rate (1 - Specificity)", fontsize=10)
    ax.set_ylabel("True Positive Rate (Recall / Sensitivity)", fontsize=10)
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.02, 1.02)
    ax.grid(True)
    ax.legend(loc="lower right", frameon=True, fontsize=9)

    out_file = output_dir / "roc_curves.png"
    plt.savefig(out_file, bbox_inches="tight")
    plt.close()
    return out_file


def plot_pr_curves(scoring_res: ScoringEvaluationResult, ml_res: MLComparisonResult, output_dir: Path) -> Path:
    """Plot Precision-Recall (PR) curves comparing models."""
    fig, ax = plt.subplots(figsize=(7, 6), dpi=300)

    ax.plot(
        scoring_res.recall_values,
        scoring_res.precision_values,
        color="#2563eb",
        linewidth=2.2,
        label=f"MailIntel Rule-Based (AP = {scoring_res.pr_auc:.4f})",
    )

    ax.plot(
        ml_res.ml_rec,
        ml_res.ml_prec,
        color="#7c3aed",
        linewidth=2.0,
        linestyle="-.",
        label=f"TF-IDF + Header Logistic Reg (AP = {ml_res.ml_baseline_metrics.pr_auc:.4f})",
    )

    # Prevalence baseline
    phish_ratio = sum(scoring_res.all_labels) / len(scoring_res.all_labels)
    ax.axhline(phish_ratio, color="#94a3b8", linestyle="--", linewidth=1.2, label=f"Prevalence Baseline ({phish_ratio:.2f})")

    ax.set_title("Precision-Recall (PR) Performance", fontsize=12, fontweight="bold", pad=10)
    ax.set_xlabel("Recall (Coverage of Phishing Attacks)", fontsize=10)
    ax.set_ylabel("Precision (True Positive Proportion)", fontsize=10)
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(min(0.4, phish_ratio - 0.1), 1.05)
    ax.grid(True)
    ax.legend(loc="lower left", frameon=True, fontsize=9)

    out_file = output_dir / "pr_curves.png"
    plt.savefig(out_file, bbox_inches="tight")
    plt.close()
    return out_file


def plot_ioc_metrics(ioc_res: IocEvaluationResult, output_dir: Path) -> Path:
    """Plot grouped bar chart of IOC extraction Precision, Recall, and F1."""
    fig, ax = plt.subplots(figsize=(9, 5), dpi=300)

    cat_names = ["IPv4", "Domain", "URL", "Email", "Overall"]
    cat_keys = ["ipv4", "domain", "url", "email", "overall"]

    precisions = []
    recalls = []
    f1s = []

    cat_map = ioc_res.categories
    overall = ioc_res.overall_metrics

    for k in cat_keys:
        m = cat_map[k] if k != "overall" else overall
        precisions.append(m.precision * 100.0)
        recalls.append(m.recall * 100.0)
        f1s.append(m.f1_score * 100.0)

    x = np.arange(len(cat_names))
    width = 0.25

    rects1 = ax.bar(x - width, precisions, width, label="Precision", color="#3b82f6")
    rects2 = ax.bar(x, recalls, width, label="Recall", color="#10b981")
    rects3 = ax.bar(x + width, f1s, width, label="F1-Score", color="#8b5cf6")

    ax.set_ylabel("Percentage (%)", fontsize=10)
    ax.set_title("IOC Extraction Performance by Indicator Type", fontsize=12, fontweight="bold", pad=10)
    ax.set_xticks(x)
    ax.set_xticklabels(cat_names, fontsize=10)
    ax.set_ylim(0, 115)
    ax.grid(True, axis="y")
    ax.legend(loc="upper right", frameon=True, fontsize=9)

    # Attach value labels on bars
    for rects in [rects1, rects2, rects3]:
        for rect in rects:
            height = rect.get_height()
            ax.annotate(
                f"{height:.1f}%",
                xy=(rect.get_x() + rect.get_width() / 2, height),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=7.5,
            )

    out_file = output_dir / "ioc_extraction_performance.png"
    plt.savefig(out_file, bbox_inches="tight")
    plt.close()
    return out_file


def plot_feature_importance(ml_res: MLComparisonResult, output_dir: Path) -> Path:
    """Plot horizontal bar chart of top positive (phishing) and negative (ham) coefficients."""
    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)

    top_phish = ml_res.top_phishing_features[:10]
    top_ham = ml_res.top_ham_features[:10]

    all_feats = list(reversed(top_ham)) + top_phish
    names = [f[0] for f in all_feats]
    weights = [f[1] for f in all_feats]

    colors = ["#10b981" if w < 0 else "#ef4444" for w in weights]

    y_pos = np.arange(len(names))
    ax.barh(y_pos, weights, color=colors, height=0.65, edgecolor="none")

    ax.set_yticks(y_pos)
    ax.set_yticklabels(names, fontsize=9)
    ax.set_xlabel("Logistic Regression Coefficient Weight (Log-Odds)", fontsize=10)
    ax.set_title("Feature Interpretability: Top Phishing vs Ham Predictors", fontsize=12, fontweight="bold", pad=10)
    ax.axvline(0, color="#64748b", linewidth=1.0)
    ax.grid(True, axis="x")

    out_file = output_dir / "ml_feature_coefficients.png"
    plt.savefig(out_file, bbox_inches="tight")
    plt.close()
    return out_file
