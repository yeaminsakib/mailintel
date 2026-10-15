"""
evaluation/run_evaluation.py
============================
Executable runner for the MailIntel evaluation harness.
Runs the evaluation pipeline over the labelled corpus (phishing_pot + SpamAssassin ham),
evaluates IOC extraction, computes score distributions, ROC/PR curves,
trains the TF-IDF + Header ML baseline, runs false-positive analysis,
generates figures, and outputs results tables and reports.
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.ioc.whitelist import WhitelistPolicy
from core.scoring.risk_score import RiskScorer

from .dataset import load_evaluation_corpus
from .error_analysis import analyze_errors
from .ioc_evaluator import evaluate_ioc_extraction
from .ml_baseline import evaluate_ml_baseline
from .plots import generate_all_plots
from .report_generator import generate_evaluation_artifacts
from .scoring_evaluator import evaluate_scoring

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("mailintel.evaluation")
console = Console()


def run_pipeline(
    corpus_size: int = 150,
    output_dir: Path | None = None,
    generate_plots: bool = True,
) -> dict[str, Any]:
    """Execute the complete evaluation pipeline and print rich results."""
    out_dir = output_dir or (Path(__file__).resolve().parent / "output")
    out_dir.mkdir(parents=True, exist_ok=True)

    console.print(
        Panel.fit(
            "[bold cyan]MailIntel[/bold cyan] [bold white]Empirical Evaluation Harness[/bold white]\n"
            f"[dim]Labelled Corpus: phishing_pot (positives) + SpamAssassin ham (negatives)[/dim]\n"
            f"[dim]Target Output Directory: {out_dir}[/dim]",
            border_style="cyan",
        )
    )

    # 1. Load Corpus
    with console.status("[cyan]Loading labelled evaluation corpus...", spinner="dots"):
        corpus = load_evaluation_corpus(total_target_size=corpus_size)

    n_phish = len(corpus.phishing_samples)
    n_ham = len(corpus.ham_samples)
    n_bench = len(corpus.hand_labelled_samples)
    console.print(
        f"[green][+] Corpus Loaded:[/green] {len(corpus)} total emails "
        f"([red]{n_phish} Phishing[/red], [blue]{n_ham} Ham[/blue], [yellow]{n_bench} Hand-labelled ground truth[/yellow])"
    )

    # 2. Evaluate IOC Extraction
    with console.status("[cyan]Evaluating IOC extraction precision and recall...", spinner="dots"):
        whitelist = WhitelistPolicy.load()
        ioc_res = evaluate_ioc_extraction(corpus.hand_labelled_samples, whitelist=whitelist)

    # Print IOC extraction table
    ioc_table = Table(title="IOC Extraction Performance (Hand-Labelled Ground Truth)", border_style="cyan")
    ioc_table.add_column("Category", style="cyan", no_wrap=True)
    ioc_table.add_column("Expected", justify="right")
    ioc_table.add_column("Extracted", justify="right")
    ioc_table.add_column("TP", justify="right", style="green")
    ioc_table.add_column("FP", justify="right", style="red")
    ioc_table.add_column("FN", justify="right", style="yellow")
    ioc_table.add_column("Precision", justify="right", style="bold")
    ioc_table.add_column("Recall", justify="right", style="bold")
    ioc_table.add_column("F1-Score", justify="right", style="bold magenta")

    for cat_name, m in ioc_res.categories.items():
        ioc_table.add_row(
            cat_name.upper(),
            str(m.total_expected),
            str(m.total_extracted),
            str(m.true_positives),
            str(m.false_positives),
            str(m.false_negatives),
            f"{m.precision * 100:.1f}%",
            f"{m.recall * 100:.1f}%",
            f"{m.f1_score * 100:.1f}%",
        )
    ov = ioc_res.overall_metrics
    ioc_table.add_row(
        "[bold]OVERALL[/bold]",
        f"[bold]{ov.total_expected}[/bold]",
        f"[bold]{ov.total_extracted}[/bold]",
        f"[bold]{ov.true_positives}[/bold]",
        f"[bold]{ov.false_positives}[/bold]",
        f"[bold]{ov.false_negatives}[/bold]",
        f"[bold]{ov.precision * 100:.1f}%[/bold]",
        f"[bold]{ov.recall * 100:.1f}%[/bold]",
        f"[bold]{ov.f1_score * 100:.1f}%[/bold]",
    )
    console.print(ioc_table)

    # 3. Evaluate Risk Scoring
    with console.status("[cyan]Computing risk score distributions and ROC/PR curves...", spinner="dots"):
        scorer = RiskScorer()
        scoring_res = evaluate_scoring(corpus.samples, scorer=scorer)

    # Print Score Distribution Table
    score_table = Table(title="Risk Score Distribution & Statistical Separation", border_style="green")
    score_table.add_column("Class", style="bold")
    score_table.add_column("Count", justify="right")
    score_table.add_column("Mean", justify="right")
    score_table.add_column("Median", justify="right")
    score_table.add_column("Std", justify="right")
    score_table.add_column("Q25", justify="right")
    score_table.add_column("Q75", justify="right")
    score_table.add_column("IQR", justify="right")

    score_table.add_row(
        "[blue]Ham (SpamAssassin)[/blue]",
        str(scoring_res.ham_stats.count),
        f"{scoring_res.ham_stats.mean:.1f}",
        f"{scoring_res.ham_stats.median:.1f}",
        f"{scoring_res.ham_stats.std:.1f}",
        f"{scoring_res.ham_stats.q25:.1f}",
        f"{scoring_res.ham_stats.q75:.1f}",
        f"{scoring_res.ham_stats.iqr:.1f}",
    )
    score_table.add_row(
        "[red]Phishing (phishing_pot)[/red]",
        str(scoring_res.phishing_stats.count),
        f"{scoring_res.phishing_stats.mean:.1f}",
        f"{scoring_res.phishing_stats.median:.1f}",
        f"{scoring_res.phishing_stats.std:.1f}",
        f"{scoring_res.phishing_stats.q25:.1f}",
        f"{scoring_res.phishing_stats.q75:.1f}",
        f"{scoring_res.phishing_stats.iqr:.1f}",
    )
    console.print(score_table)
    console.print(
        f"[bold green][+] Discrimination Power:[/bold green] Cohen's d = [bold]{scoring_res.cohens_d:.2f}[/bold] | "
        f"Rule-Based ROC-AUC = [bold cyan]{scoring_res.roc_auc:.4f}[/bold cyan] | "
        f"PR-AUC = [bold magenta]{scoring_res.pr_auc:.4f}[/bold magenta]"
    )

    # 4. Train & Evaluate ML Baseline
    with console.status("[cyan]Training TF-IDF + Header-Feature Logistic Regression (5-Fold CV)...", spinner="dots"):
        ml_res = evaluate_ml_baseline(corpus.samples, scoring_res.all_scores)

    # Print Comparison Table
    comp_table = Table(title="Model Benchmark Comparison: Rule-Based vs ML vs Ensemble", border_style="magenta")
    comp_table.add_column("Model Architecture", style="bold")
    comp_table.add_column("Accuracy", justify="right")
    comp_table.add_column("Precision", justify="right")
    comp_table.add_column("Recall", justify="right")
    comp_table.add_column("F1-Score", justify="right")
    comp_table.add_column("ROC-AUC", justify="right", style="cyan")
    comp_table.add_column("PR-AUC", justify="right", style="magenta")

    comp_table.add_row(
        f"MailIntel Rule-Based (Thresh {scoring_res.optimal_threshold:.1f})",
        f"{scoring_res.optimal_metrics.accuracy * 100:.2f}%",
        f"{scoring_res.optimal_metrics.precision * 100:.2f}%",
        f"{scoring_res.optimal_metrics.recall * 100:.2f}%",
        f"{scoring_res.optimal_metrics.f1_score * 100:.2f}%",
        f"{scoring_res.roc_auc:.4f}",
        f"{scoring_res.pr_auc:.4f}",
    )
    comp_table.add_row(
        "MailIntel Rule-Based (Default 50.0)",
        f"{scoring_res.default_50_metrics.accuracy * 100:.2f}%",
        f"{scoring_res.default_50_metrics.precision * 100:.2f}%",
        f"{scoring_res.default_50_metrics.recall * 100:.2f}%",
        f"{scoring_res.default_50_metrics.f1_score * 100:.2f}%",
        f"{scoring_res.roc_auc:.4f}",
        f"{scoring_res.pr_auc:.4f}",
    )
    comp_table.add_row(
        "TF-IDF + Header Logistic Regression",
        f"{ml_res.ml_baseline_metrics.accuracy * 100:.2f}%",
        f"{ml_res.ml_baseline_metrics.precision * 100:.2f}%",
        f"{ml_res.ml_baseline_metrics.recall * 100:.2f}%",
        f"{ml_res.ml_baseline_metrics.f1_score * 100:.2f}%",
        f"{ml_res.ml_baseline_metrics.roc_auc:.4f}",
        f"{ml_res.ml_baseline_metrics.pr_auc:.4f}",
    )
    comp_table.add_row(
        "[bold]Hybrid Ensemble (Rule + ML)[/bold]",
        f"[bold]{ml_res.ensemble_metrics.accuracy * 100:.2f}%[/bold]",
        f"[bold]{ml_res.ensemble_metrics.precision * 100:.2f}%[/bold]",
        f"[bold]{ml_res.ensemble_metrics.recall * 100:.2f}%[/bold]",
        f"[bold]{ml_res.ensemble_metrics.f1_score * 100:.2f}%[/bold]",
        f"[bold]{ml_res.ensemble_metrics.roc_auc:.4f}[/bold]",
        f"[bold]{ml_res.ensemble_metrics.pr_auc:.4f}[/bold]",
    )
    console.print(comp_table)

    # 5. Error & False-Positive Analysis
    with console.status("[cyan]Running false-positive and evasion analysis...", spinner="dots"):
        error_res = analyze_errors(scoring_res.sample_details, threshold=scoring_res.optimal_threshold)

    console.print(
        f"[bold yellow][+] Error Analysis:[/bold yellow] At threshold {scoring_res.optimal_threshold:.1f}, "
        f"False Positives = {error_res.false_positives_count} ({error_res.fp_rate * 100:.1f}%), "
        f"False Negatives = {error_res.false_negatives_count} ({error_res.fn_rate * 100:.1f}%)"
    )

    # 6. Generate Figures
    figure_paths: list[Path] = []
    if generate_plots:
        with console.status("[cyan]Rendering publication figures with Matplotlib (300 DPI)...", spinner="dots"):
            figure_paths = generate_all_plots(
                scoring_res=scoring_res,
                ioc_res=ioc_res,
                ml_res=ml_res,
                output_dir=out_dir,
            )
        console.print(f"[bold green][+] Generated {len(figure_paths)} Publication Figures in {out_dir}[/bold green]")
        for fp in figure_paths:
            console.print(f"  - {fp.name}")

    # 7. Generate Evaluation Report & Results Tables
    with console.status("[cyan]Writing evaluation report markdown and results tables...", spinner="dots"):
        artifacts = generate_evaluation_artifacts(
            scoring_res=scoring_res,
            ioc_res=ioc_res,
            ml_res=ml_res,
            error_res=error_res,
            figure_paths=figure_paths,
            output_dir=out_dir,
        )

    console.print(f"\n[bold green][+] Evaluation Complete! Artifacts written to {out_dir}:[/bold green]")
    for name, path in artifacts.items():
        console.print(f"  - [bold cyan]{name}[/bold cyan]: {path}")

    return {
        "scoring": scoring_res,
        "ioc": ioc_res,
        "ml": ml_res,
        "error": error_res,
        "artifacts": artifacts,
        "figures": figure_paths,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="MailIntel Empirical Evaluation Harness")
    parser.add_argument("--corpus-size", type=int, default=150, help="Total sample count to load")
    parser.add_argument("--output-dir", type=Path, default=None, help="Directory to save report and plots")
    parser.add_argument("--no-plots", action="store_true", help="Skip rendering plots")
    args = parser.parse_args()

    run_pipeline(
        corpus_size=args.corpus_size,
        output_dir=args.output_dir,
        generate_plots=not args.no_plots,
    )


if __name__ == "__main__":
    main()
