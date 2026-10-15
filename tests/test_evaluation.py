"""
tests/test_evaluation.py
========================
Tests for the MailIntel evaluation harness:
- Corpus loading & ground truth validation
- IOC extraction precision/recall computation
- Risk score distribution & ROC/PR curve calculation
- TF-IDF + Header Logistic Regression baseline
- False positive & error analysis
- Matplotlib plot generation & report export
"""
from __future__ import annotations

from pathlib import Path

from evaluation.dataset import load_evaluation_corpus
from evaluation.error_analysis import analyze_errors
from evaluation.ioc_evaluator import evaluate_ioc_extraction
from evaluation.ml_baseline import evaluate_ml_baseline
from evaluation.plots import generate_all_plots
from evaluation.report_generator import generate_evaluation_artifacts
from evaluation.scoring_evaluator import evaluate_scoring


def test_load_evaluation_corpus():
    corpus = load_evaluation_corpus(total_target_size=20, include_hand_labelled=True)
    assert len(corpus) >= 20
    assert len(corpus.phishing_samples) > 0
    assert len(corpus.ham_samples) > 0
    assert len(corpus.hand_labelled_samples) >= 10

    # Verify sample properties
    sample = corpus.hand_labelled_samples[0]
    assert sample.sample_id
    assert sample.raw_eml
    assert sample.label in (0, 1)
    assert isinstance(sample.expected_iocs, dict)


def test_ioc_extraction_evaluation():
    corpus = load_evaluation_corpus(total_target_size=15, include_hand_labelled=True)
    res = evaluate_ioc_extraction(corpus.hand_labelled_samples)

    assert res.total_samples > 0
    assert "ipv4" in res.categories
    assert "url" in res.categories
    assert "email" in res.categories
    assert "domain" in res.categories

    overall = res.overall_metrics
    assert overall.true_positives > 0
    assert 0.0 <= overall.precision <= 1.0
    assert 0.0 <= overall.recall <= 1.0
    assert 0.0 <= overall.f1_score <= 1.0

    res_dict = res.to_dict()
    assert "categories" in res_dict
    assert "overall" in res_dict["categories"]


def test_scoring_evaluation():
    corpus = load_evaluation_corpus(total_target_size=24, include_hand_labelled=True)
    res = evaluate_scoring(corpus.samples)

    assert res.total_samples == len(corpus.samples)
    assert res.phishing_stats.count > 0
    assert res.ham_stats.count > 0

    # Phishing scores should average significantly higher than ham
    assert res.phishing_stats.mean > res.ham_stats.mean
    assert res.roc_auc >= 0.80
    assert res.pr_auc >= 0.80
    assert 0.0 <= res.optimal_threshold <= 100.0

    d = res.to_dict()
    assert "roc_auc" in d
    assert "pr_auc" in d
    assert "phishing_distribution" in d


def test_ml_baseline_evaluation():
    corpus = load_evaluation_corpus(total_target_size=24, include_hand_labelled=True)
    scoring_res = evaluate_scoring(corpus.samples)

    ml_res = evaluate_ml_baseline(corpus.samples, scoring_res.all_scores)

    assert ml_res.rule_based_metrics.roc_auc >= 0.80
    assert ml_res.ml_baseline_metrics.roc_auc >= 0.80
    assert ml_res.ensemble_metrics.roc_auc >= 0.80

    assert len(ml_res.top_phishing_features) > 0
    assert len(ml_res.top_ham_features) > 0

    d = ml_res.to_dict()
    assert "comparison" in d
    assert "top_phishing_features" in d


def test_error_analysis():
    corpus = load_evaluation_corpus(total_target_size=24, include_hand_labelled=True)
    scoring_res = evaluate_scoring(corpus.samples)

    error_res = analyze_errors(scoring_res.sample_details, threshold=scoring_res.optimal_threshold)

    assert error_res.total_samples == len(corpus.samples)
    assert 0.0 <= error_res.fp_rate <= 1.0
    assert 0.0 <= error_res.fn_rate <= 1.0
    assert len(error_res.case_studies) > 0

    d = error_res.to_dict()
    assert "case_studies" in d


def test_plots_and_report_artifacts(tmp_path: Path):
    corpus = load_evaluation_corpus(total_target_size=20, include_hand_labelled=True)
    ioc_res = evaluate_ioc_extraction(corpus.hand_labelled_samples)
    scoring_res = evaluate_scoring(corpus.samples)
    ml_res = evaluate_ml_baseline(corpus.samples, scoring_res.all_scores)
    error_res = analyze_errors(scoring_res.sample_details, threshold=scoring_res.optimal_threshold)

    # 1. Plots
    figs = generate_all_plots(scoring_res, ioc_res, ml_res, tmp_path)
    assert len(figs) == 5
    for f in figs:
        assert f.exists()
        assert f.stat().st_size > 0

    # 2. Artifacts
    artifacts = generate_evaluation_artifacts(
        scoring_res, ioc_res, ml_res, error_res, figs, tmp_path
    )
    assert "results_table_csv" in artifacts
    assert "results_table_md" in artifacts
    assert "ioc_metrics_csv" in artifacts
    assert "results_summary_json" in artifacts
    assert "evaluation_report_md" in artifacts

    for p in artifacts.values():
        assert p.exists()
        assert p.stat().st_size > 0
