"""
evaluation/scoring_evaluator.py
===============================
Evaluates MailIntel explainable risk scores over labelled phishing and ham corpora.
Computes score distribution statistics, ROC curves (AUROC), and PR curves (AUPRC).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)

from core.parser.eml_parser import parse_eml_bytes
from core.scoring.risk_score import RiskScorer

from .dataset import EvaluationSample

logger = logging.getLogger(__name__)


@dataclass
class DistributionStats:
    """Descriptive statistics for a set of scores."""

    count: int
    mean: float
    median: float
    std: float
    min: float
    max: float
    q10: float
    q25: float
    q75: float
    q90: float
    iqr: float

    @classmethod
    def from_scores(cls, scores: list[float]) -> DistributionStats:
        if not scores:
            return cls(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        arr = np.array(scores)
        q25, q75 = float(np.percentile(arr, 25)), float(np.percentile(arr, 75))
        return cls(
            count=len(scores),
            mean=round(float(np.mean(arr)), 2),
            median=round(float(np.median(arr)), 2),
            std=round(float(np.std(arr)), 2),
            min=round(float(np.min(arr)), 2),
            max=round(float(np.max(arr)), 2),
            q10=round(float(np.percentile(arr, 10)), 2),
            q25=round(q25, 2),
            q75=round(q75, 2),
            q90=round(float(np.percentile(arr, 90)), 2),
            iqr=round(q75 - q25, 2),
        )


@dataclass
class ThresholdMetrics:
    """Classification performance at a specific score threshold."""

    threshold: float
    tp: int
    fp: int
    tn: int
    fn: int
    accuracy: float
    precision: float
    recall: float
    specificity: float
    f1_score: float


@dataclass
class ScoringEvaluationResult:
    """Complete evaluation results for the scoring engine."""

    total_samples: int
    phishing_stats: DistributionStats
    ham_stats: DistributionStats
    cohens_d: float
    roc_auc: float
    pr_auc: float
    fpr_values: list[float]
    tpr_values: list[float]
    precision_values: list[float]
    recall_values: list[float]
    optimal_threshold: float
    optimal_metrics: ThresholdMetrics
    default_50_metrics: ThresholdMetrics
    all_scores: list[float]
    all_labels: list[int]
    sample_details: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_samples": self.total_samples,
            "phishing_distribution": {
                "count": self.phishing_stats.count,
                "mean": self.phishing_stats.mean,
                "median": self.phishing_stats.median,
                "std": self.phishing_stats.std,
                "min": self.phishing_stats.min,
                "max": self.phishing_stats.max,
                "q25": self.phishing_stats.q25,
                "q75": self.phishing_stats.q75,
                "iqr": self.phishing_stats.iqr,
            },
            "ham_distribution": {
                "count": self.ham_stats.count,
                "mean": self.ham_stats.mean,
                "median": self.ham_stats.median,
                "std": self.ham_stats.std,
                "min": self.ham_stats.min,
                "max": self.ham_stats.max,
                "q25": self.ham_stats.q25,
                "q75": self.ham_stats.q75,
                "iqr": self.ham_stats.iqr,
            },
            "cohens_d_effect_size": round(self.cohens_d, 3),
            "roc_auc": round(self.roc_auc, 4),
            "pr_auc": round(self.pr_auc, 4),
            "optimal_threshold": self.optimal_threshold,
            "metrics_at_optimal_threshold": {
                "threshold": self.optimal_metrics.threshold,
                "accuracy": round(self.optimal_metrics.accuracy, 4),
                "precision": round(self.optimal_metrics.precision, 4),
                "recall": round(self.optimal_metrics.recall, 4),
                "f1_score": round(self.optimal_metrics.f1_score, 4),
                "tp": self.optimal_metrics.tp,
                "fp": self.optimal_metrics.fp,
                "tn": self.optimal_metrics.tn,
                "fn": self.optimal_metrics.fn,
            },
            "metrics_at_default_50": {
                "threshold": self.default_50_metrics.threshold,
                "accuracy": round(self.default_50_metrics.accuracy, 4),
                "precision": round(self.default_50_metrics.precision, 4),
                "recall": round(self.default_50_metrics.recall, 4),
                "f1_score": round(self.default_50_metrics.f1_score, 4),
                "tp": self.default_50_metrics.tp,
                "fp": self.default_50_metrics.fp,
                "tn": self.default_50_metrics.tn,
                "fn": self.default_50_metrics.fn,
            },
        }


def _score_sample(sample: EvaluationSample, scorer: RiskScorer) -> tuple[float, list[Any], list[str]]:
    """Parse and calculate risk score for a single sample."""
    try:
        raw_bytes = sample.raw_eml.encode("utf-8")
        parsed = parse_eml_bytes(raw_bytes)

        # 1. Auth dictionary
        auth_dict = {
            "spf": parsed.auth_results.spf,
            "dkim": parsed.auth_results.dkim,
            "dmarc": parsed.auth_results.dmarc,
        }

        # 2. Attachments
        attach_list = [
            {"filename": a.filename, "mime_type": a.mime_type}
            for a in parsed.attachments
        ]

        # 3. IOC scores
        ioc_scores = {}
        for url in parsed.urls:
            ioc_scores[url] = scorer.score_ioc("url", url)
            try:
                from urllib.parse import urlparse
                dom = (urlparse(url).hostname or "").strip().lower()
                if dom:
                    ioc_scores[dom] = scorer.score_ioc("domain", dom)
            except Exception:
                pass

        if "@" in parsed.headers.from_addr:
            from_dom = parsed.headers.from_addr.split("@", 1)[-1].strip().lower()
            if from_dom:
                ioc_scores[from_dom] = scorer.score_ioc("domain", from_dom)

        for hop in parsed.received_chain:
            if hop.from_ip and hop.is_external:
                ioc_scores[hop.from_ip] = scorer.score_ioc("ipv4", hop.from_ip)

        # 4. Email score
        email_score = scorer.score_email(
            auth_results=auth_dict,
            from_addr=parsed.headers.from_addr,
            reply_to=parsed.headers.reply_to,
            attachments=attach_list,
            ioc_scores=ioc_scores,
            urls=parsed.urls,
        )

        return email_score.score, email_score.breakdown, email_score.behaviour_tags
    except Exception as exc:
        logger.warning("Failed scoring sample %s: %s", sample.sample_id, exc)
        return 0.0, [], []


def _compute_metrics_at_threshold(y_true: np.ndarray, y_scores: np.ndarray, threshold: float) -> ThresholdMetrics:
    """Calculate confusion matrix and rates at a given threshold."""
    y_pred = (y_scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    accuracy = (tp + tn) / len(y_true) if len(y_true) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 1.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return ThresholdMetrics(
        threshold=threshold,
        tp=int(tp),
        fp=int(fp),
        tn=int(tn),
        fn=int(fn),
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        specificity=specificity,
        f1_score=f1,
    )


def evaluate_scoring(
    samples: list[EvaluationSample],
    scorer: RiskScorer | None = None,
) -> ScoringEvaluationResult:
    """Run full scoring evaluation over all corpus samples.

    Parameters
    ----------
    samples : list[EvaluationSample]
        Corpus containing positive (phishing) and negative (ham) samples.
    scorer : RiskScorer or None
        Risk scorer instance. Defaults to default RiskScorer.

    Returns
    -------
    ScoringEvaluationResult
    """
    if scorer is None:
        scorer = RiskScorer()

    scores: list[float] = []
    labels: list[int] = []
    sample_details: list[dict[str, Any]] = []

    for s in samples:
        sc, breakdown, tags = _score_sample(s, scorer)
        scores.append(sc)
        labels.append(s.label)
        sample_details.append({
            "sample_id": s.sample_id,
            "label": s.label,
            "source": s.source,
            "score": sc,
            "breakdown": [(f.factor, f.points, f.reason) for f in breakdown],
            "behaviour_tags": tags,
        })

    y_true = np.array(labels)
    y_scores = np.array(scores)

    phish_scores = [sc for sc, lb in zip(scores, labels, strict=False) if lb == 1]
    ham_scores = [sc for sc, lb in zip(scores, labels, strict=False) if lb == 0]

    p_stats = DistributionStats.from_scores(phish_scores)
    h_stats = DistributionStats.from_scores(ham_scores)

    # Cohen's d effect size
    pooled_std = np.sqrt(((p_stats.std ** 2) + (h_stats.std ** 2)) / 2.0)
    cohens_d = (p_stats.mean - h_stats.mean) / pooled_std if pooled_std > 0 else 0.0

    # ROC Curve & AUROC
    # Normalize scores to [0, 1] for probabilities
    norm_scores = y_scores / 100.0
    if len(np.unique(y_true)) > 1:
        roc_auc = float(roc_auc_score(y_true, norm_scores))
        fpr, tpr, roc_thresh = roc_curve(y_true, norm_scores)
        pr_auc = float(average_precision_score(y_true, norm_scores))
        prec, rec, pr_thresh = precision_recall_curve(y_true, norm_scores)
    else:
        roc_auc = 1.0
        pr_auc = 1.0
        fpr, tpr = np.array([0.0, 1.0]), np.array([1.0, 1.0])
        prec, rec = np.array([1.0, 0.0]), np.array([0.0, 1.0])

    # Find optimal threshold using Youden's Index (J = TPR - FPR)
    # Search over threshold values from 5 to 95 in steps of 2.5
    best_j = -1.0
    optimal_thresh = 50.0
    for cand in np.arange(10.0, 90.0, 2.5):
        m = _compute_metrics_at_threshold(y_true, y_scores, cand)
        j_val = m.recall - (1.0 - m.specificity)
        if j_val > best_j:
            best_j = j_val
            optimal_thresh = cand

    optimal_metrics = _compute_metrics_at_threshold(y_true, y_scores, optimal_thresh)
    default_50_metrics = _compute_metrics_at_threshold(y_true, y_scores, 50.0)

    return ScoringEvaluationResult(
        total_samples=len(samples),
        phishing_stats=p_stats,
        ham_stats=h_stats,
        cohens_d=cohens_d,
        roc_auc=roc_auc,
        pr_auc=pr_auc,
        fpr_values=[float(x) for x in fpr],
        tpr_values=[float(x) for x in tpr],
        precision_values=[float(x) for x in prec],
        recall_values=[float(x) for x in rec],
        optimal_threshold=optimal_thresh,
        optimal_metrics=optimal_metrics,
        default_50_metrics=default_50_metrics,
        all_scores=scores,
        all_labels=labels,
        sample_details=sample_details,
    )
