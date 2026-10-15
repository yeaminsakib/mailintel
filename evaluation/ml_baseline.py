"""
evaluation/ml_baseline.py
=========================
TF-IDF + Header-Feature Logistic Regression baseline model.
Provides a statistical machine learning benchmark to compare against MailIntel's
rule-based explainable risk scoring model.
"""
from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler

from core.parser.eml_parser import parse_eml_bytes

from .dataset import EvaluationSample

logger = logging.getLogger(__name__)

_URGENCY_PATTERN = re.compile(
    r"\b(urgent|immediate|suspended?|locked?|action required|verify|confirm|security alert|fraud|wire|unauthorized|decline|overdue|invoice)\b",
    re.IGNORECASE,
)
_DANGEROUS_EXTS = {".exe", ".scr", ".pif", ".bat", ".cmd", ".vbs", ".js", ".docm", ".xlsm", ".pptm", ".iso", ".img"}


@dataclass
class ModelMetrics:
    """Standard evaluation metrics for binary classification."""

    model_name: str
    roc_auc: float
    pr_auc: float
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    brier_score: float
    tp: int
    fp: int
    tn: int
    fn: int


@dataclass
class MLComparisonResult:
    """Comparison results between Rule-Based Scorer, ML Baseline, and Ensemble."""

    rule_based_metrics: ModelMetrics
    ml_baseline_metrics: ModelMetrics
    ensemble_metrics: ModelMetrics
    ml_fpr: list[float]
    ml_tpr: list[float]
    ml_prec: list[float]
    ml_rec: list[float]
    top_phishing_features: list[tuple[str, float]]
    top_ham_features: list[tuple[str, float]]
    feature_names: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "comparison": {
                "rule_based": {
                    "accuracy": round(self.rule_based_metrics.accuracy, 4),
                    "precision": round(self.rule_based_metrics.precision, 4),
                    "recall": round(self.rule_based_metrics.recall, 4),
                    "f1_score": round(self.rule_based_metrics.f1_score, 4),
                    "roc_auc": round(self.rule_based_metrics.roc_auc, 4),
                    "pr_auc": round(self.rule_based_metrics.pr_auc, 4),
                },
                "ml_logistic_regression": {
                    "accuracy": round(self.ml_baseline_metrics.accuracy, 4),
                    "precision": round(self.ml_baseline_metrics.precision, 4),
                    "recall": round(self.ml_baseline_metrics.recall, 4),
                    "f1_score": round(self.ml_baseline_metrics.f1_score, 4),
                    "roc_auc": round(self.ml_baseline_metrics.roc_auc, 4),
                    "pr_auc": round(self.ml_baseline_metrics.pr_auc, 4),
                },
                "hybrid_ensemble": {
                    "accuracy": round(self.ensemble_metrics.accuracy, 4),
                    "precision": round(self.ensemble_metrics.precision, 4),
                    "recall": round(self.ensemble_metrics.recall, 4),
                    "f1_score": round(self.ensemble_metrics.f1_score, 4),
                    "roc_auc": round(self.ensemble_metrics.roc_auc, 4),
                    "pr_auc": round(self.ensemble_metrics.pr_auc, 4),
                },
            },
            "top_phishing_features": [
                {"feature": feat, "weight": round(float(w), 4)}
                for feat, w in self.top_phishing_features[:15]
            ],
            "top_ham_features": [
                {"feature": feat, "weight": round(float(w), 4)}
                for feat, w in self.top_ham_features[:15]
            ],
        }


HEADER_FEATURE_NAMES = [
    "hdr_spf_failed",
    "hdr_dkim_failed",
    "hdr_dmarc_failed",
    "hdr_reply_to_mismatch",
    "hdr_has_attachments",
    "hdr_has_dangerous_attachment",
    "hdr_num_urls",
    "hdr_num_received_hops",
    "hdr_has_external_origin",
    "hdr_subject_urgency",
    "hdr_subject_caps_ratio",
    "hdr_log_body_length",
]


def _extract_features_for_sample(sample: EvaluationSample) -> tuple[str, list[float]]:
    """Extract raw text and dense numerical header features from an email sample."""
    try:
        raw_bytes = sample.raw_eml.encode("utf-8")
        parsed = parse_eml_bytes(raw_bytes)

        # 1. Text payload (subject + body)
        text = f"{parsed.headers.subject} {parsed.body_plain} {parsed.body_html}".strip()

        # 2. Header / forensic signals
        spf_fail = 1.0 if parsed.auth_results.spf in ("fail", "softfail") else 0.0
        dkim_fail = 1.0 if parsed.auth_results.dkim in ("fail", "none") else 0.0
        dmarc_fail = 1.0 if parsed.auth_results.dmarc == "fail" else 0.0

        # Reply-To mismatch
        from_dom = parsed.headers.from_addr.split("@", 1)[-1].strip().lower() if "@" in parsed.headers.from_addr else ""
        reply_dom = parsed.headers.reply_to.split("@", 1)[-1].strip().lower() if "@" in parsed.headers.reply_to else ""
        mismatch = 1.0 if (reply_dom and from_dom and reply_dom != from_dom) else 0.0

        has_attach = 1.0 if len(parsed.attachments) > 0 else 0.0
        has_danger_attach = 0.0
        for a in parsed.attachments:
            ext = "." + a.filename.split(".")[-1].lower() if "." in a.filename else ""
            if ext in _DANGEROUS_EXTS or a.mime_type in ("application/x-dosexec", "application/x-executable"):
                has_danger_attach = 1.0
                break

        num_urls = float(len(parsed.urls))
        num_hops = float(len(parsed.received_chain))
        has_ext_hop = 1.0 if parsed.first_external_hop is not None else 0.0

        subj = parsed.headers.subject
        urgency = 1.0 if _URGENCY_PATTERN.search(subj) else 0.0
        caps_count = sum(1 for c in subj if c.isupper())
        caps_ratio = (caps_count / len(subj)) if len(subj) > 0 else 0.0
        log_len = math.log1p(len(parsed.body_plain))

        header_vec = [
            spf_fail,
            dkim_fail,
            dmarc_fail,
            mismatch,
            has_attach,
            has_danger_attach,
            num_urls,
            num_hops,
            has_ext_hop,
            urgency,
            caps_ratio,
            log_len,
        ]

        return text, header_vec
    except Exception as exc:
        logger.warning("Error extracting features for %s: %s", sample.sample_id, exc)
        return "", [0.0] * len(HEADER_FEATURE_NAMES)


def _compute_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float, model_name: str) -> ModelMetrics:
    """Compute standard metrics for probability scores."""
    y_pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    accuracy = float((tp + tn) / len(y_true))
    precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 1.0
    recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    brier = float(np.mean((y_prob - y_true) ** 2))

    if len(np.unique(y_true)) > 1:
        roc_auc = float(roc_auc_score(y_true, y_prob))
        pr_auc = float(average_precision_score(y_true, y_prob))
    else:
        roc_auc = 1.0
        pr_auc = 1.0

    return ModelMetrics(
        model_name=model_name,
        roc_auc=roc_auc,
        pr_auc=pr_auc,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1_score=f1,
        brier_score=brier,
        tp=int(tp),
        fp=int(fp),
        tn=int(tn),
        fn=int(fn),
    )


class MLBaselineModel:
    """TF-IDF + Header Logistic Regression Baseline model."""

    def __init__(self, max_features: int = 250, c_param: float = 1.0) -> None:
        self.vectorizer = TfidfVectorizer(
            max_features=max_features,
            stop_words="english",
            ngram_range=(1, 2),
            sublinear_tf=True,
        )
        self.scaler = StandardScaler()
        self.classifier = LogisticRegression(C=c_param, max_iter=1000, random_state=42)
        self.feature_names: list[str] = []

    def fit_and_evaluate_cv(
        self,
        samples: list[EvaluationSample],
        n_splits: int = 5,
    ) -> tuple[np.ndarray, np.ndarray, list[tuple[str, float]], list[tuple[str, float]]]:
        """Perform Stratified K-Fold CV and extract feature importances."""
        texts: list[str] = []
        headers: list[list[float]] = []
        labels: list[int] = []

        for s in samples:
            t, h = _extract_features_for_sample(s)
            texts.append(t)
            headers.append(h)
            labels.append(s.label)

        y = np.array(labels)
        H_dense = np.array(headers)

        # 1. TF-IDF feature matrix
        X_tfidf = self.vectorizer.fit_transform(texts)
        tfidf_names = list(self.vectorizer.get_feature_names_out())

        # 2. Dense header feature scaling
        H_scaled = self.scaler.fit_transform(H_dense)
        H_sparse = sparse.csr_matrix(H_scaled)

        # 3. Stack combined feature matrix
        X_all = sparse.hstack([X_tfidf, H_sparse]).tocsr()
        self.feature_names = tfidf_names + HEADER_FEATURE_NAMES

        # 4. Out-of-fold cross-validation predictions
        oof_preds = np.zeros(len(y))
        cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

        for train_idx, val_idx in cv.split(X_all, y):
            X_tr, y_tr = X_all[train_idx], y[train_idx]
            X_va = X_all[val_idx]
            fold_clf = LogisticRegression(C=1.0, max_iter=1000, random_state=42)
            fold_clf.fit(X_tr, y_tr)
            probs = fold_clf.predict_proba(X_va)[:, 1]
            oof_preds[val_idx] = probs

        # 5. Fit full model to extract interpretable coefficients
        self.classifier.fit(X_all, y)
        coefs = self.classifier.coef_[0]

        feature_weights = list(zip(self.feature_names, coefs, strict=False))
        top_phishing = sorted(feature_weights, key=lambda x: x[1], reverse=True)
        top_ham = sorted(feature_weights, key=lambda x: x[1])

        return y, oof_preds, top_phishing, top_ham


def evaluate_ml_baseline(
    samples: list[EvaluationSample],
    rule_scores: list[float],
) -> MLComparisonResult:
    """Train and evaluate the ML baseline, comparing it directly against the rule-based scorer.

    Parameters
    ----------
    samples : list[EvaluationSample]
        Corpus samples.
    rule_scores : list[float]
        Precomputed MailIntel risk scores (0-100) for each sample.

    Returns
    -------
    MLComparisonResult
    """
    model = MLBaselineModel()
    y_true, ml_probs, top_phish, top_ham = model.fit_and_evaluate_cv(samples, n_splits=5)

    # Normalized rule probabilities
    rule_probs = np.clip(np.array(rule_scores) / 100.0, 0.0, 1.0)

    # Hybrid ensemble: 50% Rule-Based + 50% ML
    ensemble_probs = (0.5 * rule_probs) + (0.5 * ml_probs)

    # Compute metrics for each approach
    rule_metrics = _compute_metrics(y_true, rule_probs, threshold=0.50, model_name="MailIntel Rule-Based Scorer")
    ml_metrics = _compute_metrics(y_true, ml_probs, threshold=0.50, model_name="TF-IDF + Header Logistic Regression")
    ensemble_metrics = _compute_metrics(y_true, ensemble_probs, threshold=0.50, model_name="Hybrid Ensemble (Rule + ML)")

    # ROC / PR curve points for ML baseline
    if len(np.unique(y_true)) > 1:
        fpr, tpr, _ = roc_curve(y_true, ml_probs)
        prec, rec, _ = precision_recall_curve(y_true, ml_probs)
    else:
        fpr, tpr = np.array([0.0, 1.0]), np.array([1.0, 1.0])
        prec, rec = np.array([1.0, 0.0]), np.array([0.0, 1.0])

    return MLComparisonResult(
        rule_based_metrics=rule_metrics,
        ml_baseline_metrics=ml_metrics,
        ensemble_metrics=ensemble_metrics,
        ml_fpr=[float(x) for x in fpr],
        ml_tpr=[float(x) for x in tpr],
        ml_prec=[float(x) for x in prec],
        ml_rec=[float(x) for x in rec],
        top_phishing_features=top_phish,
        top_ham_features=top_ham,
        feature_names=model.feature_names,
    )
