"""
evaluation
==========
Evaluation harness for MailIntel DFIR platform.
Evaluates IOC extraction precision/recall against hand-labelled ground truth,
score distribution for phishing vs ham, ROC and PR curves, false-positive analysis,
and comparison against a TF-IDF + header-feature logistic regression baseline.
"""
from __future__ import annotations

from .dataset import EvaluationCorpus, EvaluationSample, load_evaluation_corpus
from .ioc_evaluator import IocEvaluationResult, evaluate_ioc_extraction
from .ml_baseline import MLBaselineModel, evaluate_ml_baseline
from .scoring_evaluator import ScoringEvaluationResult, evaluate_scoring

__all__ = [
    "EvaluationCorpus",
    "EvaluationSample",
    "IocEvaluationResult",
    "MLBaselineModel",
    "ScoringEvaluationResult",
    "evaluate_ioc_extraction",
    "evaluate_ml_baseline",
    "evaluate_scoring",
    "load_evaluation_corpus",
]
