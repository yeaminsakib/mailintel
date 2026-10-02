"""
Explainable risk scoring engine (Phase 3).

Public API
----------
RiskScorer
    The main scorer — initialise once, call ``score_ioc`` / ``score_email``.
ScoreFactor
    One factor's contribution to a score.
IocScore / EmailScore
    Aggregated result with breakdown.
"""
from .risk_score import EmailScore, IocScore, RiskScorer, ScoreFactor

__all__ = [
    "EmailScore",
    "IocScore",
    "RiskScorer",
    "ScoreFactor",
]
