"""
evaluation/ioc_evaluator.py
===========================
Evaluates MailIntel IOC extraction accuracy (precision, recall, F1-score)
against human-annotated ground-truth benchmark samples.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

from core.ioc.extractors import (
    extract_email_addresses,
    extract_ipv4,
    extract_urls,
)
from core.ioc.whitelist import WhitelistPolicy
from core.parser.eml_parser import parse_eml_bytes

from .dataset import EvaluationSample

logger = logging.getLogger(__name__)


@dataclass
class IocCategoryMetrics:
    """Precision, recall, and F1 metrics for a single IOC category."""

    category: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def total_expected(self) -> int:
        return self.true_positives + self.false_negatives

    @property
    def total_extracted(self) -> int:
        return self.true_positives + self.false_positives

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return (self.true_positives / denom) if denom > 0 else 1.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return (self.true_positives / denom) if denom > 0 else 1.0

    @property
    def f1_score(self) -> float:
        p = self.precision
        r = self.recall
        return (2 * p * r / (p + r)) if (p + r) > 0 else 0.0


@dataclass
class IocEvaluationResult:
    """Overall evaluation result across all IOC categories and samples."""

    total_samples: int
    categories: dict[str, IocCategoryMetrics] = field(default_factory=dict)
    sample_details: list[dict] = field(default_factory=list)

    @property
    def overall_metrics(self) -> IocCategoryMetrics:
        tp = sum(m.true_positives for m in self.categories.values())
        fp = sum(m.false_positives for m in self.categories.values())
        fn = sum(m.false_negatives for m in self.categories.values())
        return IocCategoryMetrics(
            category="overall",
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
        )

    def to_dict(self) -> dict:
        cat_dict = {}
        for name, m in self.categories.items():
            cat_dict[name] = {
                "tp": m.true_positives,
                "fp": m.false_positives,
                "fn": m.false_negatives,
                "precision": round(m.precision, 4),
                "recall": round(m.recall, 4),
                "f1": round(m.f1_score, 4),
            }
        overall = self.overall_metrics
        cat_dict["overall"] = {
            "tp": overall.true_positives,
            "fp": overall.false_positives,
            "fn": overall.false_negatives,
            "precision": round(overall.precision, 4),
            "recall": round(overall.recall, 4),
            "f1": round(overall.f1_score, 4),
        }
        return {
            "total_samples": self.total_samples,
            "categories": cat_dict,
        }


def _extract_iocs_from_sample(sample: EvaluationSample, whitelist: WhitelistPolicy | None = None) -> dict[str, set[str]]:
    """Run MailIntel's full extraction pipeline on a raw EML sample."""
    extracted: dict[str, set[str]] = {
        "ipv4": set(),
        "domain": set(),
        "url": set(),
        "email": set(),
    }

    raw_bytes = sample.raw_eml.encode("utf-8")
    parsed = parse_eml_bytes(raw_bytes)

    # 1. Received Hops & Body IPv4
    for hop in parsed.received_chain:
        if hop.from_ip and hop.is_external and ":" not in hop.from_ip:
            extracted["ipv4"].add(hop.from_ip.strip())

    for ip in extract_ipv4(parsed.body_plain):
        extracted["ipv4"].add(ip.strip())

    # 2. URLs (from body HTML/text)
    for u in parsed.urls:
        clean_u = u.strip()
        if clean_u:
            extracted["url"].add(clean_u)
            # Pull domain from URL
            try:
                parsed_u = urlparse(clean_u)
                dom = (parsed_u.hostname or "").lower().strip()
                if dom and not (whitelist and whitelist.is_whitelisted(dom, context="body_url")):
                    extracted["domain"].add(dom)
            except Exception:
                pass

    # Also extract plain text URLs if parser missed any
    for u in extract_urls(parsed.body_plain):
        clean_u = u.strip()
        if clean_u:
            extracted["url"].add(clean_u)
            try:
                parsed_u = urlparse(clean_u)
                dom = (parsed_u.hostname or "").lower().strip()
                if dom and not (whitelist and whitelist.is_whitelisted(dom, context="body_url")):
                    extracted["domain"].add(dom)
            except Exception:
                pass

    # 3. Emails from headers & body
    header_str = f"{parsed.headers.from_addr} {parsed.headers.reply_to} {parsed.headers.return_path}"
    for e in extract_email_addresses(header_str):
        clean_e = e.strip().lower()
        extracted["email"].add(clean_e)
        if "@" in clean_e:
            dom = clean_e.split("@", 1)[-1]
            if dom and not (whitelist and whitelist.is_whitelisted(dom, context="sender")):
                extracted["domain"].add(dom)

    return extracted


def evaluate_ioc_extraction(
    samples: list[EvaluationSample],
    whitelist: WhitelistPolicy | None = None,
) -> IocEvaluationResult:
    """Evaluate IOC extraction against hand-labelled ground truth samples.

    Parameters
    ----------
    samples : list[EvaluationSample]
        Subset of samples that contain expected_iocs ground truth annotations.
    whitelist : WhitelistPolicy or None
        Contextual whitelist policy for domain filtering.

    Returns
    -------
    IocEvaluationResult
    """
    eval_samples = [s for s in samples if s.expected_iocs]
    if not eval_samples:
        logger.warning("No samples with expected_iocs ground truth provided to evaluator.")
        eval_samples = samples

    categories = {
        "ipv4": IocCategoryMetrics("ipv4"),
        "domain": IocCategoryMetrics("domain"),
        "url": IocCategoryMetrics("url"),
        "email": IocCategoryMetrics("email"),
    }

    sample_details = []

    for s in eval_samples:
        extracted = _extract_iocs_from_sample(s, whitelist=whitelist)
        expected = s.expected_iocs

        detail: dict = {
            "sample_id": s.sample_id,
            "label": s.label,
            "categories": {},
        }

        for cat, cat_metric in categories.items():
            actual_set = extracted.get(cat, set())
            expected_set = {v.lower().strip() for v in expected.get(cat, [])}

            # Normalize actual set for fair comparison
            norm_actual = {v.lower().strip() for v in actual_set}

            # Matching: exact or URL prefix/suffix containment
            tp_items = set()
            for exp in expected_set:
                for act in norm_actual:
                    if exp == act or (cat == "url" and (exp in act or act in exp)):
                        tp_items.add(exp)
                        break

            tp = len(tp_items)
            fn = len(expected_set) - tp
            # FP: items extracted that were not expected
            fp = max(0, len(norm_actual) - tp)

            cat_metric.true_positives += tp
            cat_metric.false_positives += fp
            cat_metric.false_negatives += fn

            detail["categories"][cat] = {
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "expected": list(expected_set),
                "extracted": list(norm_actual),
            }

        sample_details.append(detail)

    return IocEvaluationResult(
        total_samples=len(eval_samples),
        categories=categories,
        sample_details=sample_details,
    )
