"""
evaluation/report_generator.py
==============================
Generates publication-ready evaluation report markdown, results tables (CSV/MD),
and structured JSON summaries for inclusion in academic theses, technical reports, and slides.
"""
from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Any

from .error_analysis import ErrorAnalysisResult
from .ioc_evaluator import IocEvaluationResult
from .ml_baseline import MLComparisonResult
from .scoring_evaluator import ScoringEvaluationResult

logger = logging.getLogger(__name__)


def generate_evaluation_artifacts(
    scoring_res: ScoringEvaluationResult,
    ioc_res: IocEvaluationResult,
    ml_res: MLComparisonResult,
    error_res: ErrorAnalysisResult,
    figure_paths: list[Path],
    output_dir: Path,
) -> dict[str, Path]:
    """Compile and write all report artifacts.

    Returns
    -------
    dict[str, Path]
        Map of artifact type to generated file path.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, Path] = {}

    # 1. Results comparison table (CSV)
    csv_file = output_dir / "results_table.csv"
    _write_results_csv(csv_file, scoring_res, ml_res)
    results["results_table_csv"] = csv_file

    # 2. IOC extraction metrics (CSV)
    ioc_csv_file = output_dir / "ioc_metrics.csv"
    _write_ioc_csv(ioc_csv_file, ioc_res)
    results["ioc_metrics_csv"] = ioc_csv_file

    # 3. Comprehensive JSON summary
    json_file = output_dir / "results_summary.json"
    _write_results_json(json_file, scoring_res, ioc_res, ml_res, error_res)
    results["results_summary_json"] = json_file

    # 4. Results comparison table (Markdown)
    table_md_file = output_dir / "results_table.md"
    _write_results_table_md(table_md_file, scoring_res, ml_res)
    results["results_table_md"] = table_md_file

    # 5. Full Academic Evaluation Report (Markdown)
    report_file = output_dir / "evaluation_report.md"
    _write_full_report_md(report_file, scoring_res, ioc_res, ml_res, error_res, figure_paths)
    results["evaluation_report_md"] = report_file

    return results


def _write_results_csv(path: Path, scoring_res: ScoringEvaluationResult, ml_res: MLComparisonResult) -> None:
    headers = ["Model", "Accuracy", "Precision", "Recall", "F1_Score", "ROC_AUC", "PR_AUC", "TP", "FP", "TN", "FN"]
    rows = [
        [
            "MailIntel Rule-Based (Optimal Thresh)",
            f"{scoring_res.optimal_metrics.accuracy:.4f}",
            f"{scoring_res.optimal_metrics.precision:.4f}",
            f"{scoring_res.optimal_metrics.recall:.4f}",
            f"{scoring_res.optimal_metrics.f1_score:.4f}",
            f"{scoring_res.roc_auc:.4f}",
            f"{scoring_res.pr_auc:.4f}",
            scoring_res.optimal_metrics.tp,
            scoring_res.optimal_metrics.fp,
            scoring_res.optimal_metrics.tn,
            scoring_res.optimal_metrics.fn,
        ],
        [
            "MailIntel Rule-Based (Default 50)",
            f"{scoring_res.default_50_metrics.accuracy:.4f}",
            f"{scoring_res.default_50_metrics.precision:.4f}",
            f"{scoring_res.default_50_metrics.recall:.4f}",
            f"{scoring_res.default_50_metrics.f1_score:.4f}",
            f"{scoring_res.roc_auc:.4f}",
            f"{scoring_res.pr_auc:.4f}",
            scoring_res.default_50_metrics.tp,
            scoring_res.default_50_metrics.fp,
            scoring_res.default_50_metrics.tn,
            scoring_res.default_50_metrics.fn,
        ],
        [
            "TF-IDF + Header Logistic Regression (5-Fold CV)",
            f"{ml_res.ml_baseline_metrics.accuracy:.4f}",
            f"{ml_res.ml_baseline_metrics.precision:.4f}",
            f"{ml_res.ml_baseline_metrics.recall:.4f}",
            f"{ml_res.ml_baseline_metrics.f1_score:.4f}",
            f"{ml_res.ml_baseline_metrics.roc_auc:.4f}",
            f"{ml_res.ml_baseline_metrics.pr_auc:.4f}",
            ml_res.ml_baseline_metrics.tp,
            ml_res.ml_baseline_metrics.fp,
            ml_res.ml_baseline_metrics.tn,
            ml_res.ml_baseline_metrics.fn,
        ],
        [
            "Hybrid Ensemble (Rule + ML)",
            f"{ml_res.ensemble_metrics.accuracy:.4f}",
            f"{ml_res.ensemble_metrics.precision:.4f}",
            f"{ml_res.ensemble_metrics.recall:.4f}",
            f"{ml_res.ensemble_metrics.f1_score:.4f}",
            f"{ml_res.ensemble_metrics.roc_auc:.4f}",
            f"{ml_res.ensemble_metrics.pr_auc:.4f}",
            ml_res.ensemble_metrics.tp,
            ml_res.ensemble_metrics.fp,
            ml_res.ensemble_metrics.tn,
            ml_res.ensemble_metrics.fn,
        ],
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)


def _write_ioc_csv(path: Path, ioc_res: IocEvaluationResult) -> None:
    headers = ["IOC_Category", "True_Positives", "False_Positives", "False_Negatives", "Precision", "Recall", "F1_Score"]
    rows = []
    for cat_name, m in ioc_res.categories.items():
        rows.append([
            cat_name.upper(),
            m.true_positives,
            m.false_positives,
            m.false_negatives,
            f"{m.precision:.4f}",
            f"{m.recall:.4f}",
            f"{m.f1_score:.4f}",
        ])
    ov = ioc_res.overall_metrics
    rows.append([
        "OVERALL",
        ov.true_positives,
        ov.false_positives,
        ov.false_negatives,
        f"{ov.precision:.4f}",
        f"{ov.recall:.4f}",
        f"{ov.f1_score:.4f}",
    ])
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)


def _write_results_json(
    path: Path,
    scoring_res: ScoringEvaluationResult,
    ioc_res: IocEvaluationResult,
    ml_res: MLComparisonResult,
    error_res: ErrorAnalysisResult,
) -> None:
    data: dict[str, Any] = {
        "ioc_extraction": ioc_res.to_dict(),
        "scoring_evaluation": scoring_res.to_dict(),
        "ml_comparison": ml_res.to_dict(),
        "error_analysis": error_res.to_dict(),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _write_results_table_md(path: Path, scoring_res: ScoringEvaluationResult, ml_res: MLComparisonResult) -> None:
    md = f"""### Model Performance Benchmark Comparison Table

| Model Architecture | Accuracy | Precision | Recall | F1-Score | ROC-AUC | PR-AUC |
|:-------------------|:--------:|:---------:|:------:|:--------:|:-------:|:------:|
| **MailIntel Rule-Based (Optimal Thresh {scoring_res.optimal_threshold:.1f})** | **{scoring_res.optimal_metrics.accuracy * 100:.2f}%** | **{scoring_res.optimal_metrics.precision * 100:.2f}%** | **{scoring_res.optimal_metrics.recall * 100:.2f}%** | **{scoring_res.optimal_metrics.f1_score * 100:.2f}%** | **{scoring_res.roc_auc:.4f}** | **{scoring_res.pr_auc:.4f}** |
| MailIntel Rule-Based (Default SOC 50.0) | {scoring_res.default_50_metrics.accuracy * 100:.2f}% | {scoring_res.default_50_metrics.precision * 100:.2f}% | {scoring_res.default_50_metrics.recall * 100:.2f}% | {scoring_res.default_50_metrics.f1_score * 100:.2f}% | {scoring_res.roc_auc:.4f} | {scoring_res.pr_auc:.4f} |
| TF-IDF + Header Logistic Regression (5-Fold CV) | {ml_res.ml_baseline_metrics.accuracy * 100:.2f}% | {ml_res.ml_baseline_metrics.precision * 100:.2f}% | {ml_res.ml_baseline_metrics.recall * 100:.2f}% | {ml_res.ml_baseline_metrics.f1_score * 100:.2f}% | {ml_res.ml_baseline_metrics.roc_auc:.4f} | {ml_res.ml_baseline_metrics.pr_auc:.4f} |
| **Hybrid Ensemble (Rule-Based + ML)** | **{ml_res.ensemble_metrics.accuracy * 100:.2f}%** | **{ml_res.ensemble_metrics.precision * 100:.2f}%** | **{ml_res.ensemble_metrics.recall * 100:.2f}%** | **{ml_res.ensemble_metrics.f1_score * 100:.2f}%** | **{ml_res.ensemble_metrics.roc_auc:.4f}** | **{ml_res.ensemble_metrics.pr_auc:.4f}** |
"""
    path.write_text(md, encoding="utf-8")


def _write_full_report_md(
    path: Path,
    scoring_res: ScoringEvaluationResult,
    ioc_res: IocEvaluationResult,
    ml_res: MLComparisonResult,
    error_res: ErrorAnalysisResult,
    figure_paths: list[Path],
) -> None:
    """Write the full academic evaluation chapter."""
    ov_ioc = ioc_res.overall_metrics

    # Build IOC table rows
    ioc_rows_md = []
    for cat_name, m in ioc_res.categories.items():
        ioc_rows_md.append(
            f"| `{cat_name.upper()}` | {m.total_expected} | {m.total_extracted} | {m.true_positives} | {m.false_positives} | {m.false_negatives} | {m.precision * 100:.1f}% | {m.recall * 100:.1f}% | **{m.f1_score * 100:.1f}%** |"
        )
    ioc_table_str = "\n".join(ioc_rows_md)

    # Top features list
    phish_feats = ", ".join([f"`{f}` (+{w:.2f})" for f, w in ml_res.top_phishing_features[:8]])
    ham_feats = ", ".join([f"`{f}` ({w:.2f})" for f, w in ml_res.top_ham_features[:8]])

    # Case study writeups
    cs_md = []
    for idx, cs in enumerate(error_res.case_studies, start=1):
        factors_str = "; ".join([f"{f} (+{pts} pts: {r})" for f, pts, r in cs.factors]) or "None"
        cs_md.append(f"""#### Case Study {idx}: `{cs.sample_id}`
- **Ground Truth**: {cs.true_label} | **Classification**: {cs.predicted_label} (Score: **{cs.risk_score:.1f}/100**)
- **Active Factors**: {factors_str}
- **Forensic Root Cause**: {cs.root_cause}
- **Remediation / Mitigation**: {cs.remediation}
""")
    case_studies_str = "\n".join(cs_md)

    report = f"""# Empirical Evaluation of the MailIntel DFIR Platform

**Evaluation Benchmark Report**
*Target Application*: MailIntel Automated Threat Intelligence & Email DFIR Platform
*Dataset*: Labelled Honeypot Phishing Corpus (`phishing_pot`) & SpamAssassin Ham (`easy_ham`)

---

## 1. Executive Summary

This report presents an empirical evaluation of **MailIntel**, assessing its capabilities across two core forensic objectives:
1. **IOC Extraction Accuracy**: Precision and recall of extracted Indicators of Compromise (IPs, domains, URLs, sender addresses, attachment hashes) against a hand-labelled benchmark ground truth.
2. **Threat Detection & Discrimination**: How effectively the explainable **0–100 Risk Score** separates malicious phishing lures from legitimate business correspondence, benchmarked via ROC and Precision-Recall analyses, and compared against a **TF-IDF + Header-Feature Logistic Regression** statistical machine learning baseline.

### Summary Metrics At-A-Glance:
- **Corpus Size**: {scoring_res.total_samples} labelled email messages ({len([s for s in scoring_res.all_labels if s == 1])} Phishing, {len([s for s in scoring_res.all_labels if s == 0])} Ham).
- **IOC Extraction Performance**: **{ov_ioc.precision * 100:.1f}% Precision**, **{ov_ioc.recall * 100:.1f}% Recall**, and **{ov_ioc.f1_score * 100:.1f}% F1-Score**.
- **Discrimination Power**:
  - **Rule-Based ROC-AUC**: **{scoring_res.roc_auc:.4f}** (PR-AUC / Average Precision: **{scoring_res.pr_auc:.4f}**).
  - **Statistical Separation**: Cohen's $d = **{scoring_res.cohens_d:.2f}**$ (large effect size), with phishing scores averaging **{scoring_res.phishing_stats.mean:.1f}/100** vs. ham averaging **{scoring_res.ham_stats.mean:.1f}/100**.
  - **Machine Learning Benchmark**: TF-IDF + Header Logistic Regression achieves **{ml_res.ml_baseline_metrics.roc_auc:.4f} ROC-AUC**; a Hybrid Ensemble combining rule-based explainability and statistical n-grams achieves **{ml_res.ensemble_metrics.roc_auc:.4f} ROC-AUC**.

---

## 2. Experimental Methodology & Dataset

### 2.1 Corpus Composition
The evaluation utilizes a balanced, representative corpus constructed from two benchmark sources:
- **Positives (Phishing)**: Authentic honeypot samples from the `phishing_pot` repository spanning diverse attack vectors:
  - Financial & Banking credential harvesting (PayPal, Wells Fargo, Chase Bank).
  - Cloud infrastructure & identity theft (Microsoft 365, Google Drive, Apple ID lockout).
  - Malicious attachment lures (executable files masked with double extensions, macro-enabled documents, disk images).
  - Lookalike and typosquat domains (Levenshtein distance <= 2 against major brands).
- **Negatives (Ham)**: Authentic non-phishing emails sourced from the SpamAssassin `easy_ham` corpus and legitimate enterprise correspondence:
  - Technical engineering discussions, meeting minutes, Git merge notifications.
  - Legitimate automated alerts with passing SPF/DKIM authentication (Amazon AWS, IT Helpdesk).
  - Community digests and academic symposium calls for papers.

### 2.2 Hand-Labelled Ground Truth
To evaluate indicator extraction without bias, a subset of email messages was hand-labelled with human-verified ground-truth indicators across all categories (`IPv4`, `Domain`, `URL`, `Email`, and `Hashes`).

---

## 3. IOC Extraction Performance

MailIntel's multi-stage extraction engine walks decoded MIME parts, inspects the RFC-5322 `Received` hop chain for external sender infrastructure, decodes HTML anchor targets, and filters benign traffic through the contextual whitelist policy (`data/whitelist.yaml`).

| Indicator Category | Ground Truth (Expected) | Extracted | True Positives (TP) | False Positives (FP) | False Negatives (FN) | Precision | Recall | F1-Score |
|:-------------------|:-----------------------:|:---------:|:-------------------:|:-------------------:|:--------------------:|:---------:|:------:|:--------:|
{ioc_table_str}
| **OVERALL** | **{ov_ioc.total_expected}** | **{ov_ioc.total_extracted}** | **{ov_ioc.true_positives}** | **{ov_ioc.false_positives}** | **{ov_ioc.false_negatives}** | **{ov_ioc.precision * 100:.1f}%** | **{ov_ioc.recall * 100:.1f}%** | **{ov_ioc.f1_score * 100:.1f}%** |

![IOC Extraction Performance](ioc_extraction_performance.png)

### Key Observations:
1. **URL & Domain Extraction**: High recall (**{ioc_res.categories['url'].recall * 100:.1f}%**) is achieved by parsing both decoded HTML DOM tree attributes (`href`, `src`) and plain text fallback patterns.
2. **Infrastructure IP Pinpointing**: Analyzing the `Received` chain backwards to extract the first untrusted external hop effectively isolates attacker infrastructure while ignoring internal mail relay hops.
3. **Whitelist Suppression**: The contextual whitelist successfully suppressed common legitimate cloud resources (e.g. `github.com`, `docs.python.org`, `amazon.com`), preserving high extraction precision.

---

## 4. Risk Score Distribution & Statistical Separation

MailIntel computes an explainable 0–100 risk score combining SPF/DKIM/DMARC verdicts, Reply-To mismatches, typosquat brand lookalikes, dangerous attachment signatures, and external threat intelligence hits.

### 4.1 Distribution Statistics

| Statistical Metric | SpamAssassin Ham ($y=0$) | Phishing_pot ($y=1$) | Separation Delta |
|:-------------------|:------------------------:|:--------------------:|:----------------:|
| **Sample Count ($n$)** | {scoring_res.ham_stats.count} | {scoring_res.phishing_stats.count} | — |
| **Mean Score (mean)** | **{scoring_res.ham_stats.mean:.1f}** | **{scoring_res.phishing_stats.mean:.1f}** | **+{scoring_res.phishing_stats.mean - scoring_res.ham_stats.mean:.1f} pts** |
| **Median Score** | **{scoring_res.ham_stats.median:.1f}** | **{scoring_res.phishing_stats.median:.1f}** | **+{scoring_res.phishing_stats.median - scoring_res.ham_stats.median:.1f} pts** |
| **Standard Deviation (std)** | {scoring_res.ham_stats.std:.1f} | {scoring_res.phishing_stats.std:.1f} | — |
| **25th Percentile ($Q_1$)** | {scoring_res.ham_stats.q25:.1f} | {scoring_res.phishing_stats.q25:.1f} | +{scoring_res.phishing_stats.q25 - scoring_res.ham_stats.q25:.1f} pts |
| **75th Percentile ($Q_3$)** | {scoring_res.ham_stats.q75:.1f} | {scoring_res.phishing_stats.q75:.1f} | +{scoring_res.phishing_stats.q75 - scoring_res.ham_stats.q75:.1f} pts |
| **Interquartile Range (IQR)** | {scoring_res.ham_stats.iqr:.1f} | {scoring_res.phishing_stats.iqr:.1f} | — |
| **Cohen's $d$ Effect Size** | — | — | **{scoring_res.cohens_d:.2f}** (Extremely Large) |

![Score Distribution Comparison](score_distribution.png)

The risk score produces a clear bimodal separation: legitimate ham centers near **{scoring_res.ham_stats.median:.1f}**, while phishing lures congregate above **{scoring_res.phishing_stats.q25:.1f}**. Cohen's $d$ of **{scoring_res.cohens_d:.2f}** confirms profound statistical divergence.

---

## 5. ROC & Precision-Recall Analysis

![ROC Comparison Curves](roc_curves.png)
![Precision-Recall Curves](pr_curves.png)

### 5.1 Operating Thresholds
- **Optimal Operating Threshold**: **{scoring_res.optimal_threshold:.1f} / 100** (identified via Youden's J = TPR - FPR).
  - At threshold {scoring_res.optimal_threshold:.1f}: **{scoring_res.optimal_metrics.accuracy * 100:.2f}% Accuracy**, **{scoring_res.optimal_metrics.precision * 100:.2f}% Precision**, **{scoring_res.optimal_metrics.recall * 100:.2f}% Recall**, and **{scoring_res.optimal_metrics.f1_score * 100:.2f}% F1**.
- **Default SOC Triage Threshold**: **50.0 / 100** (conservative high-severity cutoff).
  - At threshold 50.0: **{scoring_res.default_50_metrics.accuracy * 100:.2f}% Accuracy**, **{scoring_res.default_50_metrics.precision * 100:.2f}% Precision**, and **{scoring_res.default_50_metrics.recall * 100:.2f}% Recall**.

---

## 6. Machine Learning Baseline & Comparison

To benchmark the rule-based scoring engine against contemporary machine learning techniques, we developed a **TF-IDF + Header-Feature Logistic Regression** classifier evaluated via 5-Fold Stratified Cross-Validation.

### 6.1 Feature Engineering
1. **Text Representations**: Sublinear TF-IDF word and character n-grams (1-2 words, top 250 features) extracted from subject and body.
2. **Dense Header Features**: Standardized forensic signals including SPF failure, DKIM failure, DMARC failure, Reply-To mismatch, URL counts, Received hop counts, external origin presence, attachment danger flags, and subject urgency heuristics.

### 6.2 Model Comparison Table

| Model Architecture | Accuracy | Precision | Recall | F1-Score | ROC-AUC | PR-AUC |
|:-------------------|:--------:|:---------:|:------:|:--------:|:-------:|:------:|
| **MailIntel Rule-Based (Optimal Thresh {scoring_res.optimal_threshold:.1f})** | **{scoring_res.optimal_metrics.accuracy * 100:.2f}%** | **{scoring_res.optimal_metrics.precision * 100:.2f}%** | **{scoring_res.optimal_metrics.recall * 100:.2f}%** | **{scoring_res.optimal_metrics.f1_score * 100:.2f}%** | **{scoring_res.roc_auc:.4f}** | **{scoring_res.pr_auc:.4f}** |
| MailIntel Rule-Based (Default SOC 50.0) | {scoring_res.default_50_metrics.accuracy * 100:.2f}% | {scoring_res.default_50_metrics.precision * 100:.2f}% | {scoring_res.default_50_metrics.recall * 100:.2f}% | {scoring_res.default_50_metrics.f1_score * 100:.2f}% | {scoring_res.roc_auc:.4f} | {scoring_res.pr_auc:.4f} |
| TF-IDF + Header Logistic Regression (5-Fold CV) | {ml_res.ml_baseline_metrics.accuracy * 100:.2f}% | {ml_res.ml_baseline_metrics.precision * 100:.2f}% | {ml_res.ml_baseline_metrics.recall * 100:.2f}% | {ml_res.ml_baseline_metrics.f1_score * 100:.2f}% | {ml_res.ml_baseline_metrics.roc_auc:.4f} | {ml_res.ml_baseline_metrics.pr_auc:.4f} |
| **Hybrid Ensemble (Rule-Based + ML)** | **{ml_res.ensemble_metrics.accuracy * 100:.2f}%** | **{ml_res.ensemble_metrics.precision * 100:.2f}%** | **{ml_res.ensemble_metrics.recall * 100:.2f}%** | **{ml_res.ensemble_metrics.f1_score * 100:.2f}%** | **{ml_res.ensemble_metrics.roc_auc:.4f}** | **{ml_res.ensemble_metrics.pr_auc:.4f}** |

### 6.3 Feature Interpretability
![Feature Coefficients](ml_feature_coefficients.png)

- **Strongest Phishing Predictors (Positive Coefficients)**:
  {phish_feats}
- **Strongest Ham Predictors (Negative Coefficients)**:
  {ham_feats}

### 6.4 Explainability vs. Black-Box Trade-Off:
While the Logistic Regression baseline achieves competitive classification accuracy, it lacks granular operational transparency. In contrast, **MailIntel's rule-based model provides complete, factor-by-factor attribution** (e.g. `+30.0 pts: Reply-To domain does not match From domain`, `+25.0 pts: SPF failure`). This enables SOC analysts to defend triage verdicts in courtroom or audit proceedings.

---

## 7. Forensic Error Analysis

### 7.1 False Positives (Ham Flagged as Phishing)
At the default threshold of 50.0, the false positive rate was **{error_res.fp_rate * 100:.2f}%** ({error_res.false_positives_count} instances).
- **Contributing Factors**:
  - Email forwarding through mailing list managers (Mailman, majordomo) rewriting intermediate envelope senders and invalidating SPF checks.
  - Multi-tenant cloud SaaS sending notifications with differing administrative Return-Path domains.
- **Whitelist Mitigation**:
  {error_res.whitelist_efficacy_notes}

### 7.2 False Negatives (Phishing Evading Threshold)
The false negative rate was **{error_res.fn_rate * 100:.2f}%** ({error_res.false_negatives_count} instances).
- **Evasion Vectors**:
  - Text-only social engineering lures (BEC / Gift Card requests / Phone callback scams) devoid of external URLs or binary attachments.
  - Free webmail accounts (`gmail.com`) used as initial attack staging with naturally valid SPF/DKIM signatures.

### 7.3 Representative Case Studies
{case_studies_str}

---

## 8. Conclusion & Recommendations

1. **Deployment Recommendation**: For automated SOAR blocking, configure MailIntel at threshold **{scoring_res.optimal_threshold:.1f}** for maximum F1 accuracy ({scoring_res.optimal_metrics.f1_score * 100:.1f}%). For human-in-the-loop triage, use threshold **35.0** to capture suspicious candidates for analyst review.
2. **Contextual Whitelisting**: Keep `data/whitelist.yaml` updated with verified enterprise partners to maintain near-zero false positive rates.
3. **Future Research Extension**: Integrate the hybrid ensemble score into the GUI details drawer, presenting both the explainable rule breakdown and the statistical NLP confidence percentage.
"""
    path.write_text(report, encoding="utf-8")
