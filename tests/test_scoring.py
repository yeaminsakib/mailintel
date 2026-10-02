"""
tests/test_scoring.py
Comprehensive tests for core/scoring/risk_score.py.

Tests cover:
- Weight / brand list loading
- VirusTotal detection scoring
- AbuseIPDB confidence scoring
- Domain age (RDAP) scoring
- SPF / DKIM / DMARC auth failure scoring
- Reply-To / From mismatch scoring
- Dangerous attachment and macro scoring
- Lookalike / typosquat detection (Levenshtein + homoglyph)
- IOC frequency scoring
- Full IOC-level score aggregation
- Full email-level score aggregation
- Clamping to [0, 100]
- Levenshtein distance function
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from core.scoring.risk_score import (
    EmailScore,
    IocScore,
    RiskScorer,
    ScoreFactor,
    _extract_domain,
    _has_homoglyphs,
    _normalize_homoglyphs,
    levenshtein,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scorer(tmp_path: Path) -> RiskScorer:
    """Return a RiskScorer with default weights and a small brand list."""
    brands_file = tmp_path / "brands.txt"
    brands_file.write_text(
        "paypal.com\nmicrosoft.com\ngoogle.com\napple.com\nchase.com\n"
    )
    # Use the real weights file from data/
    return RiskScorer(brands_path=brands_file)


@pytest.fixture
def scorer_custom(tmp_path: Path) -> RiskScorer:
    """RiskScorer with custom weights for precise point assertions."""
    weights_file = tmp_path / "weights.yaml"
    weights_file.write_text(textwrap.dedent("""\
        virustotal:
          max_points: 30
          min_hit_points: 5
        abuseipdb:
          max_points: 20
        domain_age:
          max_points: 15
          newly_registered_days: 7
          recently_registered_days: 30
          young_domain_days: 90
        auth_failure:
          max_points: 15
          spf_fail: 6
          dkim_fail: 5
          dmarc_fail: 8
        reply_to_mismatch:
          max_points: 10
        dangerous_attachment:
          max_points: 15
          extensions:
            - .exe
            - .scr
            - .bat
            - .js
            - .ps1
            - .iso
          macro_extensions:
            - .xlsm
            - .docm
          macro_points: 12
        lookalike:
          max_points: 15
          levenshtein_threshold: 2
          homoglyph_points: 15
          levenshtein_points: 12
        ioc_frequency:
          max_points: 10
          high_freq_threshold: 20
    """))
    brands_file = tmp_path / "brands.txt"
    brands_file.write_text("paypal.com\nmicrosoft.com\ngoogle.com\n")
    return RiskScorer(weights_path=weights_file, brands_path=brands_file)


# ---------------------------------------------------------------------------
# Levenshtein distance
# ---------------------------------------------------------------------------

class TestLevenshtein:
    def test_identical(self) -> None:
        assert levenshtein("hello", "hello") == 0

    def test_one_insertion(self) -> None:
        assert levenshtein("cat", "cats") == 1

    def test_one_deletion(self) -> None:
        assert levenshtein("cats", "cat") == 1

    def test_one_substitution(self) -> None:
        assert levenshtein("cat", "car") == 1

    def test_empty_strings(self) -> None:
        assert levenshtein("", "") == 0
        assert levenshtein("abc", "") == 3
        assert levenshtein("", "abc") == 3

    def test_completely_different(self) -> None:
        assert levenshtein("abc", "xyz") == 3

    def test_typosquat_paypal(self) -> None:
        # paypa1.com vs paypal.com → 1 substitution
        assert levenshtein("paypa1.com", "paypal.com") == 1


# ---------------------------------------------------------------------------
# Homoglyph utilities
# ---------------------------------------------------------------------------

class TestHomoglyphs:
    def test_has_homoglyphs_true(self) -> None:
        # \u0430 = Cyrillic 'а' (looks like Latin 'a')
        assert _has_homoglyphs("p\u0430ypal.com")

    def test_has_homoglyphs_false(self) -> None:
        assert not _has_homoglyphs("paypal.com")

    def test_normalize_cyrillic(self) -> None:
        result = _normalize_homoglyphs("p\u0430yp\u0430l.com")
        assert result == "paypal.com"

    def test_normalize_no_change(self) -> None:
        assert _normalize_homoglyphs("google.com") == "google.com"


# ---------------------------------------------------------------------------
# Domain extraction
# ---------------------------------------------------------------------------

class TestExtractDomain:
    def test_email_address(self) -> None:
        assert _extract_domain("user@example.com") == "example.com"

    def test_bare_domain(self) -> None:
        assert _extract_domain("example.com") == "example.com"

    def test_angle_bracket_email(self) -> None:
        assert _extract_domain("John <john@example.com>") == "example.com"


# ---------------------------------------------------------------------------
# VirusTotal scoring
# ---------------------------------------------------------------------------

class TestVirusTotalScoring:
    def test_high_malicious_detections(self, scorer_custom: RiskScorer) -> None:
        enrichments = [{
            "provider": "virustotal",
            "verdict": "malicious",
            "score": 80.0,
            "tags": [],
            "error": None,
            "raw": {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 30,
                            "suspicious": 5,
                            "harmless": 20,
                            "undetected": 5,
                        }
                    }
                }
            },
        }]
        result = scorer_custom.score_ioc("ipv4", "1.2.3.4", enrichments)
        vt_factor = _find_factor(result, "virustotal")
        assert vt_factor is not None
        assert vt_factor.points > 15  # should be high
        assert "30" in vt_factor.reason  # malicious count in reason

    def test_zero_detections(self, scorer_custom: RiskScorer) -> None:
        enrichments = [{
            "provider": "virustotal",
            "error": None,
            "raw": {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 60,
                            "undetected": 10,
                        }
                    }
                }
            },
        }]
        result = scorer_custom.score_ioc("ipv4", "8.8.8.8", enrichments)
        vt_factor = _find_factor(result, "virustotal")
        assert vt_factor is not None
        assert vt_factor.points == 0.0

    def test_single_detection_gets_min_hit(self, scorer_custom: RiskScorer) -> None:
        enrichments = [{
            "provider": "virustotal",
            "error": None,
            "raw": {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 1,
                            "suspicious": 0,
                            "harmless": 69,
                            "undetected": 0,
                        }
                    }
                }
            },
        }]
        result = scorer_custom.score_ioc("ipv4", "1.1.1.1", enrichments)
        vt_factor = _find_factor(result, "virustotal")
        assert vt_factor is not None
        assert vt_factor.points >= 5.0  # min_hit_points

    def test_no_vt_enrichment(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_ioc("ipv4", "1.2.3.4", [])
        vt_factor = _find_factor(result, "virustotal")
        assert vt_factor is None


# ---------------------------------------------------------------------------
# AbuseIPDB scoring
# ---------------------------------------------------------------------------

class TestAbuseIPDBScoring:
    def test_high_confidence(self, scorer_custom: RiskScorer) -> None:
        enrichments = [{
            "provider": "abuseipdb",
            "error": None,
            "score": 85,
            "raw": {"data": {"abuseConfidenceScore": 85}},
        }]
        result = scorer_custom.score_ioc("ipv4", "5.6.7.8", enrichments)
        factor = _find_factor(result, "abuseipdb")
        assert factor is not None
        assert factor.points == 17.0  # 85 / 100 * 20

    def test_zero_confidence(self, scorer_custom: RiskScorer) -> None:
        enrichments = [{
            "provider": "abuseipdb",
            "error": None,
            "score": 0,
            "raw": {"data": {"abuseConfidenceScore": 0}},
        }]
        result = scorer_custom.score_ioc("ipv4", "8.8.8.8", enrichments)
        factor = _find_factor(result, "abuseipdb")
        assert factor is not None
        assert factor.points == 0.0


# ---------------------------------------------------------------------------
# Domain age scoring
# ---------------------------------------------------------------------------

class TestDomainAgeScoring:
    def test_newly_registered(self, scorer_custom: RiskScorer) -> None:
        enrichments = [{
            "provider": "rdap",
            "error": None,
            "tags": ["age:3d"],
            "raw": {},
        }]
        result = scorer_custom.score_ioc("domain", "evil.xyz", enrichments)
        factor = _find_factor(result, "domain_age")
        assert factor is not None
        assert factor.points == 15.0  # full max_points
        assert "newly registered" in factor.reason

    def test_recently_registered(self, scorer_custom: RiskScorer) -> None:
        enrichments = [{
            "provider": "rdap",
            "error": None,
            "tags": ["age:15d"],
            "raw": {},
        }]
        result = scorer_custom.score_ioc("domain", "recent.xyz", enrichments)
        factor = _find_factor(result, "domain_age")
        assert factor is not None
        assert factor.points == 10.5  # 15 * 0.7

    def test_established_domain(self, scorer_custom: RiskScorer) -> None:
        enrichments = [{
            "provider": "rdap",
            "error": None,
            "tags": ["age:1825d"],
            "raw": {},
        }]
        result = scorer_custom.score_ioc("domain", "google.com", enrichments)
        factor = _find_factor(result, "domain_age")
        assert factor is not None
        assert factor.points == 0.0

    def test_age_factor_not_on_ip(self, scorer_custom: RiskScorer) -> None:
        enrichments = [{
            "provider": "rdap",
            "error": None,
            "tags": ["age:3d"],
            "raw": {},
        }]
        result = scorer_custom.score_ioc("ipv4", "1.2.3.4", enrichments)
        factor = _find_factor(result, "domain_age")
        assert factor is None  # domain age only applies to domain IOCs


# ---------------------------------------------------------------------------
# Auth failure scoring
# ---------------------------------------------------------------------------

class TestAuthFailureScoring:
    def test_all_fail(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_email(
            auth_results={"spf": "fail", "dkim": "fail", "dmarc": "fail"}
        )
        factor = _find_factor(result, "auth_failure")
        assert factor is not None
        # 6 + 5 + 8 = 19 → clamped to 15
        assert factor.points == 15.0

    def test_spf_softfail(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_email(
            auth_results={"spf": "softfail", "dkim": "pass", "dmarc": "pass"}
        )
        factor = _find_factor(result, "auth_failure")
        assert factor is not None
        assert factor.points == 6.0

    def test_all_pass(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_email(
            auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"}
        )
        factor = _find_factor(result, "auth_failure")
        assert factor is None  # no points when everything passes


# ---------------------------------------------------------------------------
# Reply-To mismatch scoring
# ---------------------------------------------------------------------------

class TestReplyToMismatch:
    def test_mismatch(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_email(
            from_addr="support@company.com",
            reply_to="attacker@evil.com",
        )
        factor = _find_factor(result, "reply_to_mismatch")
        assert factor is not None
        assert factor.points == 10.0
        assert "evil.com" in factor.reason

    def test_same_domain(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_email(
            from_addr="user@company.com",
            reply_to="admin@company.com",
        )
        factor = _find_factor(result, "reply_to_mismatch")
        assert factor is None

    def test_empty_reply_to(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_email(
            from_addr="user@company.com",
            reply_to="",
        )
        factor = _find_factor(result, "reply_to_mismatch")
        assert factor is None


# ---------------------------------------------------------------------------
# Dangerous attachment scoring
# ---------------------------------------------------------------------------

class TestDangerousAttachments:
    def test_exe_attachment(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_email(
            attachments=[{"filename": "invoice.exe", "mime_type": "application/x-msdownload"}]
        )
        factor = _find_factor(result, "dangerous_attachment")
        assert factor is not None
        assert factor.points == 15.0

    def test_macro_enabled_doc(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_email(
            attachments=[{"filename": "report.xlsm", "mime_type": "application/vnd.ms-excel"}]
        )
        factor = _find_factor(result, "dangerous_attachment")
        assert factor is not None
        assert factor.points == 12.0
        assert "macro_execution" in result.behaviour_tags

    def test_double_extension(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_email(
            attachments=[{"filename": "invoice.pdf.exe", "mime_type": "application/octet-stream"}]
        )
        factor = _find_factor(result, "dangerous_attachment")
        assert factor is not None
        assert factor.points == 15.0
        assert "masquerading_double_extension" in result.behaviour_tags

    def test_safe_attachment(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_email(
            attachments=[{"filename": "document.pdf", "mime_type": "application/pdf"}]
        )
        factor = _find_factor(result, "dangerous_attachment")
        assert factor is None

    def test_iso_attachment_tags(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_email(
            attachments=[{"filename": "image.iso", "mime_type": "application/octet-stream"}]
        )
        assert "disk_image_delivery" in result.behaviour_tags

    def test_script_attachment_tags(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_email(
            attachments=[{"filename": "payload.js", "mime_type": "application/javascript"}]
        )
        assert "script_execution" in result.behaviour_tags

    def test_ps1_attachment_tags(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_email(
            attachments=[{"filename": "script.ps1", "mime_type": "text/plain"}]
        )
        assert "powershell_execution" in result.behaviour_tags


# ---------------------------------------------------------------------------
# Lookalike / Typosquat detection
# ---------------------------------------------------------------------------

class TestLookalikeDetection:
    def test_levenshtein_typosquat(self, scorer_custom: RiskScorer) -> None:
        # paypall.com → paypal.com (1 insertion, no homoglyphs)
        result = scorer_custom.score_ioc("domain", "paypall.com", [])
        factor = _find_factor(result, "lookalike")
        assert factor is not None
        assert factor.points == 12.0
        assert "paypal.com" in factor.reason


    def test_levenshtein_too_far(self, scorer_custom: RiskScorer) -> None:
        # completely different domain
        result = scorer_custom.score_ioc("domain", "totallyunknown.com", [])
        factor = _find_factor(result, "lookalike")
        assert factor is None

    def test_homoglyph_attack(self, scorer_custom: RiskScorer) -> None:
        # p + Cyrillic 'а' + ypal.com
        result = scorer_custom.score_ioc("domain", "p\u0430ypal.com", [])
        factor = _find_factor(result, "lookalike")
        assert factor is not None
        assert factor.points == 15.0
        assert "Homoglyph" in factor.reason

    def test_exact_brand_not_flagged(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_ioc("domain", "paypal.com", [])
        factor = _find_factor(result, "lookalike")
        assert factor is None  # exact match = not a lookalike

    def test_subdomain_of_brand_not_flagged(self, scorer_custom: RiskScorer) -> None:
        # mail.google.com → registrable = google.com → exact match → skip
        result = scorer_custom.score_ioc("domain", "mail.google.com", [])
        factor = _find_factor(result, "lookalike")
        assert factor is None

    def test_masquerading_tag(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_ioc("domain", "paypa1.com", [])
        assert "masquerading" in result.behaviour_tags


# ---------------------------------------------------------------------------
# IOC frequency scoring
# ---------------------------------------------------------------------------

class TestFrequencyScoring:
    def test_single_occurrence(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_ioc("ipv4", "1.2.3.4", [], frequency=1)
        factor = _find_factor(result, "ioc_frequency")
        assert factor is None  # frequency of 1 = not flagged

    def test_moderate_frequency(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_ioc("ipv4", "1.2.3.4", [], frequency=10)
        factor = _find_factor(result, "ioc_frequency")
        assert factor is not None
        assert factor.points == 5.0  # 10/20 * 10

    def test_high_frequency_capped(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_ioc("ipv4", "1.2.3.4", [], frequency=100)
        factor = _find_factor(result, "ioc_frequency")
        assert factor is not None
        assert factor.points == 10.0  # capped at max


# ---------------------------------------------------------------------------
# Full IOC score aggregation
# ---------------------------------------------------------------------------

class TestIocScoreAggregation:
    def test_combined_score(self, scorer_custom: RiskScorer) -> None:
        enrichments = [
            {
                "provider": "virustotal",
                "error": None,
                "raw": {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 20,
                                "suspicious": 0,
                                "harmless": 30,
                                "undetected": 10,
                            }
                        }
                    }
                },
            },
            {
                "provider": "abuseipdb",
                "error": None,
                "score": 50,
                "raw": {"data": {"abuseConfidenceScore": 50}},
            },
        ]
        result = scorer_custom.score_ioc("ipv4", "1.2.3.4", enrichments, frequency=15)
        assert result.score > 0
        assert result.score <= 100
        assert len(result.breakdown) >= 2  # at least VT + AbuseIPDB

    def test_score_clamped_to_100(self, scorer_custom: RiskScorer) -> None:
        """Even with extreme inputs the score never exceeds 100."""
        enrichments = [
            {
                "provider": "virustotal",
                "error": None,
                "raw": {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 60,
                                "suspicious": 10,
                                "harmless": 0,
                                "undetected": 0,
                            }
                        }
                    }
                },
            },
            {
                "provider": "abuseipdb",
                "error": None,
                "score": 100,
                "raw": {"data": {"abuseConfidenceScore": 100}},
            },
            {
                "provider": "rdap",
                "error": None,
                "tags": ["age:1d"],
                "raw": {},
            },
        ]
        result = scorer_custom.score_ioc(
            "domain", "paypa1.com", enrichments, frequency=50
        )
        assert result.score <= 100.0

    def test_clean_ioc_low_score(self, scorer_custom: RiskScorer) -> None:
        """Clean IOC with no enrichment data should score 0."""
        result = scorer_custom.score_ioc("ipv4", "8.8.8.8", [], frequency=1)
        assert result.score == 0.0
        assert len(result.breakdown) == 0


# ---------------------------------------------------------------------------
# Full email score aggregation
# ---------------------------------------------------------------------------

class TestEmailScoreAggregation:
    def test_phishing_email_high_score(self, scorer_custom: RiskScorer) -> None:
        ioc = scorer_custom.score_ioc("ipv4", "1.2.3.4", [{
            "provider": "virustotal",
            "error": None,
            "raw": {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 40,
                            "suspicious": 0,
                            "harmless": 20,
                            "undetected": 0,
                        }
                    }
                }
            },
        }])

        result = scorer_custom.score_email(
            auth_results={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
            from_addr="support@paypal.com",
            reply_to="hacker@evil.com",
            attachments=[{"filename": "invoice.exe", "mime_type": "application/octet-stream"}],
            ioc_scores={"1.2.3.4": ioc},
            urls=["http://evil.com/login"],
        )
        assert result.score > 40  # should be quite high
        assert result.score <= 100
        assert len(result.breakdown) >= 3
        assert "phishing_attachment" in result.behaviour_tags
        assert "phishing_link" in result.behaviour_tags

    def test_clean_email_low_score(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_email(
            auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            from_addr="user@company.com",
            reply_to="user@company.com",
            attachments=[{"filename": "report.pdf", "mime_type": "application/pdf"}],
        )
        assert result.score == 0.0

    def test_behaviour_tags_deduplicated(self, scorer_custom: RiskScorer) -> None:
        result = scorer_custom.score_email(
            auth_results={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        )
        # Tags should be deduplicated
        assert len(result.behaviour_tags) == len(set(result.behaviour_tags))


# ---------------------------------------------------------------------------
# Score factor / model basics
# ---------------------------------------------------------------------------

class TestScoreModels:
    def test_score_factor_frozen(self) -> None:
        sf = ScoreFactor(factor="test", points=5.0, reason="test reason")
        assert sf.factor == "test"
        assert sf.points == 5.0

    def test_ioc_score_defaults(self) -> None:
        s = IocScore()
        assert s.score == 0.0
        assert s.breakdown == []
        assert s.behaviour_tags == []

    def test_email_score_defaults(self) -> None:
        s = EmailScore()
        assert s.score == 0.0
        assert s.ioc_scores == {}


# ---------------------------------------------------------------------------
# Weight loading edge cases
# ---------------------------------------------------------------------------

class TestWeightLoading:
    def test_missing_weights_file(self, tmp_path: Path) -> None:
        """RiskScorer should work with default weights if file is missing."""
        scorer = RiskScorer(
            weights_path=tmp_path / "nonexistent.yaml",
            brands_path=tmp_path / "nonexistent.txt",
        )
        result = scorer.score_ioc("ipv4", "1.2.3.4", [])
        assert result.score == 0.0

    def test_empty_weights_file(self, tmp_path: Path) -> None:
        weights = tmp_path / "empty.yaml"
        weights.write_text("")
        brands = tmp_path / "brands.txt"
        brands.write_text("")
        scorer = RiskScorer(weights_path=weights, brands_path=brands)
        # Should still work, just with 0 defaults everywhere
        result = scorer.score_ioc("ipv4", "1.2.3.4", [])
        assert result.score == 0.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_factor(
    result: IocScore | EmailScore, factor_name: str
) -> ScoreFactor | None:
    """Find a specific factor in the breakdown list."""
    for f in result.breakdown:
        if f.factor == factor_name:
            return f
    return None
