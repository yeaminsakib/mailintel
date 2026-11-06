"""
tests/test_mail_flag_scoring.py
The mail-level flags (Return-Path mismatch, display-name spoof, subject lure
wording) contribute to the explainable mail score.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.dashboard import DashboardWindow
from core.parser.models import AuthResults, HeaderInfo, ParsedEmail
from core.scoring import RiskScorer, email_flag_inputs, score_emails
from core.storage.database import Database
from core.storage.ingest import ingest_parsed_email


@pytest.fixture(scope="module")
def scorer() -> RiskScorer:
    return RiskScorer()


def _factors(result) -> dict[str, float]:
    return {f.factor: f.points for f in result.breakdown}


class TestFactors:
    def test_no_flags_no_new_factors(self, scorer: RiskScorer) -> None:
        assert scorer.score_email().breakdown == []

    def test_return_path_mismatch(self, scorer: RiskScorer) -> None:
        result = scorer.score_email(return_path_mismatch=True)
        assert _factors(result) == {"return_path_mismatch": 5.0}
        assert "masquerading" in result.behaviour_tags
        assert result.score == 5.0

    def test_display_name_spoof(self, scorer: RiskScorer) -> None:
        result = scorer.score_email(display_name_spoof=True)
        assert _factors(result) == {"display_name_spoof": 10.0}
        assert "masquerading" in result.behaviour_tags

    def test_subject_lure_scales_with_categories_and_is_capped(self, scorer: RiskScorer) -> None:
        one = scorer.score_email(subject_patterns=["urgency"])
        two = scorer.score_email(subject_patterns=["urgency", "payment_invoice"])
        five = scorer.score_email(
            subject_patterns=["urgency", "payment_invoice", "account_security", "prize_gift", "shipping"])
        assert _factors(one) == {"subject_lure": 2.0}
        assert _factors(two) == {"subject_lure": 4.0}
        assert _factors(five) == {"subject_lure": 6.0}          # capped
        assert "urgent wording" in one.breakdown[0].reason      # readable, not the internal key

    def test_unknown_pattern_name_is_still_reported(self, scorer: RiskScorer) -> None:
        assert "made_up" in scorer.score_email(subject_patterns=["made_up"]).breakdown[0].reason

    def test_flags_add_up_with_the_existing_factors(self, scorer: RiskScorer) -> None:
        result = scorer.score_email(
            auth_results={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
            from_addr="a@corp.com", reply_to="b@evil.net",
            return_path_mismatch=True, display_name_spoof=True, subject_patterns=["urgency"],
        )
        factors = _factors(result)
        assert {"auth_failure", "reply_to_mismatch", "return_path_mismatch",
                "display_name_spoof", "subject_lure"} <= set(factors)
        assert result.score == round(sum(factors.values()), 1)         # score is exactly the sum: explainable
        assert result.score <= 100

    def test_weights_can_be_retuned_without_code_changes(self, tmp_path: Path) -> None:
        weights = tmp_path / "w.yaml"
        weights.write_text(
            "return_path_mismatch:\n  max_points: 20\n"
            "display_name_spoof:\n  max_points: 1\n"
            "subject_lure:\n  points_per_category: 5\n  max_points: 7\n",
            encoding="utf-8",
        )
        tuned = RiskScorer(weights_path=weights)
        result = tuned.score_email(return_path_mismatch=True, display_name_spoof=True,
                                   subject_patterns=["urgency", "shipping", "prize_gift"])
        assert _factors(result) == {"return_path_mismatch": 20.0, "display_name_spoof": 1.0, "subject_lure": 7.0}

    def test_defaults_apply_when_the_weights_file_has_no_such_sections(self, tmp_path: Path) -> None:
        weights = tmp_path / "empty.yaml"
        weights.write_text("virustotal:\n  max_points: 30\n", encoding="utf-8")
        result = RiskScorer(weights_path=weights).score_email(
            return_path_mismatch=True, display_name_spoof=True, subject_patterns=["urgency"])
        assert _factors(result) == {"return_path_mismatch": 5.0, "display_name_spoof": 10.0, "subject_lure": 2.0}

    def test_shipped_weights_file_defines_the_new_sections(self) -> None:
        weights = RiskScorer()._weights
        assert weights["return_path_mismatch"]["max_points"] == 5
        assert weights["display_name_spoof"]["max_points"] == 10
        assert weights["subject_lure"] == {"points_per_category": 2, "max_points": 6}


class TestFlagInputs:
    def test_reads_columns_and_json(self) -> None:
        row = {"return_path_mismatch": 1,
               "flags_json": '{"display_name_spoof": true, "subject_patterns": ["urgency"], "auth_failures": ["spf"]}'}
        assert email_flag_inputs(row) == {
            "return_path_mismatch": True, "display_name_spoof": True, "subject_patterns": ["urgency"]}

    @pytest.mark.parametrize("row", [{}, {"flags_json": "{}"}, {"flags_json": "garbage"}, {"flags_json": "[1]"},
                                     {"flags_json": None, "return_path_mismatch": 0}])
    def test_old_or_broken_rows_mean_no_flags(self, row: dict) -> None:
        assert email_flag_inputs(row) == {
            "return_path_mismatch": False, "display_name_spoof": False, "subject_patterns": []}


def _mail(sha: str, *, subject: str, from_addr: str, return_path: str = "", filename: str) -> ParsedEmail:
    return ParsedEmail(
        filepath=f"/mail/{filename}", file_sha256=sha * 32,
        headers=HeaderInfo(from_addr=from_addr, return_path=return_path, subject=subject,
                           date="Mon, 02 Nov 2026 10:00:00 +0000", message_id=f"<{sha}@x>"),
        auth_results=AuthResults(), body_plain="hello", urls=[],
    )


@pytest.fixture
def seeded(tmp_path: Path) -> Path:
    path = tmp_path / "flags.db"
    db = Database(path)
    ingest_parsed_email(_mail(
        "aa", subject="Urgent: verify your account password", filename="spoof.eml",
        from_addr='"support@paypal.com" <x7@mailer-xyz.top>', return_path="<bounce@spam-host.biz>"), db)
    ingest_parsed_email(_mail(
        "bb", subject="Minutes of Tuesday", filename="plain.eml", from_addr="Alice <alice@corp.com>"), db)
    db.close()
    return path


class TestStoredMailScore:
    def test_flagged_mail_scores_higher_and_says_why(self, seeded: Path, scorer: RiskScorer) -> None:
        db = Database(seeded)
        try:
            rows = {r["filename"]: r for r in db.search_emails()}
            scores = score_emails(scorer, db, list(rows.values()))
        finally:
            db.close()
        spoof, plain = scores[rows["spoof.eml"]["id"]], scores[rows["plain.eml"]["id"]]
        factors = _factors(spoof)
        assert {"return_path_mismatch", "display_name_spoof", "subject_lure"} <= set(factors)
        assert spoof.score >= 5 + 10 + 4          # return-path + display name + two lure categories
        assert spoof.score > plain.score
        assert plain.score < 5
        assert spoof.score == round(sum(f.points for f in spoof.breakdown), 1)

    def test_mails_page_explains_the_new_factors(self, seeded: Path, qtbot) -> None:
        window = DashboardWindow(db_path=seeded)
        qtbot.addWidget(window)
        window.select_nav_button(5)
        window.mail_table.selectRow(0)                       # riskiest first
        text = window.mail_summary.toPlainText()
        for expected in ("display_name_spoof", "return_path_mismatch", "subject_lure", "urgent wording"):
            assert expected in text

    def test_graph_node_uses_the_same_flags(self, seeded: Path, qtbot) -> None:
        window = DashboardWindow(db_path=seeded)
        qtbot.addWidget(window)
        window.select_nav_button(2)
        scores = {d["label"]: d["risk_score"] for _, d in window.graph_builder.graph.nodes(data=True)
                  if d.get("entity_type") == "email"}
        flagged = next(v for k, v in scores.items() if k.startswith("Urgent"))
        plain = next(v for k, v in scores.items() if k.startswith("Minutes"))
        assert flagged >= 19 and flagged > plain
