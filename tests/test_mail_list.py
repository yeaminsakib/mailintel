"""
tests/test_mail_list.py
Week 2 / M3: the mail list (database queries, shared mail scoring, Mails page)
and the stored-enrichment scoring fix.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.dashboard import MAIL_FILTER_CHOICES, DashboardWindow
from core.ioc.flags import describe_flags
from core.parser.models import AttachmentInfo, AuthResults, FileHashes, HeaderInfo, ParsedEmail
from core.scoring import RiskScorer, score_emails
from core.storage.database import MAIL_FLAG_FILTERS, Database
from core.storage.ingest import ingest_parsed_email


def _att(name: str) -> AttachmentInfo:
    return AttachmentInfo(
        filename=name, mime_type="application/octet-stream", size=10,
        hashes=FileHashes(md5="a" * 32, sha1="a" * 40, sha256="a" * 64),
    )


def _mail(
    sha: str,
    *,
    subject: str,
    from_addr: str,
    reply_to: str = "",
    return_path: str = "",
    spf: str = "pass",
    dkim: str = "pass",
    dmarc: str = "pass",
    urls: list[str] | None = None,
    attachments: list[AttachmentInfo] | None = None,
    filename: str = "m.eml",
) -> ParsedEmail:
    return ParsedEmail(
        filepath=f"/mail/{filename}",
        file_sha256=sha * 32,
        headers=HeaderInfo(
            from_addr=from_addr, reply_to=reply_to, return_path=return_path,
            subject=subject, date="Mon, 02 Nov 2026 10:00:00 +0000", message_id=f"<{sha}@x>",
        ),
        auth_results=AuthResults(spf=spf, dkim=dkim, dmarc=dmarc),
        body_plain="body",
        urls=urls or [],
        attachments=attachments or [],
    )


@pytest.fixture
def seeded(tmp_path: Path) -> Path:
    """A database with one clearly bad mail, one benign mail and a few in between."""
    path = tmp_path / "mails.db"
    db = Database(path)
    ingest_parsed_email(_mail(
        "aa", subject="URGENT: invoice overdue", from_addr="Billing <billing@evil-pay.org>",
        reply_to="collect@other-domain.net", return_path="<bounce@third.io>",
        spf="fail", dkim="fail", dmarc="fail", urls=["http://evil-pay.org/pay"],
        attachments=[_att("invoice.pdf.exe")], filename="bad.eml",
    ), db)
    ingest_parsed_email(_mail(
        "bb", subject="Meeting notes", from_addr="Alice <alice@corp.com>", filename="ok.eml",
    ), db)
    ingest_parsed_email(_mail(
        "cc", subject="100%_done report", from_addr="bob@corp.com", spf="softfail", filename="pct.eml",
    ), db)
    ingest_parsed_email(_mail(
        "dd", subject="Quarterly figures", from_addr="carol@corp.com",
        attachments=[_att("figures.xlsx")], filename="att.eml",
    ), db)
    db.close()
    return path


@pytest.fixture
def db(seeded: Path) -> Database:
    database = Database(seeded)
    yield database
    database.close()


# ---------------------------------------------------------------------------
# Database: search / filters / count
# ---------------------------------------------------------------------------

class TestMailQueries:
    def test_all_mails_newest_first(self, db: Database) -> None:
        rows = db.search_emails()
        assert [r["filename"] for r in rows] == ["att.eml", "pct.eml", "ok.eml", "bad.eml"]
        assert db.count_emails() == 4

    def test_every_filter_key_is_valid_sql(self, db: Database) -> None:
        for key in MAIL_FLAG_FILTERS:
            assert isinstance(db.search_emails(flag=key), list)
            assert db.count_emails(flag=key) == len(db.search_emails(flag=key))

    @pytest.mark.parametrize(
        ("flag", "expected"),
        [
            ("reply_to_mismatch", {"bad.eml"}),
            ("return_path_mismatch", {"bad.eml"}),
            ("auth_failure", {"bad.eml", "pct.eml"}),
            ("has_attachment", {"bad.eml", "att.eml"}),
            ("lure_subject", {"bad.eml"}),
            ("display_name_spoof", set()),
        ],
    )
    def test_flag_filters(self, db: Database, flag: str, expected: set[str]) -> None:
        assert {r["filename"] for r in db.search_emails(flag=flag)} == expected
        assert db.count_emails(flag=flag) == len(expected)

    def test_unknown_filter_is_rejected(self, db: Database) -> None:
        with pytest.raises(ValueError):
            db.search_emails(flag="1=1; DROP TABLE emails")

    def test_search_matches_subject_sender_and_file_case_insensitively(self, db: Database) -> None:
        assert {r["filename"] for r in db.search_emails("MEETING")} == {"ok.eml"}
        assert {r["filename"] for r in db.search_emails("evil-pay")} == {"bad.eml"}
        assert {r["filename"] for r in db.search_emails("att.eml")} == {"att.eml"}

    def test_search_wildcards_are_literal(self, db: Database) -> None:
        assert {r["filename"] for r in db.search_emails("%")} == {"pct.eml"}
        assert {r["filename"] for r in db.search_emails("_")} == {"pct.eml"}
        assert {r["filename"] for r in db.search_emails("100%_")} == {"pct.eml"}
        assert db.search_emails("!") == []
        assert db.search_emails("'; DROP TABLE emails; --") == []
        assert db.get_email_count() == 4

    def test_search_and_filter_combine(self, db: Database) -> None:
        assert {r["filename"] for r in db.search_emails("figures", flag="has_attachment")} == {"att.eml"}
        assert db.search_emails("figures", flag="reply_to_mismatch") == []

    def test_limit_and_offset(self, db: Database) -> None:
        assert len(db.search_emails(limit=2)) == 2
        assert db.search_emails(limit=2, offset=3)[0]["filename"] == "bad.eml"
        assert db.count_emails() == 4          # count ignores paging

    def test_attachments_grouped_by_email(self, db: Database) -> None:
        ids = [r["id"] for r in db.search_emails()]
        grouped = db.get_attachments_for_emails(ids)
        names = sorted(a["filename"] for rows in grouped.values() for a in rows)
        assert names == ["figures.xlsx", "invoice.pdf.exe"]
        assert db.get_attachments_for_emails([]) == {}


# ---------------------------------------------------------------------------
# describe_flags
# ---------------------------------------------------------------------------

class TestDescribeFlags:
    def test_labels_for_a_bad_mail(self, db: Database) -> None:
        bad = next(r for r in db.search_emails() if r["filename"] == "bad.eml")
        labels = " | ".join(describe_flags(bad))
        for expected in ("Reply-To differs", "Return-Path differs", "SPF/DKIM/DMARC", "urgent wording",
                         "payment / invoice lure", "1 attachment"):
            assert expected in labels

    def test_benign_mail_has_no_labels(self, db: Database) -> None:
        ok = next(r for r in db.search_emails() if r["filename"] == "ok.eml")
        assert describe_flags(ok) == []

    def test_old_or_broken_rows_do_not_raise(self) -> None:
        assert describe_flags({}) == []
        assert describe_flags({"flags_json": "not json"}) == []
        assert describe_flags({"flags_json": "[1, 2]"}) == []


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

class TestMailScoring:
    def test_bad_mail_outscores_benign_and_explains_why(self, db: Database) -> None:
        scorer = RiskScorer()
        rows = {r["filename"]: r for r in db.search_emails()}
        scores = score_emails(scorer, db, list(rows.values()))
        bad, ok = scores[rows["bad.eml"]["id"]], scores[rows["ok.eml"]["id"]]
        assert bad.score > ok.score
        # the benign mail only gets the small "indicator seen in several mails" factor
        assert ok.score < 5
        assert {f.factor for f in ok.breakdown} <= {"ioc_intelligence"}
        factors = {f.factor for f in bad.breakdown}
        assert {"auth_failure", "reply_to_mismatch", "dangerous_attachment"} <= factors

    def test_stored_attachments_are_used(self, db: Database) -> None:
        scorer = RiskScorer()
        rows = {r["filename"]: r for r in db.search_emails()}
        scores = score_emails(scorer, db, [rows["att.eml"]])
        assert "phishing_attachment" in scores[rows["att.eml"]["id"]].behaviour_tags

    def test_empty_input(self, db: Database) -> None:
        assert score_emails(RiskScorer(), db, []) == {}

    def test_stored_enrichment_changes_the_score(self, db: Database) -> None:
        """Regression: cached provider results used to be ignored (raw_json was never parsed)."""
        scorer = RiskScorer()
        rows = {r["filename"]: r for r in db.search_emails()}
        bad = rows["bad.eml"]
        before = score_emails(scorer, db, [bad])[bad["id"]].score
        url_ioc = next(i for i in db.get_iocs_for_email(bad["id"]) if i["type"] == "url")
        db.upsert_enrichment(
            ioc_id=url_ioc["id"], provider="virustotal", verdict="malicious", score=90.0,
            raw_json=json.dumps({"data": {"attributes": {"last_analysis_stats": {
                "malicious": 40, "suspicious": 0, "harmless": 10, "undetected": 10}}}}),
        )
        after = score_emails(scorer, db, [bad])[bad["id"]].score
        assert after > before

    def test_enrichment_rows_expose_parsed_raw(self, db: Database) -> None:
        ioc_id = db.upsert_ioc("ipv4", "198.51.100.9")
        db.upsert_enrichment(ioc_id=ioc_id, provider="abuseipdb", verdict="malicious", score=80.0,
                             raw_json='{"data": {"abuseConfidenceScore": 80}}')
        db.upsert_enrichment(ioc_id=ioc_id, provider="otx", verdict="unknown", score=None, raw_json="not json")
        rows = {r["provider"]: r for r in db.get_enrichments_for_ioc(ioc_id)}
        assert rows["abuseipdb"]["raw"] == {"data": {"abuseConfidenceScore": 80}}
        assert rows["otx"]["raw"] == {}                       # invalid JSON never raises
        assert rows["abuseipdb"]["raw_json"]                  # original column kept


# ---------------------------------------------------------------------------
# Mails page
# ---------------------------------------------------------------------------

class TestMailsPage:
    def _open(self, db_path: Path, qtbot) -> DashboardWindow:
        window = DashboardWindow(db_path=db_path)
        qtbot.addWidget(window)
        window.select_nav_button(5)
        return window

    def test_lists_mails_riskiest_first(self, seeded: Path, qtbot) -> None:
        window = self._open(seeded, qtbot)
        table = window.mail_table
        assert table.rowCount() == 4
        assert table.item(0, 7).text() == "bad.eml"                 # highest score first
        scores = [int(table.item(r, 1).text().split("/")[0]) for r in range(4)]
        assert scores == sorted(scores, reverse=True)
        assert "4 of 4 mails match" in window.mail_count_label.text()
        assert "Reply-To differs" in table.item(0, 5).text()

    def test_filter_and_search(self, seeded: Path, qtbot) -> None:
        window = self._open(seeded, qtbot)
        window.mail_filter.setCurrentIndex(window.mail_filter.findData("has_attachment"))
        assert {window.mail_table.item(r, 7).text() for r in range(window.mail_table.rowCount())} == {
            "bad.eml", "att.eml"}
        window.mail_filter.setCurrentIndex(0)
        window.mail_search.setText("meeting")
        assert window.mail_table.rowCount() == 1
        assert "1 of 4 mails match" in window.mail_count_label.text()
        window.mail_search.setText("no such mail")
        assert window.mail_table.rowCount() == 0

    def test_selecting_a_mail_explains_its_score(self, seeded: Path, qtbot) -> None:
        window = self._open(seeded, qtbot)
        window.mail_table.selectRow(0)
        text = window.mail_summary.toPlainText()
        assert "URGENT: invoice overdue" in text
        assert "Why this score" in text and "dangerous_attachment" in text and "auth_failure" in text
        assert "Verdict:" in text

    def test_benign_mail_summary(self, seeded: Path, qtbot) -> None:
        window = self._open(seeded, qtbot)
        window.mail_search.setText("meeting")
        window.mail_table.selectRow(0)
        text = window.mail_summary.toPlainText()
        assert "Verdict: LOW" in text
        for warning in ("auth_failure", "reply_to_mismatch", "dangerous_attachment"):
            assert warning not in text

    def test_empty_database_message(self, tmp_path: Path, qtbot) -> None:
        empty = tmp_path / "empty.db"
        Database(empty).close()
        window = self._open(empty, qtbot)
        assert window.mail_table.rowCount() == 0
        assert "No mails stored yet" in window.mail_count_label.text()

    def test_every_filter_choice_loads(self, seeded: Path, qtbot) -> None:
        window = self._open(seeded, qtbot)
        for index in range(window.mail_filter.count()):
            window.mail_filter.setCurrentIndex(index)
        assert window.mail_filter.count() == len(MAIL_FILTER_CHOICES)

    def test_nav_highlights_the_right_button(self, seeded: Path, qtbot) -> None:
        window = DashboardWindow(db_path=seeded)
        qtbot.addWidget(window)
        labels = [b.text().split("\n")[-1] for b in window.nav_buttons]
        assert labels == ["Dash", "Mails", "Cases", "Graph", "Intel", "Config"]
        window.select_nav_button(5)
        active = [b.text().split("\n")[-1] for b in window.nav_buttons if "rgba(0, 210, 255, 0.14)" in b.styleSheet()]
        assert active == ["Mails"]
        window.select_nav_button(1)
        active = [b.text().split("\n")[-1] for b in window.nav_buttons if "rgba(0, 210, 255, 0.14)" in b.styleSheet()]
        assert active == ["Cases"]

    def test_graph_scores_use_stored_attachments_and_auth(self, seeded: Path, qtbot) -> None:
        window = DashboardWindow(db_path=seeded)
        qtbot.addWidget(window)
        window.select_nav_button(2)
        graph = window.graph_builder.graph
        email_scores = {d["label"]: d["risk_score"] for _, d in graph.nodes(data=True) if d.get("entity_type") == "email"}
        bad = next(v for k, v in email_scores.items() if k.startswith("URGENT"))
        ok = next(v for k, v in email_scores.items() if k.startswith("Meeting"))
        assert bad > ok >= 0
        assert bad >= 30        # auth failures + reply-to + .exe attachment were all counted
