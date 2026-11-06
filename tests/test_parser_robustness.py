"""
tests/test_parser_robustness.py
One unparseable header or MIME part must cost only that piece of data,
never the whole message (found by scanning the 8,752-mail spam corpus).
"""
from __future__ import annotations

from core.parser import eml_parser
from core.parser.eml_parser import parse_eml_bytes
from core.storage.database import Database
from core.storage.ingest import ingest_parsed_email

# Header seen in real spam (Exim rewrite); the stdlib raises
# AttributeError: 'Group' object has no attribute 'local_part' when it is read.
UNLISTED = b"To: unlisted-recipients:; (no To-header on input)@mail.UM\r\n"


def _mail(extra_headers: bytes = b"", body: bytes = b"Visit http://evil.example.org/x now\r\n") -> bytes:
    return (
        b"From: Miss Sonia <sonia@centrum.cz>\r\n"
        b"Subject: Dear friend\r\n"
        + extra_headers
        + b"Message-ID: <abc@centrum.cz>\r\n\r\n"
        + body
    )


class TestUnparseableHeaders:
    def test_group_with_trailing_text_in_to_header(self) -> None:
        parsed = parse_eml_bytes(_mail(UNLISTED))
        assert parsed.headers.subject == "Dear friend"
        assert parsed.headers.from_addr.endswith("<sonia@centrum.cz>")
        assert parsed.headers.message_id == "<abc@centrum.cz>"
        assert "evil.example.org" in " ".join(parsed.urls)
        # The header is kept rather than dropped.  Python <= 3.13 cannot parse it, so the
        # raw text is stored; newer versions return a cleaned-up value - either way it
        # starts with the group name.
        assert parsed.headers.to.startswith("unlisted-recipients:;")

    def test_same_problem_in_cc_header(self) -> None:
        parsed = parse_eml_bytes(_mail(b"Cc: undisclosed:; (hidden)@x.y\r\n"))
        assert parsed.headers.subject == "Dear friend"
        assert parsed.headers.cc

    def test_message_with_such_a_header_can_be_ingested(self) -> None:
        db = Database(":memory:")
        parsed = parse_eml_bytes(_mail(UNLISTED))
        parsed.file_sha256 = "ab" * 32
        ingest_parsed_email(parsed, db)
        assert db.get_email_count() == 1
        assert db.get_all_emails()[0]["subject"] == "Dear friend"

    def test_raw_header_fallback_unfolds_lines(self) -> None:
        raw = _mail(b"To: undisclosed:;\r\n (folded junk)@x.y\r\n")
        assert "\n" not in parse_eml_bytes(raw).headers.to


class TestStageIsolation:
    ATTACHED = (
        b"From: a@b.org\r\nSubject: S\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=XX\r\n\r\n"
        b"--XX\r\nContent-Type: text/plain\r\n\r\nSee http://evil.example.org/p\r\n"
        b"--XX\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=one.bin\r\n\r\nAAAA\r\n"
        b"--XX\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=two.bin\r\n\r\nBBBB\r\n"
        b"--XX--\r\n"
    )

    def test_failing_header_stage_keeps_body_urls_and_attachments(self, monkeypatch) -> None:
        def boom(_msg):
            raise RuntimeError("header stage exploded")

        monkeypatch.setattr(eml_parser, "extract_headers", boom)
        parsed = parse_eml_bytes(self.ATTACHED)
        assert parsed.headers.subject == ""                      # default
        assert "evil.example.org" in " ".join(parsed.urls)
        assert [a.filename for a in parsed.attachments] == ["one.bin", "two.bin"]

    def test_failing_attachment_stage_keeps_headers_and_urls(self, monkeypatch) -> None:
        def boom(_msg):
            raise RuntimeError("attachment stage exploded")

        monkeypatch.setattr(eml_parser, "extract_attachments", boom)
        parsed = parse_eml_bytes(self.ATTACHED)
        assert parsed.headers.subject == "S"
        assert parsed.attachments == []
        assert parsed.urls

    def test_one_bad_part_does_not_lose_the_other_attachments(self, monkeypatch) -> None:
        from core.parser import attachments as att

        real = att._attachment_from_part

        def flaky(part):
            if part.get_filename() == "one.bin":
                raise ValueError("bad part")
            return real(part)

        monkeypatch.setattr(att, "_attachment_from_part", flaky)
        parsed = parse_eml_bytes(self.ATTACHED)
        assert [a.filename for a in parsed.attachments] == ["two.bin"]

    def test_garbage_input_never_raises(self) -> None:
        for blob in (b"", b"\x00\xff\xfe" * 50, b"Subject\r\n\r\n", b":::\r\n\r\n", b"From: <<<>>>\r\n\r\nx"):
            parse_eml_bytes(blob)
