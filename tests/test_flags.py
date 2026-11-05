"""
tests/test_flags.py
Unit tests for core/ioc/flags.py (mismatch, spoof, auth and subject flags).
"""
from __future__ import annotations

import pytest

from core.ioc.flags import compute_flags, related_domains, subject_patterns
from core.parser.models import AuthResults, HeaderInfo


def _headers(**kw: str) -> HeaderInfo:
    return HeaderInfo(**kw)


class TestRelatedDomains:
    def test_equal_and_subdomain_are_related(self) -> None:
        assert related_domains("example.com", "example.com")
        assert related_domains("mail.example.com", "example.com")
        assert related_domains("example.com", "mail.example.com")

    def test_different_domains_are_not_related(self) -> None:
        assert not related_domains("example.com", "evil.com")
        # suffix match must be on a label boundary
        assert not related_domains("badexample.com", "example.com")

    def test_missing_side_means_no_claim(self) -> None:
        assert related_domains(None, "example.com")
        assert related_domains("example.com", None)


class TestMismatchFlags:
    def test_reply_to_mismatch(self) -> None:
        h = _headers(from_addr="ceo@corp.com", reply_to="ceo@gmail-mail.ru")
        assert compute_flags(h, AuthResults()).reply_to_mismatch

    def test_reply_to_same_domain_is_fine(self) -> None:
        h = _headers(from_addr="ceo@corp.com", reply_to="helpdesk@support.corp.com")
        assert not compute_flags(h, AuthResults()).reply_to_mismatch

    def test_return_path_mismatch(self) -> None:
        h = _headers(from_addr="Billing <billing@corp.com>", return_path="<bounce@spammer.net>")
        flags = compute_flags(h, AuthResults())
        assert flags.return_path_mismatch
        assert not flags.reply_to_mismatch

    def test_null_return_path_is_not_a_mismatch(self) -> None:
        h = _headers(from_addr="a@corp.com", return_path="<>")
        assert not compute_flags(h, AuthResults()).return_path_mismatch

    def test_missing_headers_raise_no_flags(self) -> None:
        flags = compute_flags(_headers(), AuthResults())
        assert not (flags.reply_to_mismatch or flags.return_path_mismatch or flags.display_name_spoof)
        assert flags.auth_failures == []
        assert flags.subject_patterns == []


class TestDisplayNameSpoof:
    def test_display_name_with_other_domain_is_flagged(self) -> None:
        h = _headers(from_addr='"support@paypal.com" <x1234@evil.org>')
        assert compute_flags(h, AuthResults()).display_name_spoof

    def test_plain_display_name_is_fine(self) -> None:
        h = _headers(from_addr="PayPal Support <x1234@evil.org>")
        assert not compute_flags(h, AuthResults()).display_name_spoof

    def test_display_name_with_same_domain_is_fine(self) -> None:
        h = _headers(from_addr='"alice@corp.com" <alice@corp.com>')
        assert not compute_flags(h, AuthResults()).display_name_spoof


class TestAuthFailures:
    def test_lists_only_failing_methods(self) -> None:
        auth = AuthResults(spf="fail", dkim="pass", dmarc="softfail")
        assert compute_flags(_headers(), auth).auth_failures == ["spf", "dmarc"]

    @pytest.mark.parametrize("verdict", ["pass", "none", "neutral"])
    def test_non_failures_are_ignored(self, verdict: str) -> None:
        auth = AuthResults(spf=verdict, dkim=verdict, dmarc=verdict)
        assert compute_flags(_headers(), auth).auth_failures == []


class TestSubjectPatterns:
    @pytest.mark.parametrize(
        ("subject", "expected"),
        [
            ("URGENT: action required", "urgency"),
            ("Invoice #4471 overdue", "payment_invoice"),
            ("Verify your account password", "account_security"),
            ("You are a winner! Claim your gift card", "prize_gift"),
            ("Your DHL parcel could not be delivered", "shipping"),
        ],
    )
    def test_category_matches(self, subject: str, expected: str) -> None:
        assert expected in subject_patterns(subject)

    def test_benign_subject_has_no_pattern(self) -> None:
        assert subject_patterns("Minutes of Tuesday's meeting") == []

    def test_multiple_categories_and_empty_subject(self) -> None:
        got = subject_patterns("Urgent: invoice overdue")
        assert {"urgency", "payment_invoice"} <= set(got)
        assert subject_patterns("") == []

    def test_flags_dict_is_json_serialisable(self) -> None:
        import json

        flags = compute_flags(_headers(subject="Urgent invoice"), AuthResults(spf="fail"))
        assert json.loads(json.dumps(flags.to_dict()))["auth_failures"] == ["spf"]
