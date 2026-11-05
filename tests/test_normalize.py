"""
tests/test_normalize.py
Unit tests for core/ioc/normalize.py (domain and URL canonicalisation).
"""
from __future__ import annotations

import pytest

from core.ioc.normalize import domain_from_url, email_domain, normalize_domain, normalize_url


class TestNormalizeDomain:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Example.COM", "example.com"),
            ("example.com.", "example.com"),
            ("  <mail.example.com>  ", "mail.example.com"),
            ("(evil-site.org),", "evil-site.org"),
            ("bücher.de", "xn--bcher-kva.de"),
            ("xn--bcher-kva.de", "xn--bcher-kva.de"),
            ("_dmarc.example.com", "_dmarc.example.com"),
            ("a-b.c-d.co.uk", "a-b.c-d.co.uk"),
        ],
    )
    def test_valid_domains_are_canonicalised(self, raw: str, expected: str) -> None:
        assert normalize_domain(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            None,
            "",
            "   ",
            "localhost",              # single label
            "evil",                   # single label
            "a..b.com",               # empty label
            "-bad.com",               # label starts with hyphen
            "bad-.com",               # label ends with hyphen
            "has space.com",
            "203.0.113.9",            # IPv4 literal
            "2001:db8::1",            # IPv6 literal
            "1.2.3.456",              # numeric TLD
            "printer.corp",           # internal-only suffix
            "edge-firewall.enterprise.local",
            "host.localdomain",
            "site.test",
            "x" * 64 + ".com",       # label longer than 63
            ("a" * 60 + ".") * 5 + "com",  # name longer than 253
        ],
    )
    def test_invalid_or_non_public_names_are_rejected(self, raw: str | None) -> None:
        assert normalize_domain(raw) is None


class TestDomainExtraction:
    def test_domain_from_url(self) -> None:
        assert domain_from_url("http://User:pw@Phish.Example.COM:8080/a?b=c") == "phish.example.com"

    def test_domain_from_url_ip_host_is_none(self) -> None:
        assert domain_from_url("http://203.0.113.9/login") is None
        assert domain_from_url("http://[2001:db8::1]/") is None

    def test_domain_from_defanged_scheme_still_works(self) -> None:
        assert domain_from_url("hxxp://evil.org/x") == "evil.org"

    @pytest.mark.parametrize("bad", [None, "", "not a url", "http://", "http://[::1"])
    def test_domain_from_url_bad_input(self, bad: str | None) -> None:
        assert domain_from_url(bad) is None

    def test_email_domain(self) -> None:
        assert email_domain("Jane.Doe@Sub.Example.COM") == "sub.example.com"

    @pytest.mark.parametrize("bad", [None, "", "no-at-sign", "user@", "user@localhost"])
    def test_email_domain_bad_input(self, bad: str | None) -> None:
        assert email_domain(bad) is None


class TestNormalizeUrl:
    def test_lowercases_scheme_and_host_only(self) -> None:
        assert normalize_url("HTTP://Evil.COM/Path/With/Case?Token=AbC") == (
            "http://evil.com/Path/With/Case?Token=AbC"
        )

    def test_drops_default_port_and_fragment(self) -> None:
        assert normalize_url("https://evil.com:443/a#frag") == "https://evil.com/a"
        assert normalize_url("http://evil.com:80") == "http://evil.com/"

    def test_keeps_non_default_port(self) -> None:
        assert normalize_url("http://evil.com:8080/a") == "http://evil.com:8080/a"

    def test_empty_path_becomes_slash(self) -> None:
        assert normalize_url("http://evil.com") == "http://evil.com/"

    def test_idn_host_becomes_punycode(self) -> None:
        assert normalize_url("http://bücher.de/x") == "http://xn--bcher-kva.de/x"

    def test_ipv6_host_keeps_brackets(self) -> None:
        assert normalize_url("http://[2001:DB8::1]:8080/a") == "http://[2001:db8::1]:8080/a"

    def test_userinfo_is_preserved(self) -> None:
        assert normalize_url("https://User:Pw@Ex.com:443/") == "https://User:Pw@ex.com/"

    @pytest.mark.parametrize(
        "unchanged",
        ["mailto:a@b.com", "javascript:alert(1)", "hxxp://x.com/a", "http://ex.com:99999/", "not a url"],
    )
    def test_other_inputs_are_returned_stripped(self, unchanged: str) -> None:
        assert normalize_url(f"  {unchanged}  ") == unchanged

    def test_idempotent(self) -> None:
        once = normalize_url("HTTPS://Evil.com:443/A#x")
        assert normalize_url(once) == once

    def test_variants_collapse_to_one_key(self) -> None:
        variants = ["http://Evil.com", "http://evil.com:80/", "HTTP://EVIL.COM/#top"]
        assert len({normalize_url(v) for v in variants}) == 1
