"""
core/ioc/flags.py
Per-mail indicators that are not IOC values themselves:

* ``reply_to_mismatch``   - Reply-To domain differs from the From domain
* ``return_path_mismatch``- Return-Path domain differs from the From domain
* ``display_name_spoof``  - the From display name shows an address on another domain
* ``auth_failures``       - which of SPF / DKIM / DMARC did not pass
* ``subject_patterns``    - lure categories matched in the subject (keyword rules)

Domains are compared with :func:`related_domains` (equal, or one is a
subdomain of the other).  There is no public-suffix list, so two unrelated
sites that share a registrable domain's parent are not detected - this is a
heuristic, documented as such in the thesis.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from email.utils import getaddresses, parseaddr

from core.parser.models import AuthResults, HeaderInfo

from .extractors import extract_email_addresses
from .normalize import email_domain

#: category -> regex (case-insensitive) applied to the decoded subject
SUBJECT_PATTERNS: dict[str, re.Pattern[str]] = {
    name: re.compile(pattern, re.IGNORECASE)
    for name, pattern in {
        "urgency": r"\b(urgent|immediate(ly)?|action required|asap|final notice|last warning"
                   r"|within \d+ ?(hours?|days?)|expires?( today| soon)?)\b",
        "payment_invoice": r"\b(invoice|payment|remittance|receipt|purchase order|wire transfer"
                           r"|overdue|refund|statement)\b",
        "account_security": r"\b(verify|confirm|suspend(ed)?|locked|security alert|password"
                            r"|unusual (sign|log)[- ]?in|account (will be )?(closed|disabled|limited))\b",
        "prize_gift": r"\b(winner|lottery|gift ?card|prize|reward|bitcoin|crypto(currency)?|inheritance)\b",
        "shipping": r"\b(parcel|package|delivery|shipment|tracking number|dhl|fedex|ups)\b",
    }.items()
}


@dataclass
class MailFlags:
    """Derived per-mail flags (stored as columns + ``flags_json``)."""

    reply_to_mismatch: bool = False
    return_path_mismatch: bool = False
    display_name_spoof: bool = False
    auth_failures: list[str] = field(default_factory=list)
    subject_patterns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def related_domains(a: str | None, b: str | None) -> bool:
    """True if the domains are equal or one is a subdomain of the other."""
    if not a or not b:
        return True  # nothing to compare -> no mismatch claim
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _header_domain(header_value: str) -> str | None:
    """Domain of the first *real* address in an address header.

    ``getaddresses`` separates the display name from the address, so
    ``"support@paypal.com" <x@evil.org>`` yields ``evil.org``, not ``paypal.com``.
    """
    for _name, addr in getaddresses([header_value or ""]):
        domain = email_domain(addr)
        if domain:
            return domain
    return None


def _text_domain(text: str) -> str | None:
    """Domain of the first address-like string found anywhere in *text*."""
    for addr in extract_email_addresses(text or ""):
        domain = email_domain(addr)
        if domain:
            return domain
    return None


def subject_patterns(subject: str) -> list[str]:
    """Return the names of all lure categories that match *subject*."""
    return [name for name, rx in SUBJECT_PATTERNS.items() if rx.search(subject or "")]


def compute_flags(headers: HeaderInfo, auth: AuthResults) -> MailFlags:
    """Compute :class:`MailFlags` from parsed headers and auth results."""
    from_domain = _header_domain(headers.from_addr)
    reply_domain = _header_domain(headers.reply_to)
    return_domain = _header_domain(headers.return_path)  # "<>" has no address -> None

    display_name, _addr = parseaddr(headers.from_addr or "")
    shown_domain = _text_domain(display_name) if "@" in display_name else None

    failures = [
        method
        for method, verdict in (("spf", auth.spf), ("dkim", auth.dkim), ("dmarc", auth.dmarc))
        if verdict in ("fail", "softfail", "permerror", "temperror")
    ]

    return MailFlags(
        reply_to_mismatch=not related_domains(from_domain, reply_domain),
        return_path_mismatch=not related_domains(from_domain, return_domain),
        display_name_spoof=not related_domains(from_domain, shown_domain),
        auth_failures=failures,
        subject_patterns=subject_patterns(headers.subject),
    )
