"""
core/ioc/extractors.py
IOC (Indicator of Compromise) extractors for various artifact types.

Each extractor returns a **deduplicated, ordered** list of IOC strings
found in the input text.  Private / reserved addresses are excluded.

Extractors
----------
extract_ipv4(text)            → list[str]   Public IPv4 addresses
extract_ipv6(text)            → list[str]   Global IPv6 addresses
extract_urls(text)            → list[str]   http/https/ftp URLs
extract_email_addresses(text) → list[str]   user@domain addresses
"""
from __future__ import annotations

import ipaddress
import re


# ---------- IPv4 ----------
_RE_IPV4 = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b"
)


# ---------- IPv6 ----------
# Broad candidate regex — validated by ipaddress.IPv6Address afterwards
_RE_IPV6_CANDIDATE = re.compile(
    r"(?<![:\w])"
    r"("
    # Full form: 8 hex groups
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|"
    # Compressed forms with ::
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|"
    r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|"
    r":(?::[0-9a-fA-F]{1,4}){1,7}"
    r"|"
    # IPv4-mapped IPv6
    r"::(?:[fF]{4}:)?(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}"
    r"(?:25[0-5]|(?:2[0-4]|1?\d)?\d)"
    r")"
    r"(?![:\w])"
)


# ---------- URL ----------
_RE_URL = re.compile(
    r"(https?://[^\s<>\"'`\)\]\}]+|ftp://[^\s<>\"'`\)\]\}]+)",
    re.IGNORECASE,
)
_TRAILING_PUNCT = re.compile(r"[.,;:!?\)\]\}>]+$")


# ---------- Email ----------
_RE_EMAIL = re.compile(
    r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b"
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_ipv4(text: str) -> list[str]:
    """Extract unique, globally-routable IPv4 addresses from *text*.

    Private (RFC 1918), loopback, link-local, CGNAT, multicast, reserved,
    and documentation addresses are excluded.
    """
    seen: set[str] = set()
    results: list[str] = []
    for match in _RE_IPV4.finditer(text):
        ip = match.group(1)
        if ip in seen:
            continue
        try:
            addr = ipaddress.IPv4Address(ip)
            if addr.is_global:
                seen.add(ip)
                results.append(ip)
        except ValueError:
            continue
    return results


def extract_ipv6(text: str) -> list[str]:
    """Extract unique, globally-routable IPv6 addresses from *text*.

    Candidates are found via regex and validated with
    :class:`ipaddress.IPv6Address`.  Non-global addresses (loopback,
    link-local, multicast) are excluded.
    """
    seen: set[str] = set()
    results: list[str] = []
    for match in _RE_IPV6_CANDIDATE.finditer(text):
        candidate = match.group(1).strip()
        try:
            addr = ipaddress.IPv6Address(candidate)
            normalised = str(addr)
            if addr.is_global and normalised not in seen:
                seen.add(normalised)
                results.append(normalised)
        except ValueError:
            continue
    return results


def extract_urls(text: str) -> list[str]:
    """Extract unique ``http`` / ``https`` / ``ftp`` URLs from *text*.

    Trailing punctuation that the regex may have captured is stripped.
    """
    seen: set[str] = set()
    results: list[str] = []
    for match in _RE_URL.finditer(text):
        url = _TRAILING_PUNCT.sub("", match.group(1))
        if url not in seen:
            seen.add(url)
            results.append(url)
    return results


def extract_email_addresses(text: str) -> list[str]:
    """Extract unique email addresses from *text* (lowercased)."""
    seen: set[str] = set()
    results: list[str] = []
    for match in _RE_EMAIL.finditer(text):
        email = match.group(1).lower()
        if email not in seen:
            seen.add(email)
            results.append(email)
    return results
