"""
core/parser/headers.py
Header extraction from parsed ``email.message.EmailMessage`` objects.

Handles:
- Standard headers (From, Reply-To, Return-Path, Subject, Date, Message-ID, To, Cc)
- Received chain parsing with from-host, by-host, sender IP, and timestamp
- First external hop identification (the real sender's infrastructure)
- SPF / DKIM / DMARC verdicts from Authentication-Results
"""
from __future__ import annotations

import ipaddress
import re
from email.message import EmailMessage

from .models import AuthResults, HeaderInfo, ReceivedHop


# ---------------------------------------------------------------------------
# Received-header regex helpers
# ---------------------------------------------------------------------------

# IP address inside Received (IPv4 in brackets or bare, IPv6 in brackets)
_RE_RECEIVED_IP = re.compile(
    r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]"   # [1.2.3.4]
    r"|"
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"    # 1.2.3.4 bare
    r"|"
    r"\[([0-9a-fA-F:]+)\]"                           # [IPv6]
)

_RE_RECEIVED_FROM = re.compile(r"from\s+([\w.\-]+)", re.IGNORECASE)
_RE_RECEIVED_BY = re.compile(r"by\s+([\w.\-]+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Private / reserved IP check (uses stdlib ipaddress)
# ---------------------------------------------------------------------------

def _is_private_ip(ip: str) -> bool:
    """Return True if *ip* is private, loopback, reserved, or link-local."""
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_reserved
            or addr.is_link_local
            or addr.is_multicast
        )
    except ValueError:
        return True  # unparseable → treat as internal


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_headers(msg: EmailMessage) -> HeaderInfo:
    """Extract key headers from an ``EmailMessage``.

    Missing headers are returned as empty strings (never ``None``).
    """
    def _get(name: str) -> str:
        val = msg.get(name, "")
        return str(val).strip() if val else ""

    return HeaderInfo(
        from_addr=_get("From"),
        reply_to=_get("Reply-To"),
        return_path=_get("Return-Path"),
        subject=_get("Subject"),
        date=_get("Date"),
        message_id=_get("Message-ID"),
        to=_get("To"),
        cc=_get("Cc"),
    )


def parse_received_chain(msg: EmailMessage) -> list[ReceivedHop]:
    """Parse all ``Received`` headers into structured hops.

    Returns hops in header order (newest → oldest, top → bottom).
    Each hop records whether it came from an external (public) IP.
    """
    hops: list[ReceivedHop] = []
    received_headers = msg.get_all("Received") or []

    for raw_value in received_headers:
        raw = str(raw_value).strip()

        # Extract "from <host>"
        from_match = _RE_RECEIVED_FROM.search(raw)
        from_host = from_match.group(1) if from_match else ""

        # Extract "by <host>"
        by_match = _RE_RECEIVED_BY.search(raw)
        by_host = by_match.group(1) if by_match else ""

        # Extract first IP
        from_ip: str | None = None
        for ipv4_bracket, ipv4_bare, ipv6 in _RE_RECEIVED_IP.findall(raw):
            candidate = ipv4_bracket or ipv4_bare or ipv6
            if candidate:
                from_ip = candidate
                break

        # Timestamp sits after the semicolon
        timestamp: str | None = None
        if ";" in raw:
            timestamp = raw.split(";", 1)[1].strip()

        is_external = bool(from_ip and not _is_private_ip(from_ip))

        hops.append(ReceivedHop(
            from_host=from_host,
            by_host=by_host,
            from_ip=from_ip,
            timestamp=timestamp,
            raw=raw,
            is_external=is_external,
        ))

    return hops


def find_first_external_hop(hops: list[ReceivedHop]) -> ReceivedHop | None:
    """Return the first external hop — the real sender's infrastructure.

    ``Received`` headers are prepended top-down (newest first), so the
    *last* external hop in the list is the oldest — the one closest to
    the actual sender.
    """
    external_hops = [h for h in hops if h.is_external]
    return external_hops[-1] if external_hops else None


def parse_auth_results(msg: EmailMessage) -> AuthResults:
    """Parse ``Authentication-Results`` for SPF / DKIM / DMARC verdicts."""
    raw_values = msg.get_all("Authentication-Results") or []
    if not raw_values:
        return AuthResults()

    combined = " ".join(str(v) for v in raw_values)

    return AuthResults(
        spf=_extract_auth_verdict(combined, "spf"),
        dkim=_extract_auth_verdict(combined, "dkim"),
        dmarc=_extract_auth_verdict(combined, "dmarc"),
        raw=combined,
    )


def _extract_auth_verdict(text: str, method: str) -> str:
    """Extract the verdict (pass/fail/softfail/none/…) for an auth method."""
    pattern = re.compile(rf"{method}\s*=\s*(\w+)", re.IGNORECASE)
    match = pattern.search(text)
    return match.group(1).lower() if match else "none"
