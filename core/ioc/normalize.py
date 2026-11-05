"""
core/ioc/normalize.py
Normalisation helpers so the same indicator is always stored under one key.

* ``normalize_domain`` - lower-case, strip decoration and the trailing dot,
  convert Unicode (IDN) labels to punycode, reject IP literals and anything
  that is not a syntactically valid multi-label DNS name.
* ``normalize_url``    - lower-case scheme and host, drop default ports and the
  fragment, give an empty path as ``/``.  Path and query keep their case
  (they are case-sensitive and may be the actual malicious token).
* ``domain_from_url`` / ``email_domain`` - get a normalised domain out of a
  URL or an e-mail address.

Pure functions, no I/O.  Limitation: there is no public-suffix list, so no
"registrable domain" logic (``a.b.example.co.uk`` stays as it is).
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443, "ftp": 21}
_STRIP_CHARS = " \t\r\n<>[](){}\"'`,;"

#: Reserved / internal-only top-level labels (RFC 2606, RFC 6761, RFC 6762 and
#: common private-network suffixes).  Names under them cannot be looked up on
#: the public Internet, so they are never useful as threat indicators.
NON_PUBLIC_TLDS: frozenset[str] = frozenset({
    "local", "localhost", "localdomain", "internal", "intranet", "lan", "home",
    "corp", "private", "invalid", "test", "example", "arpa",
})


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def normalize_domain(value: str | None) -> str | None:
    """Return the canonical form of a domain name, or ``None`` if invalid.

    >>> normalize_domain(" <Mail.Example.COM.> ")
    'mail.example.com'
    >>> normalize_domain("bücher.de")
    'xn--bcher-kva.de'
    >>> normalize_domain("203.0.113.9") is None
    True
    >>> normalize_domain("edge-firewall.enterprise.local") is None
    True
    """
    if not value:
        return None
    domain = value.strip(_STRIP_CHARS).rstrip(".").lower()
    if not domain or len(domain) > 253 or _is_ip(domain):
        return None
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(domain) > 253:
        return None
    labels = domain.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.match(label) for label in labels):
        return None
    if labels[-1].isdigit():  # "1.2.3.456" and similar are not domains
        return None
    if labels[-1] in NON_PUBLIC_TLDS:
        return None
    return domain


def domain_from_url(url: str | None) -> str | None:
    """Return the normalised host of *url*, or ``None`` (no host / IP host)."""
    if not url:
        return None
    try:
        host = urlsplit(url.strip()).hostname
    except ValueError:
        return None
    return normalize_domain(host)


def email_domain(address: str | None) -> str | None:
    """Return the normalised domain part of an e-mail address."""
    if not address or "@" not in address:
        return None
    return normalize_domain(address.rsplit("@", 1)[-1])


def normalize_url(url: str) -> str:
    """Return a canonical form of *url* for de-duplication.

    Non-http(s)/ftp URLs and URLs that cannot be parsed are returned
    unchanged (stripped).

    >>> normalize_url("HTTP://Evil.COM:80/Path?A=b#frag")
    'http://evil.com/Path?A=b'
    """
    url = url.strip()
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return url
    scheme = parts.scheme.lower()
    host = parts.hostname
    if scheme not in _DEFAULT_PORTS or not host:
        return url

    if not _is_ip(host):
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    elif ":" in host:
        host = f"[{host}]"

    userinfo = ""
    if parts.username is not None:
        userinfo = parts.username
        if parts.password is not None:
            userinfo += f":{parts.password}"
        userinfo += "@"

    netloc = userinfo + host
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        netloc += f":{port}"

    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
