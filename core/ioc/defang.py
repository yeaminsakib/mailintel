"""
core/ioc/defang.py
Defanging and refanging utilities for IOCs.

Defanging replaces characters to prevent accidental clicks or execution::

    IP:    1.2.3.4                 → 1[.]2[.]3[.]4
    URL:   http://evil.com/path   → hXXp[://]evil[.]com/path
    Email: user@example.com       → user[@]example[.]com
"""
from __future__ import annotations

import re


def defang_ip(ip: str) -> str:
    """Defang an IP address: ``1.2.3.4`` → ``1[.]2[.]3[.]4``."""
    return ip.replace(".", "[.]")


def defang_url(url: str) -> str:
    """Defang a URL: ``http://evil.com/path`` → ``hXXp[://]evil[.]com/path``."""
    result = url
    # Replace protocol scheme
    result = re.sub(r"^https://", "hXXps[://]", result, flags=re.IGNORECASE)
    result = re.sub(r"^http://", "hXXp[://]", result, flags=re.IGNORECASE)
    result = re.sub(r"^ftp://", "fXp[://]", result, flags=re.IGNORECASE)

    # Defang dots in the domain portion only (before the first path /)
    proto_end = result.find("[://]")
    if proto_end != -1:
        proto_end += 5  # len("[://]")
        after_proto = result[proto_end:]
        slash_pos = after_proto.find("/")
        if slash_pos != -1:
            domain = after_proto[:slash_pos].replace(".", "[.]")
            path = after_proto[slash_pos:]
            return result[:proto_end] + domain + path
        return result[:proto_end] + after_proto.replace(".", "[.]")

    return result.replace(".", "[.]")


def defang_email(email: str) -> str:
    """Defang an email: ``user@example.com`` → ``user[@]example[.]com``."""
    return email.replace("@", "[@]").replace(".", "[.]")


def refang_ip(text: str) -> str:
    """Refang a defanged IP: ``1[.]2[.]3[.]4`` → ``1.2.3.4``."""
    return text.replace("[.]", ".")


def refang_url(text: str) -> str:
    """Refang a defanged URL back to its original form."""
    result = text
    result = re.sub(r"^hXXps\[://\]", "https://", result, flags=re.IGNORECASE)
    result = re.sub(r"^hXXp\[://\]", "http://", result, flags=re.IGNORECASE)
    result = re.sub(r"^fXp\[://\]", "ftp://", result, flags=re.IGNORECASE)
    return result.replace("[.]", ".")


def refang_email(text: str) -> str:
    """Refang a defanged email back to its original form."""
    return text.replace("[@]", "@").replace("[.]", ".")


def defang(ioc: str, ioc_type: str = "auto") -> str:
    """Defang an IOC, auto-detecting its type if needed.

    Parameters
    ----------
    ioc : str
        The raw IOC value.
    ioc_type : str
        One of ``'ip'``, ``'url'``, ``'email'``, or ``'auto'``.

    Returns
    -------
    str
        Defanged IOC string safe for reports and chat messages.
    """
    if ioc_type == "auto":
        if "://" in ioc:
            ioc_type = "url"
        elif "@" in ioc:
            ioc_type = "email"
        else:
            ioc_type = "ip"

    dispatch = {"ip": defang_ip, "url": defang_url, "email": defang_email}
    return dispatch.get(ioc_type, lambda x: x)(ioc)
