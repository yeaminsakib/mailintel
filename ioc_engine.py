"""
ioc_engine.py
Backend logic for MailIntel DFIR desktop tool.
Extracts and analyzes Indicators of Compromise (IOCs) from email data.

Public API
----------
parse_eml_folder(folder_path)   -> Dict  (total_emails_scanned, top_ips,
                                          top_domains, hashes, case_folder_path)
extract_iocs_from_folder(...)   -> List[Dict]   (used by the UI dashboard)
analyze_folder(...)             -> List[Dict]   (used by the UI dashboard)
"""

from __future__ import annotations

import csv
import datetime
import os
import re
from collections import Counter
from typing import Any, Dict, List, Optional, Set

# Curated DFIR Mock Threat Intel Dataset for immediate feedback and realistic demonstration
DEFAULT_IOC_DATA: List[Dict[str, Any]] = [
    {"ioc": "139.59.164.251", "type": "IP", "freq": 48, "severity": "Critical", "tag": "C2 Server"},
    {"ioc": "evil-update-auth.com", "type": "Domain", "freq": 34, "severity": "High", "tag": "Phishing Landing"},
    {"ioc": "185.220.101.5", "type": "IP", "freq": 29, "severity": "High", "tag": "Tor Exit / Proxy"},
    {"ioc": "secure-login-portal-office365.net", "type": "Domain", "freq": 23, "severity": "Critical", "tag": "Credential Harvester"},
    {"ioc": "194.26.29.112", "type": "IP", "freq": 17, "severity": "Medium", "tag": "SMTP Relay"},
    {"ioc": "cdn-cloud-storage-sync.biz", "type": "Domain", "freq": 15, "severity": "Medium", "tag": "Payload Delivery"},
    {"ioc": "45.145.66.89", "type": "IP", "freq": 12, "severity": "High", "tag": "Cobalt Strike Beacon"},
    {"ioc": "invoice-notification-sys.org", "type": "Domain", "freq": 9, "severity": "Low", "tag": "Suspicious Sender"},
    {"ioc": "91.240.118.232", "type": "IP", "freq": 7, "severity": "Low", "tag": "Scanning Host"},
    {"ioc": "accounts-verification-service.info", "type": "Domain", "freq": 5, "severity": "High", "tag": "Brand Impersonation"},
]


# ---------------------------------------------------------------------------
# Compiled Regex Patterns
# ---------------------------------------------------------------------------

# IPv4: four dot-separated octets validated by the regex structure (0-255)
_RE_IPV4 = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b"
)

# Domain: standard hostname labels ending in a recognisable TLD (2+ chars)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,})\b"
)

# MD5: exactly 32 hex characters surrounded by word boundaries
_RE_MD5 = re.compile(r"\b([0-9a-fA-F]{32})\b")


# ---------------------------------------------------------------------------
# Private / Reserved IPv4 Ranges
# ---------------------------------------------------------------------------

def _is_private_or_reserved(ip: str) -> bool:
    """
    Return True if the IPv4 address belongs to a private, loopback,
    link-local, broadcast, or documentation range and should be ignored.

    Covered ranges:
        Loopback      : 127.0.0.0/8
        Private-A     : 10.0.0.0/8
        Private-B     : 172.16.0.0/12  (172.16.x.x - 172.31.x.x)
        Private-C     : 192.168.0.0/16
        Link-local    : 169.254.0.0/16
        CGNAT         : 100.64.0.0/10  (100.64 - 100.127)
        Documentation : 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        Multicast     : 224.0.0.0/4
        Reserved      : 240.0.0.0/4
        Broadcast     : 255.255.255.255
        This-network  : 0.x.x.x
    """
    try:
        a, b, c, d = (int(p) for p in ip.split("."))  # noqa: F841
    except ValueError:
        return True  # unparseable -> discard

    if a == 127:                          # Loopback
        return True
    if a == 10:                           # Private Class A
        return True
    if a == 172 and 16 <= b <= 31:        # Private Class B
        return True
    if a == 192 and b == 168:             # Private Class C
        return True
    if a == 169 and b == 254:             # Link-local
        return True
    if a == 100 and 64 <= b <= 127:       # CGNAT
        return True
    if a == 192 and b == 0 and c == 2:    # TEST-NET-1
        return True
    if a == 198 and b == 51 and c == 100: # TEST-NET-2
        return True
    if a == 203 and b == 0 and c == 113:  # TEST-NET-3
        return True
    if a >= 224:                           # Multicast + Reserved + Broadcast
        return True
    if a == 0:                             # This-network
        return True
    return False


# ---------------------------------------------------------------------------
# Domain Whitelist
# ---------------------------------------------------------------------------

#: Curated set of benign / infrastructure domains to exclude from results.
DOMAIN_WHITELIST: Set[str] = {
    # Search & Web Giants
    "google.com", "www.google.com", "googleapis.com", "googleusercontent.com",
    "gstatic.com", "bing.com", "yahoo.com", "yandex.com",
    # Microsoft ecosystem
    "microsoft.com", "microsoftonline.com", "office.com", "office365.com",
    "outlook.com", "live.com", "hotmail.com", "windows.com",
    "schemas.microsoft.com", "schemas.openxmlformats.org",
    # Apple
    "apple.com", "icloud.com",
    # Amazon / AWS
    "amazon.com", "amazonaws.com", "aws.amazon.com",
    # Meta / Facebook
    "facebook.com", "instagram.com", "whatsapp.com", "fbcdn.net",
    # Web & Email infrastructure
    "w3.org", "iana.org", "ietf.org", "rfc-editor.org",
    "smtp.gmail.com", "mail.google.com",
    "sendgrid.net", "mailchimp.com", "mailgun.org",
    "spf.protection.outlook.com",
    # CDN & DNS
    "cloudflare.com", "cloudflare-dns.com", "akamaiedge.net",
    "fastly.net", "cdn.jsdelivr.net",
    # Encoding / standards artifacts sometimes seen in raw EML headers
    "utf-8", "charset",
}


def _is_whitelisted_domain(domain: str) -> bool:
    """Return True if *domain* or any parent zone is in DOMAIN_WHITELIST.

    Parent-zone walking stops at two-label parents (e.g. 'google.com') so
    that bare TLDs like 'com' or 'net' never become accidental wildcards.
    """
    d = domain.lower().strip(".")
    if d in DOMAIN_WHITELIST:
        return True
    # Walk up the DNS hierarchy (e.g. sub.google.com -> google.com)
    # Stop before single-label entries to avoid TLD wildcard matching.
    parts = d.split(".")
    for i in range(1, len(parts) - 1):  # -1 keeps minimum 2 labels in parent
        parent = ".".join(parts[i:])
        if parent in DOMAIN_WHITELIST:
            return True
    return False


# ---------------------------------------------------------------------------
# Core Parsing Function
# ---------------------------------------------------------------------------

def parse_eml_folder(folder_path: str) -> Dict[str, Any]:
    """
    Read every ``.eml`` file in *folder_path*, extract raw IOC strings, apply
    noise-reduction filters, and return aggregated IOC data as a structured
    JSON-serialisable dictionary.

    Parameters
    ----------
    folder_path : str
        Absolute or relative path to the directory containing ``.eml`` files.

    Returns
    -------
    dict
        .. code-block:: python

            {
                "total_emails_scanned": int,
                "top_ips": [
                    {"ioc": "<ip>",     "count": <int>},
                    ...
                ],
                "top_domains": [
                    {"ioc": "<domain>", "count": <int>},
                    ...
                ],
                "hashes": [
                    {"ioc": "<md5>",   "count": <int>},
                    ...
                ],
            }

        Lists are ordered by frequency (highest first) and uncapped — callers
        can slice as needed.  The raw Counter objects are also preserved under
        the private keys ``_counter_ipv4``, ``_counter_domains``, and
        ``_counter_md5`` for downstream functions that need direct Counter
        access (e.g. ``analyze_folder``).

    Notes
    -----
    - All private / reserved IPs are silently excluded.
    - Domains present in DOMAIN_WHITELIST (or whose parent zone is) are excluded.
    - MD5 candidates that are pure-digit strings are excluded.
    - Files that cannot be opened are skipped without raising.
    """
    ipv4_counter: Counter = Counter()
    domain_counter: Counter = Counter()
    md5_counter: Counter = Counter()
    total_emails_scanned: int = 0
    email_logs: List[Dict[str, Any]] = []  # per-email event records

    if not folder_path or not os.path.isdir(folder_path):
        return _build_result(total_emails_scanned, ipv4_counter, domain_counter, md5_counter, email_logs)

    eml_files = sorted(
        f for f in os.listdir(folder_path) if f.lower().endswith(".eml")
    )

    for filename in eml_files:
        file_path = os.path.join(folder_path, filename)
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                raw_text = fh.read()
        except OSError:
            continue  # Unreadable file – skip gracefully

        total_emails_scanned += 1

        # Per-email accumulators (sets deduplicate within one message)
        email_ips:     list = []
        email_domains: list = []
        email_hashes:  list = []
        seen_ips:     set = set()
        seen_domains: set = set()
        seen_hashes:  set = set()

        # --- IPv4 Extraction & Filtering ---
        for match in _RE_IPV4.findall(raw_text):
            if not _is_private_or_reserved(match):
                ipv4_counter[match] += 1
                if match not in seen_ips:
                    email_ips.append(match)
                    seen_ips.add(match)

        # --- Domain Extraction & Filtering ---
        for match in _RE_DOMAIN.findall(raw_text):
            lower = match.lower().strip(".")
            # Must contain a dot and be longer than 4 chars
            if "." not in lower or len(lower) <= 4:
                continue
            # Skip pure numeric labels (IP fragments mistakenly matched)
            if re.match(r"^[\d.]+$", lower):
                continue
            if _is_whitelisted_domain(lower):
                continue
            domain_counter[lower] += 1
            if lower not in seen_domains:
                email_domains.append(lower)
                seen_domains.add(lower)

        # --- MD5 Hash Extraction ---
        for match in _RE_MD5.findall(raw_text):
            lower_hash = match.lower()
            # Exclude strings that are entirely numeric (not a valid hex hash)
            if not re.match(r"^[0-9]+$", lower_hash):
                md5_counter[lower_hash] += 1
                if lower_hash not in seen_hashes:
                    email_hashes.append(lower_hash)
                    seen_hashes.add(lower_hash)

        # Build per-email event record (comma-joined strings for easy display)
        email_logs.append({
            "filename": filename,
            "ips":      ", ".join(email_ips)     if email_ips     else "",
            "domains":  ", ".join(email_domains) if email_domains else "",
            "hashes":   ", ".join(email_hashes)  if email_hashes  else "",
        })

    return _build_result(total_emails_scanned, ipv4_counter, domain_counter, md5_counter, email_logs)


# ---------------------------------------------------------------------------
# Case Logging & CSV Export
# ---------------------------------------------------------------------------

def _write_case_log(
    email_logs: List[Dict[str, Any]],
) -> str:
    """
    Create a timestamped case directory under ``<cwd>/case_log/`` and write
    per-email IOC data into ``ioc_results.csv``.

    Directory layout::

        <cwd>/
        └── case_log/
            └── case_YYYYMMDD_HHMMSS/
                └── ioc_results.csv

    CSV Headers: File Name, Extracted IPs, Extracted Domains, Extracted Hashes

    Parameters
    ----------
    email_logs :
        List of per-email dicts with keys: filename, ips, domains, hashes.

    Returns
    -------
    str
        Absolute path to the timestamped case directory.
        Returns an empty string if the write fails.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    case_dir  = os.path.join(os.getcwd(), "case_log", f"case_{timestamp}")
    csv_path  = os.path.join(case_dir, "ioc_results.csv")

    try:
        os.makedirs(case_dir, exist_ok=True)

        with open(csv_path, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            # Per-email schema – one row per .eml file
            writer.writerow(["File Name", "Extracted IPs", "Extracted Domains", "Extracted Hashes"])
            for log in email_logs:
                writer.writerow([
                    log.get("filename", ""),
                    log.get("ips",      ""),
                    log.get("domains",  ""),
                    log.get("hashes",   ""),
                ])

    except OSError as exc:
        print(f"[ioc_engine] WARNING: Could not write case log – {exc}")
        return ""

    return case_dir


def _build_result(
    total: int,
    ipv4_counter: Counter,
    domain_counter: Counter,
    md5_counter: Counter,
    email_logs: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Assemble the canonical parse_eml_folder return structure and log the case."""
    top_ips     = [{"ioc": ip, "count": c} for ip, c in ipv4_counter.most_common()]
    top_domains = [{"ioc": d,  "count": c} for d,  c in domain_counter.most_common()]
    hashes      = [{"ioc": h,  "count": c} for h,  c in md5_counter.most_common()]

    # Write per-email case log and capture the folder path
    case_folder_path: str = _write_case_log(email_logs)

    return {
        # ── Public, JSON-serialisable fields ──────────────────────────────
        "total_emails_scanned": total,
        "top_ips":              top_ips,
        "top_domains":          top_domains,
        "hashes":               hashes,
        "email_logs":           email_logs,     # per-email event records
        "case_folder_path":     case_folder_path,
        # ── Private Counter objects for downstream helpers ─────────────────
        "_counter_ipv4":    ipv4_counter,
        "_counter_domains": domain_counter,
        "_counter_md5":     md5_counter,
    }


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

def _ip_severity(freq: int) -> str:
    if freq > 20:
        return "Critical"
    if freq > 10:
        return "High"
    if freq > 4:
        return "Medium"
    return "Low"


def _domain_severity(freq: int) -> str:
    if freq > 15:
        return "High"
    if freq > 5:
        return "Medium"
    return "Low"


def _md5_severity(freq: int) -> str:
    if freq > 5:
        return "High"
    if freq > 1:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# UI-facing helpers (used by ui_dashboard.py / main.py)
# ---------------------------------------------------------------------------

def extract_iocs_from_folder(folder_path: str) -> List[Dict[str, Any]]:
    """
    Extracts Indicators of Compromise (IOCs) from .eml files in the specified
    directory.  Returns a JSON-serialisable list of IOC dictionaries with keys:
    ``ioc``, ``type``, ``freq``, ``severity``, ``tag``.
    """
    return analyze_folder(folder_path)


def analyze_folder(folder_path: str) -> List[Dict[str, Any]]:
    """
    Analyses a directory of ``.eml`` files and returns a ranked IOC list ready
    for the dashboard.  Falls back to ``DEFAULT_IOC_DATA`` when the folder is
    invalid or contains no ``.eml`` files, so the UI is never empty.

    Args:
        folder_path: Path to the folder selected by the investigator.

    Returns:
        List of IOC dicts (keys: ioc, type, freq, severity, tag),
        sorted by frequency descending, capped at top-15 IPs / top-15 domains
        / top-10 MD5 hashes.
    """
    if not folder_path or not os.path.exists(folder_path):
        return list(DEFAULT_IOC_DATA)

    eml_files = [f for f in os.listdir(folder_path) if f.lower().endswith(".eml")]
    if not eml_files:
        return list(DEFAULT_IOC_DATA)

    parsed = parse_eml_folder(folder_path)
    ipv4_counter: Counter  = parsed["_counter_ipv4"]
    domain_counter: Counter = parsed["_counter_domains"]
    md5_counter: Counter   = parsed["_counter_md5"]

    results: List[Dict[str, Any]] = []

    for ip, count in ipv4_counter.most_common(15):
        results.append({
            "ioc":      ip,
            "type":     "IP",
            "freq":     count,
            "severity": _ip_severity(count),
            "tag":      "Network IOC",
        })

    for domain, count in domain_counter.most_common(15):
        results.append({
            "ioc":      domain,
            "type":     "Domain",
            "freq":     count,
            "severity": _domain_severity(count),
            "tag":      "DNS Indicator",
        })

    for md5, count in md5_counter.most_common(10):
        results.append({
            "ioc":      md5,
            "type":     "MD5",
            "freq":     count,
            "severity": _md5_severity(count),
            "tag":      "File Hash",
        })

    if not results:
        return list(DEFAULT_IOC_DATA)

    results.sort(key=lambda x: x["freq"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Self-test entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import tempfile

    print("=" * 60)
    print(" MailIntel ioc_engine.py  –  self-test")
    print("=" * 60)

    # ── 1. Build a temporary folder with two synthetic .eml files ──────────
    DUMMY_EMAILS = [
        # email_1.eml – phishing campaign IOCs
        (
            "email_1.eml",
            """From: attacker@evil-update-auth.com
Received: from 139.59.164.251 (evil-update-auth.com)
X-Mailer: PHPMailer
Subject: Urgent: Verify your account

Click here: http://secure-login-portal-office365.net/verify
Payload hash: d41d8cd98f00b204e9800998ecf8427e
C2 beacon hash: d41d8cd98f00b204e9800998ecf8427e
Internal hop: 192.168.1.5  <- should be filtered
Loopback: 127.0.0.1        <- should be filtered
Google DNS: 8.8.8.8        <- public, kept
""",
        ),
        # email_2.eml – credential harvester + Tor exit
        (
            "email_2.eml",
            """From: noreply@accounts-verification-service.info
Received: from 185.220.101.5 (tor-exit.example.net)
Received: from 139.59.164.251
Subject: Your invoice is ready

Download: http://cdn-cloud-storage-sync.biz/invoice.exe
Malware hash: 098f6bcd4621d373cade4e832627b4f6
Alt hash: d41d8cd98f00b204e9800998ecf8427e
Private range: 10.0.0.1   <- should be filtered
""",
        ),
    ]

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Write dummy .eml files
        for fname, body in DUMMY_EMAILS:
            with open(os.path.join(tmp_dir, fname), "w", encoding="utf-8") as f:
                f.write(body)

        # ── 2. Run the parser ──────────────────────────────────────────────
        result = parse_eml_folder(tmp_dir)

    # ── 3. Print the public JSON structure ────────────────────────────────
    public = {k: v for k, v in result.items() if not k.startswith("_")}
    print("\nReturned JSON structure (summary):")
    summary = {k: v for k, v in public.items() if k != "email_logs"}
    print(json.dumps(summary, indent=2))

    print("\nPer-email event log (email_logs):")
    print(json.dumps(result["email_logs"], indent=2))

    # ── 4. Verify the CSV was created ─────────────────────────────────────
    case_path = result["case_folder_path"]
    csv_path  = os.path.join(case_path, "ioc_results.csv") if case_path else ""

    print("\n" + "-" * 60)
    print("Case folder :", case_path or "(not created)")
    print("CSV exists  :", os.path.isfile(csv_path))

    if os.path.isfile(csv_path):
        print("\nioc_results.csv contents:")
        with open(csv_path, encoding="utf-8") as f:
            print(f.read())

    print("=" * 60)
    print("Self-test complete.")
