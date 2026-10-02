"""
core/scoring/risk_score.py
Explainable risk-scoring engine.

Computes a 0–100 risk score for individual IOCs and for whole emails by
combining threat-intel enrichment results, email authentication verdicts,
content analysis, typosquat detection, and frequency signals.  Every
point contribution is recorded as a ``(factor, points, reason)`` triple
so the UI can explain *why* a particular score was assigned.

Weights are loaded from ``data/scoring_weights.yaml`` — change that file
to retune the model with zero code edits.

Public API
----------
RiskScorer
    Stateless scorer initialised once with the YAML weights and brand list.
ScoreFactor
    Dataclass representing one factor's contribution.
IocScore / EmailScore
    Dataclasses holding the final clamped score plus the breakdown list.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data directory resolution
# ---------------------------------------------------------------------------

_DATA_DIR: Path = Path(__file__).resolve().parent.parent.parent / "data"


# ---------------------------------------------------------------------------
# Result data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScoreFactor:
    """One factor's contribution to the overall risk score.

    Attributes
    ----------
    factor : str
        Short machine-readable identifier (e.g. ``'virustotal'``).
    points : float
        Points awarded (already clamped to the factor's max).
    reason : str
        Human-readable explanation for the UI.
    """

    factor: str
    points: float
    reason: str


@dataclass
class IocScore:
    """Risk score for a single IOC.

    Attributes
    ----------
    score : float
        Final risk score clamped to [0, 100].
    breakdown : list[ScoreFactor]
        Every factor that contributed to the score.
    behaviour_tags : list[str]
        Tags for MITRE ATT&CK mapping.
    """

    score: float = 0.0
    breakdown: list[ScoreFactor] = field(default_factory=list)
    behaviour_tags: list[str] = field(default_factory=list)


@dataclass
class EmailScore:
    """Risk score for a whole email.

    Attributes
    ----------
    score : float
        Final risk score clamped to [0, 100].
    breakdown : list[ScoreFactor]
        Every factor that contributed to the score.
    behaviour_tags : list[str]
        Tags for MITRE ATT&CK mapping.
    ioc_scores : dict[str, IocScore]
        Per-IOC scores keyed by IOC value.
    """

    score: float = 0.0
    breakdown: list[ScoreFactor] = field(default_factory=list)
    behaviour_tags: list[str] = field(default_factory=list)
    ioc_scores: dict[str, IocScore] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Homoglyph table — visually similar character substitutions
# ---------------------------------------------------------------------------

# Maps Unicode look-alikes to their ASCII originals.  The detector
# normalises a domain through this table and compares against the brand
# list to find homoglyph attacks.
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic
    "\u0430": "a",  # а → a
    "\u0435": "e",  # е → e
    "\u043e": "o",  # о → o
    "\u0440": "p",  # р → p
    "\u0441": "c",  # с → c
    "\u0445": "x",  # х → x
    "\u0443": "y",  # у → y
    "\u043d": "h",  # н → h
    "\u043a": "k",  # к → k
    "\u0456": "i",  # і → i
    # Greek
    "\u03b1": "a",  # α → a
    "\u03bf": "o",  # ο → o
    "\u03b5": "e",  # ε → e
    "\u03c1": "p",  # ρ → p
    # Common substitutions
    "\u0131": "i",  # ı (dotless i) → i
    "\u1d00": "a",  # ᴀ → a
    "\u026a": "i",  # ɪ → i
    "\u1e37": "l",  # ḷ → l
    "1":      "l",  # numeral 1 → l
    "0":      "o",  # numeral 0 → o
}


def _normalize_homoglyphs(s: str) -> str:
    """Replace homoglyph characters with their ASCII equivalents."""
    return "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in s)


def _has_homoglyphs(domain: str) -> bool:
    """Return True if *domain* contains any known homoglyph characters."""
    return any(ch in _HOMOGLYPH_MAP for ch in domain)


# ---------------------------------------------------------------------------
# Levenshtein distance (pure-Python, no external dependency)
# ---------------------------------------------------------------------------

def levenshtein(s: str, t: str) -> int:
    """Compute the Levenshtein edit distance between *s* and *t*."""
    if len(s) < len(t):
        return levenshtein(t, s)
    if len(t) == 0:
        return len(s)
    prev_row = list(range(len(t) + 1))
    for i, c1 in enumerate(s):
        curr_row = [i + 1]
        for j, c2 in enumerate(t):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


# ---------------------------------------------------------------------------
# Brand list loader
# ---------------------------------------------------------------------------

def _load_brands(path: Path | None = None) -> list[str]:
    """Load brand domains from ``data/brands.txt``.

    Lines starting with ``#`` are comments; blank lines are skipped.
    Returns lowercase domain strings.
    """
    if path is None:
        path = _DATA_DIR / "brands.txt"
    if not path.is_file():
        logger.warning("Brand list not found: %s", path)
        return []
    brands: list[str] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                brands.append(stripped.lower())
    return brands


# ---------------------------------------------------------------------------
# Weights loader
# ---------------------------------------------------------------------------

def _load_weights(path: Path | None = None) -> dict[str, Any]:
    """Load scoring weights from ``data/scoring_weights.yaml``."""
    if path is None:
        path = _DATA_DIR / "scoring_weights.yaml"
    if not path.is_file():
        logger.warning("Scoring weights file not found: %s — using defaults", path)
        return {}
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data


# ---------------------------------------------------------------------------
# Domain extraction helper
# ---------------------------------------------------------------------------

_RE_EMAIL_DOMAIN = re.compile(r"@([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})")


def _extract_domain(addr: str) -> str:
    """Extract the domain part from an email address string."""
    match = _RE_EMAIL_DOMAIN.search(addr)
    if match:
        return match.group(1).lower()
    # Might already be a bare domain
    return addr.lower().strip()


# ---------------------------------------------------------------------------
# Main scorer
# ---------------------------------------------------------------------------

class RiskScorer:
    """Explainable risk scorer.

    Parameters
    ----------
    weights_path : Path or None
        Override path to the YAML weights file.
    brands_path : Path or None
        Override path to the brands list file.
    """

    def __init__(
        self,
        weights_path: Path | None = None,
        brands_path: Path | None = None,
    ) -> None:
        self._weights = _load_weights(weights_path)
        self._brands = _load_brands(brands_path)

    # -- convenience weight getters -----------------------------------------

    def _w(self, section: str, key: str, default: float = 0.0) -> float:
        """Fetch a numeric weight value."""
        return float(self._weights.get(section, {}).get(key, default))

    def _w_section(self, section: str) -> dict[str, Any]:
        return self._weights.get(section, {})

    # ======================================================================
    # IOC-level scoring
    # ======================================================================

    def score_ioc(
        self,
        ioc_type: str,
        ioc_value: str,
        enrichment_results: list[dict[str, Any]] | None = None,
        frequency: int = 1,
    ) -> IocScore:
        """Compute the risk score for a single IOC.

        Parameters
        ----------
        ioc_type : str
            IOC type (``'ipv4'``, ``'domain'``, ``'url'``, ``'hash_*'``).
        ioc_value : str
            The IOC value.
        enrichment_results : list[dict]
            List of enrichment result dicts (with keys ``provider``,
            ``verdict``, ``score``, ``tags``, ``raw``).  May be empty.
        frequency : int
            How many times this IOC has been seen across all emails.

        Returns
        -------
        IocScore
        """
        breakdown: list[ScoreFactor] = []
        tags: list[str] = []

        if enrichment_results is None:
            enrichment_results = []

        # 1. VirusTotal
        vt_factor = self._score_virustotal(enrichment_results)
        if vt_factor:
            breakdown.append(vt_factor)
            if vt_factor.points > 0:
                tags.append("malware_delivery")

        # 2. AbuseIPDB
        abuse_factor = self._score_abuseipdb(enrichment_results)
        if abuse_factor:
            breakdown.append(abuse_factor)

        # 3. Domain age
        if ioc_type == "domain":
            age_factor = self._score_domain_age(enrichment_results)
            if age_factor:
                breakdown.append(age_factor)
                if age_factor.points >= self._w("domain_age", "max_points", 15) * 0.9:
                    tags.append("newly_registered_domain")

        # 4. Lookalike / typosquat (domain IOCs only)
        if ioc_type == "domain":
            lookalike_factor = self._score_lookalike(ioc_value)
            if lookalike_factor:
                breakdown.append(lookalike_factor)
                tags.append("masquerading")

        # 5. Frequency
        freq_factor = self._score_frequency(frequency)
        if freq_factor:
            breakdown.append(freq_factor)

        total = sum(f.points for f in breakdown)
        clamped = min(100.0, max(0.0, round(total, 1)))

        return IocScore(score=clamped, breakdown=breakdown, behaviour_tags=tags)

    # ======================================================================
    # Email-level scoring
    # ======================================================================

    def score_email(
        self,
        *,
        auth_results: dict[str, str] | None = None,
        from_addr: str = "",
        reply_to: str = "",
        attachments: list[dict[str, str]] | None = None,
        ioc_scores: dict[str, "IocScore"] | None = None,
        urls: list[str] | None = None,
    ) -> EmailScore:
        """Compute the risk score for a whole email.

        Parameters
        ----------
        auth_results : dict
            Keys: ``spf``, ``dkim``, ``dmarc`` with string verdicts.
        from_addr : str
            The ``From`` header value.
        reply_to : str
            The ``Reply-To`` header value.
        attachments : list[dict]
            List of dicts with ``filename`` and ``mime_type`` keys.
        ioc_scores : dict[str, IocScore]
            Pre-computed per-IOC scores keyed by IOC value.
        urls : list[str]
            URLs extracted from the email body.

        Returns
        -------
        EmailScore
        """
        breakdown: list[ScoreFactor] = []
        tags: list[str] = []

        if auth_results is None:
            auth_results = {}
        if attachments is None:
            attachments = []
        if ioc_scores is None:
            ioc_scores = {}
        if urls is None:
            urls = []

        # 1. Authentication failures
        auth_factor = self._score_auth(auth_results)
        if auth_factor:
            breakdown.append(auth_factor)
            # Add individual failure tags for MITRE mapping
            if "spf" in auth_factor.reason.lower():
                tags.append("spf_failure")
            if "dkim" in auth_factor.reason.lower():
                tags.append("dkim_failure")
            if "dmarc" in auth_factor.reason.lower():
                tags.append("dmarc_failure")

        # 2. Reply-To mismatch
        mismatch_factor = self._score_reply_to_mismatch(from_addr, reply_to)
        if mismatch_factor:
            breakdown.append(mismatch_factor)
            tags.append("masquerading")

        # 3. Dangerous attachments
        attach_factor, attach_tags = self._score_attachments(attachments)
        if attach_factor:
            breakdown.append(attach_factor)
            tags.extend(attach_tags)

        # 4. Aggregate IOC scores (take the max contributing IOC score)
        if ioc_scores:
            max_ioc = max(ioc_scores.values(), key=lambda s: s.score)
            ioc_contribution = min(max_ioc.score * 0.5, 35.0)
            if ioc_contribution > 0:
                breakdown.append(ScoreFactor(
                    factor="ioc_intelligence",
                    points=round(ioc_contribution, 1),
                    reason=f"Highest IOC risk score: {max_ioc.score:.0f}/100",
                ))
            # Merge behaviour tags from IOCs
            for ioc_s in ioc_scores.values():
                tags.extend(ioc_s.behaviour_tags)

        # 5. URL-based signals
        if urls:
            tags.append("phishing_link")
            tags.append("user_execution_link")

        # Determine attachment-related tags
        if attachments:
            tags.append("phishing_attachment")
            tags.append("user_execution_attachment")

        total = sum(f.points for f in breakdown)
        clamped = min(100.0, max(0.0, round(total, 1)))

        # Deduplicate tags
        unique_tags = list(dict.fromkeys(tags))

        return EmailScore(
            score=clamped,
            breakdown=breakdown,
            behaviour_tags=unique_tags,
            ioc_scores=ioc_scores,
        )

    # ======================================================================
    # Per-factor scoring helpers
    # ======================================================================

    def _score_virustotal(
        self, enrichments: list[dict[str, Any]]
    ) -> ScoreFactor | None:
        """Score based on VirusTotal detections."""
        section = self._w_section("virustotal")
        max_pts = float(section.get("max_points", 30))
        min_hit = float(section.get("min_hit_points", 5))

        for er in enrichments:
            if er.get("provider") != "virustotal":
                continue
            if not er.get("success", er.get("error") is None):
                continue

            raw = er.get("raw", {})
            attrs = raw.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = (
                malicious + suspicious
                + stats.get("harmless", 0)
                + stats.get("undetected", 0)
            )

            if total == 0:
                return ScoreFactor(
                    factor="virustotal",
                    points=0.0,
                    reason="VT: no analysis results available",
                )

            # Also support the normalized score/verdict path
            ratio = (malicious + suspicious * 0.5) / total
            points = ratio * max_pts
            if malicious >= 1:
                points = max(points, min_hit)
            points = min(points, max_pts)

            return ScoreFactor(
                factor="virustotal",
                points=round(points, 1),
                reason=(
                    f"VT: {malicious}/{total} engines flagged malicious"
                    + (f", {suspicious} suspicious" if suspicious else "")
                ),
            )

        # Fallback: check normalized verdict/score
        for er in enrichments:
            if er.get("provider") != "virustotal":
                continue
            verdict = er.get("verdict", "unknown")
            score = er.get("score")
            if verdict == "unknown" and score is None:
                continue
            if score is not None:
                points = min((score / 100.0) * max_pts, max_pts)
            elif verdict == "malicious":
                points = max_pts
            elif verdict == "suspicious":
                points = max_pts * 0.5
            else:
                points = 0.0
            return ScoreFactor(
                factor="virustotal",
                points=round(points, 1),
                reason=f"VT verdict: {verdict}" + (f" (score: {score})" if score else ""),
            )

        return None

    def _score_abuseipdb(
        self, enrichments: list[dict[str, Any]]
    ) -> ScoreFactor | None:
        """Score based on AbuseIPDB confidence."""
        section = self._w_section("abuseipdb")
        max_pts = float(section.get("max_points", 20))

        for er in enrichments:
            if er.get("provider") != "abuseipdb":
                continue
            if not er.get("success", er.get("error") is None):
                continue

            # Try raw response first
            raw = er.get("raw", {})
            confidence = raw.get("data", {}).get("abuseConfidenceScore")

            # Fall back to the normalized score
            if confidence is None:
                confidence = er.get("score", 0)

            confidence = float(confidence or 0)
            points = (confidence / 100.0) * max_pts
            points = min(points, max_pts)

            return ScoreFactor(
                factor="abuseipdb",
                points=round(points, 1),
                reason=f"AbuseIPDB confidence: {confidence:.0f}%",
            )

        return None

    def _score_domain_age(
        self, enrichments: list[dict[str, Any]]
    ) -> ScoreFactor | None:
        """Score based on domain registration age (from RDAP)."""
        section = self._w_section("domain_age")
        max_pts = float(section.get("max_points", 15))
        newly = int(section.get("newly_registered_days", 7))
        recently = int(section.get("recently_registered_days", 30))
        young = int(section.get("young_domain_days", 90))

        for er in enrichments:
            if er.get("provider") != "rdap":
                continue
            if not er.get("success", er.get("error") is None):
                continue

            # Extract age from tags (format: "age:NNd")
            tags = er.get("tags", [])
            age_days: int | None = None
            for tag in tags:
                if tag.startswith("age:") and tag.endswith("d"):
                    try:
                        age_days = int(tag[4:-1])
                    except ValueError:
                        pass

            if age_days is None:
                # Try verdict-based fallback
                verdict = er.get("verdict", "unknown")
                if verdict == "malicious":
                    return ScoreFactor(
                        factor="domain_age",
                        points=max_pts,
                        reason="RDAP: newly registered domain (verdict: malicious)",
                    )
                continue

            if age_days < newly:
                points = max_pts
                reason = f"Domain registered {age_days}d ago (< {newly}d — newly registered)"
            elif age_days < recently:
                points = max_pts * 0.7
                reason = f"Domain registered {age_days}d ago (< {recently}d — recently registered)"
            elif age_days < young:
                points = max_pts * 0.4
                reason = f"Domain registered {age_days}d ago (< {young}d — young domain)"
            else:
                points = 0.0
                reason = f"Domain registered {age_days}d ago (established)"

            return ScoreFactor(
                factor="domain_age",
                points=round(min(points, max_pts), 1),
                reason=reason,
            )

        return None

    def _score_auth(
        self, auth_results: dict[str, str]
    ) -> ScoreFactor | None:
        """Score SPF/DKIM/DMARC failures."""
        section = self._w_section("auth_failure")
        max_pts = float(section.get("max_points", 15))
        spf_pts = float(section.get("spf_fail", 6))
        dkim_pts = float(section.get("dkim_fail", 5))
        dmarc_pts = float(section.get("dmarc_fail", 8))

        points = 0.0
        reasons: list[str] = []

        spf = auth_results.get("spf", "none").lower()
        dkim = auth_results.get("dkim", "none").lower()
        dmarc = auth_results.get("dmarc", "none").lower()

        if spf in ("fail", "softfail"):
            points += spf_pts
            reasons.append(f"SPF {spf}")
        if dkim in ("fail",):
            points += dkim_pts
            reasons.append("DKIM fail")
        if dmarc in ("fail",):
            points += dmarc_pts
            reasons.append("DMARC fail")

        if points == 0:
            return None

        points = min(points, max_pts)
        return ScoreFactor(
            factor="auth_failure",
            points=round(points, 1),
            reason="Auth failures: " + ", ".join(reasons),
        )

    def _score_reply_to_mismatch(
        self, from_addr: str, reply_to: str
    ) -> ScoreFactor | None:
        """Score Reply-To / From domain mismatch."""
        if not from_addr or not reply_to:
            return None

        from_domain = _extract_domain(from_addr)
        reply_domain = _extract_domain(reply_to)

        if not from_domain or not reply_domain:
            return None
        if from_domain == reply_domain:
            return None

        max_pts = self._w("reply_to_mismatch", "max_points", 10)
        return ScoreFactor(
            factor="reply_to_mismatch",
            points=max_pts,
            reason=f"Reply-To domain ({reply_domain}) ≠ From domain ({from_domain})",
        )

    def _score_attachments(
        self, attachments: list[dict[str, str]]
    ) -> tuple[ScoreFactor | None, list[str]]:
        """Score dangerous attachment types and macro indicators."""
        section = self._w_section("dangerous_attachment")
        max_pts = float(section.get("max_points", 15))
        dangerous_exts = set(section.get("extensions", []))
        macro_exts = set(section.get("macro_extensions", []))
        macro_pts = float(section.get("macro_points", 12))

        tags: list[str] = []
        points = 0.0
        reasons: list[str] = []

        for att in attachments:
            filename = att.get("filename", "").lower()
            _, ext = os.path.splitext(filename)

            # Check for double extension (e.g. invoice.pdf.exe)
            parts = filename.rsplit(".", 2)
            if len(parts) >= 3:
                real_ext = "." + parts[-1]
                if real_ext in dangerous_exts:
                    points = max_pts
                    reasons.append(f"Double extension: {filename}")
                    tags.append("masquerading_double_extension")

            if ext in dangerous_exts:
                points = max(points, max_pts)
                reasons.append(f"Dangerous attachment: {filename}")
                if ext in (".js", ".vbs", ".wsf"):
                    tags.append("script_execution")
                elif ext == ".ps1":
                    tags.append("powershell_execution")
                elif ext in (".iso", ".img", ".vhd"):
                    tags.append("disk_image_delivery")

            if ext in macro_exts:
                points = max(points, macro_pts)
                reasons.append(f"Macro-enabled: {filename}")
                tags.append("macro_execution")

        if points == 0:
            return None, tags

        points = min(points, max_pts)
        return (
            ScoreFactor(
                factor="dangerous_attachment",
                points=round(points, 1),
                reason="; ".join(reasons),
            ),
            tags,
        )

    def _score_lookalike(self, domain: str) -> ScoreFactor | None:
        """Detect typosquat / homoglyph domains against the brand list."""
        section = self._w_section("lookalike")
        threshold = int(section.get("levenshtein_threshold", 2))
        homoglyph_pts = float(section.get("homoglyph_points", 15))
        levenshtein_pts = float(section.get("levenshtein_points", 12))
        max_pts = float(section.get("max_points", 15))

        domain_lower = domain.lower()

        # 1. Homoglyph check — normalise and compare
        if _has_homoglyphs(domain_lower):
            normalised = _normalize_homoglyphs(domain_lower)
            for brand in self._brands:
                if normalised == brand:
                    points = min(homoglyph_pts, max_pts)
                    return ScoreFactor(
                        factor="lookalike",
                        points=round(points, 1),
                        reason=(
                            f"Homoglyph attack: '{domain}' looks like "
                            f"'{brand}' after normalisation"
                        ),
                    )

        # 2. Levenshtein distance check
        # Extract the registrable domain (drop subdomains)
        parts = domain_lower.split(".")
        if len(parts) >= 2:
            registrable = ".".join(parts[-2:])
        else:
            registrable = domain_lower

        for brand in self._brands:
            if registrable == brand:
                continue  # exact match = it IS the brand, not a lookalike
            dist = levenshtein(registrable, brand)
            if dist <= threshold:
                points = min(levenshtein_pts, max_pts)
                return ScoreFactor(
                    factor="lookalike",
                    points=round(points, 1),
                    reason=(
                        f"Typosquat: '{registrable}' is {dist} edit(s) "
                        f"from '{brand}'"
                    ),
                )

        return None

    def _score_frequency(self, frequency: int) -> ScoreFactor | None:
        """Score based on IOC frequency across emails."""
        section = self._w_section("ioc_frequency")
        max_pts = float(section.get("max_points", 10))
        high_thresh = int(section.get("high_freq_threshold", 20))

        if frequency <= 1:
            return None

        points = min((frequency / high_thresh) * max_pts, max_pts)
        return ScoreFactor(
            factor="ioc_frequency",
            points=round(points, 1),
            reason=f"IOC seen {frequency} times across emails",
        )

