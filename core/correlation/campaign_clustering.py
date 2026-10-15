"""
core/correlation/campaign_clustering.py
Cluster emails into campaigns using shared IOCs, sender infrastructure, and
subject/body TF-IDF cosine similarity.
"""
from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

import networkx as nx
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from core.correlation.models import Campaign
from core.scoring.risk_score import RiskScorer

logger = logging.getLogger(__name__)


def extract_domain_from_email_or_url(val: str) -> str:
    """Extract clean domain from email address, URL, or raw domain string."""
    if not val:
        return ""
    val = val.strip().lower()
    if "@" in val:
        parts = val.split("@")
        return parts[-1].strip().strip("<>").strip()
    if "://" in val:
        try:
            parsed = urlparse(val)
            netloc = parsed.netloc.split(":")[0]
            return netloc.strip()
        except Exception:
            pass
    # Raw domain or host
    domain = re.sub(r"^https?://", "", val).split("/")[0].split(":")[0]
    return domain.strip()


class CampaignClusterer:
    """Clusters emails into attack campaigns using multi-signal correlation.

    Correlation signals:
    1. Shared IOCs: Identical IP, domain, URL, or attachment hash.
    2. Shared Sender Infrastructure: Identical sender address, reply-to address,
       or initial upstream sending IP (first external hop).
    3. Content/Subject Similarity: TF-IDF vectorisation and cosine similarity
       matching phishing templates or campaign subject variants.

    Parameters
    ----------
    tfidf_threshold : float
        Minimum cosine similarity (0.0 to 1.0) to connect emails on subject text.
    min_shared_iocs : int
        Minimum shared IOCs required for an IOC correlation link.
    risk_scorer : RiskScorer | None
        Optional risk scoring engine to score constituent IOCs and emails.
    """

    def __init__(
        self,
        tfidf_threshold: float = 0.65,
        min_shared_iocs: int = 1,
        risk_scorer: RiskScorer | None = None,
    ) -> None:
        self.tfidf_threshold = float(tfidf_threshold)
        self.min_shared_iocs = max(1, min_shared_iocs)
        self.scorer = risk_scorer or RiskScorer()

    # -------------------------------------------------------------------------
    # TF-IDF Cosine Similarity
    # -------------------------------------------------------------------------
    def compute_tfidf_similarities(
        self, texts: list[str]
    ) -> list[tuple[int, int, float]]:
        """Compute pairwise cosine similarities across a list of texts.

        Returns
        -------
        list[tuple[int, int, float]]
            List of (index_a, index_b, similarity_score) exceeding the threshold.
        """
        if len(texts) < 2:
            return []

        # Filter out empty or whitespace-only texts while preserving original indices
        valid_indices: list[int] = []
        clean_texts: list[str] = []
        for idx, text in enumerate(texts):
            clean = (text or "").strip()
            # Clean common subject reply/forward noise for better campaign clustering
            clean = re.sub(r"^(re|fwd|fw):\s*", "", clean, flags=re.IGNORECASE).strip()
            if len(clean) >= 3:
                valid_indices.append(idx)
                clean_texts.append(clean)

        if len(clean_texts) < 2:
            return []

        try:
            vectorizer = TfidfVectorizer(
                token_pattern=r"(?u)\b\w+\b",
                stop_words="english",
                max_features=1000,
                lowercase=True,
            )
            tfidf_matrix = vectorizer.fit_transform(clean_texts)
            if tfidf_matrix.shape[1] == 0:
                return []

            sim_matrix = cosine_similarity(tfidf_matrix)
            pairs: list[tuple[int, int, float]] = []
            n = len(valid_indices)
            for i in range(n):
                for j in range(i + 1, n):
                    score = float(sim_matrix[i, j])
                    if score >= self.tfidf_threshold:
                        pairs.append((valid_indices[i], valid_indices[j], round(score, 3)))
            return pairs
        except Exception as exc:
            logger.debug("TF-IDF similarity computation skipped: %s", exc)
            return []

    # -------------------------------------------------------------------------
    # Clustering Core
    # -------------------------------------------------------------------------
    def cluster_emails(
        self,
        emails: list[dict[str, Any]],
        email_iocs_map: dict[int, list[dict[str, Any]]] | None = None,
    ) -> list[Campaign]:
        """Cluster emails into campaigns based on shared infrastructure and content.

        Parameters
        ----------
        emails : list[dict[str, Any]]
            Email records from SQLite (id, headers_json, first_hop_ip, filename, etc.).
        email_iocs_map : dict[int, list[dict[str, Any]]] | None
            Mapping from email_id to list of IOC records linked to that email.

        Returns
        -------
        list[Campaign]
            List of detected campaigns sorted by size and risk score.
        """
        if not emails:
            return []

        if email_iocs_map is None:
            email_iocs_map = {}

        # 1. Build an email-to-email correlation graph
        g = nx.Graph()
        email_by_id: dict[int, dict[str, Any]] = {}
        email_subjects: list[str] = []
        email_id_list: list[int] = []

        for email in emails:
            eid = int(email["id"])
            email_by_id[eid] = email
            g.add_node(eid)
            email_id_list.append(eid)

            # Parse headers for subject and sender info
            headers = {}
            if isinstance(email.get("headers_json"), str):
                try:
                    headers = json.loads(email["headers_json"] or "{}")
                except Exception:
                    headers = {}
            elif isinstance(email.get("headers_json"), dict):
                headers = email["headers_json"]

            subject = headers.get("subject", "") or email.get("subject", "")
            email_subjects.append(subject)

        # 2. Correlate via Shared IOCs
        # Map: ioc_key -> list of email_ids
        ioc_to_emails: dict[str, list[int]] = defaultdict(list)
        all_iocs_by_email: dict[int, list[dict[str, Any]]] = defaultdict(list)

        for eid, iocs in email_iocs_map.items():
            if eid not in email_by_id:
                continue
            for ioc in iocs:
                val = (ioc.get("value") or "").strip().lower()
                itype = (ioc.get("type") or "").strip().lower()
                if not val:
                    continue
                ioc_key = f"{itype}:{val}"
                ioc_to_emails[ioc_key].append(eid)
                all_iocs_by_email[eid].append(ioc)

        for ioc_key, linked_eids in ioc_to_emails.items():
            unique_eids = list(dict.fromkeys(linked_eids))
            if len(unique_eids) >= 2:
                for i in range(len(unique_eids)):
                    for j in range(i + 1, len(unique_eids)):
                        e1, e2 = unique_eids[i], unique_eids[j]
                        if g.has_edge(e1, e2):
                            g[e1][e2]["reasons"].add(f"Shared IOC ({ioc_key})")
                        else:
                            g.add_edge(e1, e2, reasons={f"Shared IOC ({ioc_key})"})

        # 3. Correlate via Shared Sender Infrastructure
        sender_to_emails: dict[str, list[int]] = defaultdict(list)
        hop_ip_to_emails: dict[str, list[int]] = defaultdict(list)

        for email in emails:
            eid = int(email["id"])
            headers = {}
            if isinstance(email.get("headers_json"), str):
                try:
                    headers = json.loads(email["headers_json"] or "{}")
                except Exception:
                    pass
            elif isinstance(email.get("headers_json"), dict):
                headers = email["headers_json"]

            from_addr = (headers.get("from_addr") or email.get("from_addr") or "").strip().lower()
            reply_to = (headers.get("reply_to") or email.get("reply_to") or "").strip().lower()
            first_hop = (email.get("first_hop_ip") or "").strip()

            if from_addr:
                sender_to_emails[from_addr].append(eid)
            if reply_to and reply_to != from_addr:
                sender_to_emails[reply_to].append(eid)
            if first_hop:
                hop_ip_to_emails[first_hop].append(eid)

        for sender, linked_eids in sender_to_emails.items():
            unique_eids = list(dict.fromkeys(linked_eids))
            if len(unique_eids) >= 2:
                for i in range(len(unique_eids)):
                    for j in range(i + 1, len(unique_eids)):
                        e1, e2 = unique_eids[i], unique_eids[j]
                        reason = f"Shared Sender ({sender})"
                        if g.has_edge(e1, e2):
                            g[e1][e2]["reasons"].add(reason)
                        else:
                            g.add_edge(e1, e2, reasons={reason})

        for hop_ip, linked_eids in hop_ip_to_emails.items():
            unique_eids = list(dict.fromkeys(linked_eids))
            if len(unique_eids) >= 2:
                for i in range(len(unique_eids)):
                    for j in range(i + 1, len(unique_eids)):
                        e1, e2 = unique_eids[i], unique_eids[j]
                        reason = f"Shared Sending Hop IP ({hop_ip})"
                        if g.has_edge(e1, e2):
                            g[e1][e2]["reasons"].add(reason)
                        else:
                            g.add_edge(e1, e2, reasons={reason})

        # 4. Correlate via TF-IDF Subject/Body Cosine Similarity
        sim_pairs = self.compute_tfidf_similarities(email_subjects)
        for idx_a, idx_b, score in sim_pairs:
            e1 = email_id_list[idx_a]
            e2 = email_id_list[idx_b]
            reason = f"Subject Similarity ({int(score * 100)}%)"
            if g.has_edge(e1, e2):
                g[e1][e2]["reasons"].add(reason)
            else:
                g.add_edge(e1, e2, reasons={reason})

        # 5. Extract Connected Components as Campaigns
        components = list(nx.connected_components(g))
        # Sort components: multi-node clusters first, largest first
        components.sort(key=lambda comp: len(comp), reverse=True)

        campaigns: list[Campaign] = []
        for c_idx, component in enumerate(components, start=1):
            comp_eids = sorted(list(component))
            camp_id = f"CMP-{c_idx:03d}"

            # Aggregate campaign metrics
            camp_senders: set[str] = set()
            camp_domains: set[str] = set()
            camp_ips: set[str] = set()
            camp_hashes: set[str] = set()
            camp_subjects: list[str] = []
            camp_iocs: list[dict[str, Any]] = []
            seen_ioc_keys: set[str] = set()

            for eid in comp_eids:
                email = email_by_id[eid]
                headers = {}
                if isinstance(email.get("headers_json"), str):
                    try:
                        headers = json.loads(email["headers_json"] or "{}")
                    except Exception:
                        pass
                elif isinstance(email.get("headers_json"), dict):
                    headers = email["headers_json"]

                from_addr = (headers.get("from_addr") or email.get("from_addr") or "").strip()
                if from_addr:
                    camp_senders.add(from_addr)
                    dom = extract_domain_from_email_or_url(from_addr)
                    if dom:
                        camp_domains.add(dom)

                first_hop = (email.get("first_hop_ip") or "").strip()
                if first_hop:
                    camp_ips.add(first_hop)

                subj = (headers.get("subject") or email.get("subject") or "").strip()
                if subj and subj not in camp_subjects:
                    camp_subjects.append(subj)

                for ioc in all_iocs_by_email.get(eid, []):
                    itype = ioc.get("type", "")
                    val = ioc.get("value", "")
                    key = f"{itype}:{val}"
                    if key not in seen_ioc_keys:
                        seen_ioc_keys.add(key)
                        camp_iocs.append(ioc)

                    if itype in ("ipv4", "ipv6"):
                        camp_ips.add(val)
                    elif itype == "domain":
                        camp_domains.add(val)
                    elif itype == "url":
                        dom = extract_domain_from_email_or_url(val)
                        if dom:
                            camp_domains.add(dom)
                    elif itype.startswith("hash_"):
                        camp_hashes.add(val)
                    elif itype == "email":
                        camp_senders.add(val)
                        dom = extract_domain_from_email_or_url(val)
                        if dom:
                            camp_domains.add(dom)

            # Compute campaign risk
            total_ioc_score = 0.0
            max_ioc_score = 0.0
            for ioc in camp_iocs:
                itype = ioc.get("type", "")
                val = ioc.get("value", "")
                freq = int(ioc.get("frequency") or 1)
                s = self.scorer.score_ioc(ioc_type=itype, ioc_value=val, frequency=freq)
                total_ioc_score += s.score
                if s.score > max_ioc_score:
                    max_ioc_score = s.score

            avg_score = (total_ioc_score / len(camp_iocs)) if camp_iocs else 0.0
            # Campaign score blends max IOC risk with average and size amplifier
            size_boost = min(15.0, len(comp_eids) * 2.0)
            camp_risk = min(100.0, max(0.0, round(max(max_ioc_score, avg_score + size_boost), 1)))

            severity = "LOW"
            if camp_risk >= 75.0:
                severity = "CRITICAL"
            elif camp_risk >= 50.0:
                severity = "HIGH"
            elif camp_risk >= 25.0:
                severity = "MEDIUM"

            # Campaign naming heuristic
            name = ""
            if camp_domains:
                top_domain = sorted(list(camp_domains))[0]
                name = f"Campaign {camp_id} [{top_domain}]"
            elif camp_subjects:
                short_subj = camp_subjects[0]
                if len(short_subj) > 35:
                    short_subj = short_subj[:32] + "..."
                name = f"Campaign {camp_id} - \"{short_subj}\""
            elif camp_senders:
                name = f"Campaign {camp_id} [{sorted(list(camp_senders))[0]}]"
            else:
                name = f"Campaign {camp_id} ({len(comp_eids)} emails)"

            campaign = Campaign(
                campaign_id=camp_id,
                name=name,
                email_ids=comp_eids,
                shared_iocs=camp_iocs,
                shared_senders=sorted(list(camp_senders)),
                shared_domains=sorted(list(camp_domains)),
                shared_ips=sorted(list(camp_ips)),
                shared_hashes=sorted(list(camp_hashes)),
                subject_samples=camp_subjects[:5],
                risk_score=camp_risk,
                severity=severity,
            )
            campaigns.append(campaign)

        return campaigns
