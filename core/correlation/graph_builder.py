"""
core/correlation/graph_builder.py
Constructs a NetworkX graph of threat entities (senders, domains, IPs, hashes,
emails) and renders it using Pyvis with dark-themed styling, risk-based node
sizing, entity-type coloring, and click interactions for QWebEngineView.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urlparse

import networkx as nx
from pyvis.network import Network

from core.correlation.models import Campaign, NodeDetails
from core.scoring.risk_score import RiskScorer

logger = logging.getLogger(__name__)

# Entity Color Palette (Dark DFIR Threat Intel Theme)
ENTITY_COLORS = {
    "email": "#00f0ff",   # Vibrant Cyan
    "sender": "#f59e0b",  # Amber / Gold
    "domain": "#a78bfa",  # Soft Violet
    "ip": "#3b82f6",      # Bright Blue
    "hash": "#10b981",    # Emerald Green
    "url": "#f43f5e",     # Crimson / Rose
}

ENTITY_BORDER_COLORS = {
    "email": "#38bdf8",
    "sender": "#d97706",
    "domain": "#8b5cf6",
    "ip": "#2563eb",
    "hash": "#059669",
    "url": "#e11d48",
}


def _severity(score: float) -> str:
    if score >= 75.0:
        return "CRITICAL"
    if score >= 50.0:
        return "HIGH"
    if score >= 25.0:
        return "MEDIUM"
    return "LOW"


def _clean_domain(val: str) -> str:
    if not val:
        return ""
    val = val.strip().lower()
    if "@" in val:
        parts = val.split("@")
        return parts[-1].strip().strip("<>").strip()
    if "://" in val:
        try:
            return urlparse(val).netloc.split(":")[0].strip()
        except Exception:
            pass
    return re.sub(r"^https?://", "", val).split("/")[0].split(":")[0].strip()


class ThreatGraphBuilder:
    """Builds and styles an interconnected NetworkX graph of threat entities.

    Node Types:
    - ``email``: Represents an ingested email message
    - ``sender``: Email address from From/Reply-To
    - ``domain``: Infrastructure domain
    - ``ip``: Upstream/observed IPv4 or IPv6 address
    - ``hash``: File hash (MD5, SHA1, SHA256) of attachments
    - ``url``: Observed URL

    Node Properties:
    - Color by type (cyan, amber, purple, blue, green, crimson)
    - Size by risk score (clamped between 14.0 and 38.0)
    - Border highlighting and hover tooltips
    """

    def __init__(self, risk_scorer: RiskScorer | None = None) -> None:
        self.scorer = risk_scorer or RiskScorer()
        self.graph = nx.Graph()
        self.campaigns: list[Campaign] = []
        self._node_campaign_map: dict[str, set[str]] = {}

    def build_graph(
        self,
        emails: list[dict[str, Any]],
        email_iocs_map: dict[int, list[dict[str, Any]]],
        campaigns: list[Campaign] | None = None,
        max_nodes: int = 150,
    ) -> nx.Graph:
        """Construct the NetworkX entity relationship graph.

        Parameters
        ----------
        emails : list[dict[str, Any]]
            Email records from the database.
        email_iocs_map : dict[int, list[dict[str, Any]]]
            Mapping of email ID to its linked IOC rows.
        campaigns : list[Campaign] | None
            Pre-computed campaigns for correlation mapping.
        max_nodes : int
            Maximum number of entities to include in the visual graph to preserve
            browser rendering fluidity and responsive interactions.

        Returns
        -------
        nx.Graph
            Configured NetworkX graph.
        """
        self.graph = nx.Graph()
        self.campaigns = campaigns or []
        self._node_campaign_map = {}

        # Build reverse index of email_id -> list of campaign_ids
        email_to_camp_ids: dict[int, list[str]] = {}
        for c in self.campaigns:
            for eid in c.email_ids:
                email_to_camp_ids.setdefault(eid, []).append(c.campaign_id)

        # Track candidate nodes and prioritize high-risk and high-connectivity entities
        # 1. Add Email nodes
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

            subject = headers.get("subject") or email.get("subject") or f"Email #{eid}"
            from_addr = (headers.get("from_addr") or email.get("from_addr") or "").strip()
            first_hop = (email.get("first_hop_ip") or "").strip()
            filename = email.get("filename") or f"email_{eid}.eml"

            # Compute email risk
            iocs_for_this = email_iocs_map.get(eid, [])
            ioc_scores = {}
            for ioc in iocs_for_this:
                itype = ioc.get("type", "")
                val = ioc.get("value", "")
                freq = int(ioc.get("frequency") or 1)
                ioc_scores[val] = self.scorer.score_ioc(itype, val, frequency=freq)

            email_score_obj = self.scorer.score_email(
                from_addr=from_addr,
                reply_to=headers.get("reply_to", ""),
                ioc_scores=ioc_scores,
            )
            score = email_score_obj.score

            node_id = f"email_{eid}"
            short_label = subject[:22] + "..." if len(subject) > 22 else subject
            if not short_label.strip():
                short_label = filename

            c_ids = email_to_camp_ids.get(eid, [])
            camp_badge = f"<br><b>Campaign:</b> {', '.join(c_ids)}" if c_ids else ""

            self._add_entity_node(
                node_id=node_id,
                node_type="email",
                label=short_label,
                full_value=subject,
                risk_score=score,
                metadata={
                    "email_id": eid,
                    "filename": filename,
                    "filepath": email.get("filepath", ""),
                    "subject": subject,
                    "from_addr": from_addr,
                    "first_hop_ip": first_hop,
                    "first_seen": email.get("first_seen", ""),
                    "ioc_count": len(iocs_for_this),
                },
                campaign_ids=c_ids,
                tooltip=(
                    f"<b>[EMAIL]</b> {filename}<br>"
                    f"<b>Subject:</b> {subject}<br>"
                    f"<b>Risk:</b> {score:.1f} ({_severity(score)}){camp_badge}"
                ),
            )

            # Sender node
            if from_addr:
                sender_id = f"sender_{from_addr.lower()}"
                sender_domain = _clean_domain(from_addr)
                self._add_entity_node(
                    node_id=sender_id,
                    node_type="sender",
                    label=from_addr[:22] + "..." if len(from_addr) > 22 else from_addr,
                    full_value=from_addr,
                    risk_score=min(100.0, score * 0.9),
                    metadata={"email": from_addr, "domain": sender_domain},
                    campaign_ids=c_ids,
                    tooltip=f"<b>[SENDER]</b> {from_addr}<br><b>Domain:</b> {sender_domain}",
                )
                self.graph.add_edge(
                    node_id,
                    sender_id,
                    title="SENT_FROM",
                    color="rgba(245, 158, 11, 0.45)",
                )

                # Link sender to domain
                if sender_domain:
                    domain_id = f"domain_{sender_domain}"
                    self._add_entity_node(
                        node_id=domain_id,
                        node_type="domain",
                        label=sender_domain,
                        full_value=sender_domain,
                        risk_score=min(100.0, score * 0.8),
                        metadata={"domain": sender_domain},
                        campaign_ids=c_ids,
                        tooltip=f"<b>[DOMAIN]</b> {sender_domain}",
                    )
                    self.graph.add_edge(
                        sender_id,
                        domain_id,
                        title="SENDER_DOMAIN",
                        color="rgba(167, 139, 250, 0.45)",
                    )

            # First hop IP node
            if first_hop:
                ip_id = f"ip_{first_hop}"
                self._add_entity_node(
                    node_id=ip_id,
                    node_type="ip",
                    label=first_hop,
                    full_value=first_hop,
                    risk_score=min(100.0, score * 0.85),
                    metadata={"ip": first_hop, "role": "First External Hop"},
                    campaign_ids=c_ids,
                    tooltip=f"<b>[IP]</b> {first_hop}<br><b>Role:</b> First External Hop",
                )
                self.graph.add_edge(
                    node_id,
                    ip_id,
                    title="FIRST_HOP_IP",
                    color="rgba(59, 130, 246, 0.45)",
                )

            # Link associated IOCs
            for ioc in iocs_for_this:
                itype = ioc.get("type", "")
                val = (ioc.get("value") or "").strip()
                if not val:
                    continue

                freq = int(ioc.get("frequency") or 1)
                ioc_score_res = self.scorer.score_ioc(itype, val, frequency=freq)
                i_score = ioc_score_res.score

                if itype in ("ipv4", "ipv6"):
                    i_node_id = f"ip_{val}"
                    i_type = "ip"
                    i_label = val
                elif itype == "domain":
                    i_node_id = f"domain_{val.lower()}"
                    i_type = "domain"
                    i_label = val
                elif itype.startswith("hash_"):
                    i_node_id = f"hash_{val.lower()}"
                    i_type = "hash"
                    i_label = val[:10] + "..." if len(val) > 10 else val
                elif itype == "url":
                    i_node_id = f"url_{val}"
                    i_type = "url"
                    i_label = val[:24] + "..." if len(val) > 24 else val
                elif itype == "email":
                    i_node_id = f"sender_{val.lower()}"
                    i_type = "sender"
                    i_label = val[:20] + "..." if len(val) > 20 else val
                else:
                    continue

                self._add_entity_node(
                    node_id=i_node_id,
                    node_type=i_type,
                    label=i_label,
                    full_value=val,
                    risk_score=i_score,
                    metadata={
                        "type": itype,
                        "value": val,
                        "frequency": freq,
                        "context": ioc.get("context", ""),
                    },
                    campaign_ids=c_ids,
                    tooltip=(
                        f"<b>[{i_type.upper()}]</b> {val}<br>"
                        f"<b>Risk:</b> {i_score:.1f} ({_severity(i_score)})<br>"
                        f"<b>Corpus Frequency:</b> {freq}"
                    ),
                )
                edge_title = f"LINKED_{itype.upper()}"
                self.graph.add_edge(
                    node_id,
                    i_node_id,
                    title=edge_title,
                    color="rgba(148, 163, 184, 0.4)",
                )

                # If URL, also link to its domain
                if itype == "url":
                    dom = _clean_domain(val)
                    if dom:
                        d_id = f"domain_{dom}"
                        self._add_entity_node(
                            node_id=d_id,
                            node_type="domain",
                            label=dom,
                            full_value=dom,
                            risk_score=min(100.0, i_score * 0.8),
                            metadata={"domain": dom},
                            campaign_ids=c_ids,
                            tooltip=f"<b>[DOMAIN]</b> {dom}",
                        )
                        self.graph.add_edge(
                            i_node_id,
                            d_id,
                            title="HOSTED_ON",
                            color="rgba(167, 139, 250, 0.4)",
                        )

        # Apply maximum node threshold if needed to maintain high frame rate
        if self.graph.number_of_nodes() > max_nodes:
            self._prune_graph(max_nodes)

        return self.graph

    def _add_entity_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        full_value: str,
        risk_score: float,
        metadata: dict[str, Any],
        campaign_ids: list[str],
        tooltip: str,
    ) -> None:
        """Add or update an entity node with styled visual attributes."""
        # Calculate visual size based on risk (14.0 to 38.0)
        risk_score = min(100.0, max(0.0, float(risk_score)))
        size = round(14.0 + (risk_score / 100.0) * 24.0, 1)

        # Update campaign mapping
        if node_id not in self._node_campaign_map:
            self._node_campaign_map[node_id] = set(campaign_ids)
        else:
            self._node_campaign_map[node_id].update(campaign_ids)

        existing = self.graph.nodes.get(node_id)
        if existing:
            # Keep highest risk score
            if risk_score > existing.get("risk_score", 0.0):
                self.graph.nodes[node_id]["risk_score"] = risk_score
                self.graph.nodes[node_id]["size"] = size
                self.graph.nodes[node_id]["severity"] = _severity(risk_score)
            return

        self.graph.add_node(
            node_id,
            label=label,
            title=tooltip,
            value_full=full_value,
            entity_type=node_type,
            risk_score=risk_score,
            severity=_severity(risk_score),
            size=size,
            color={
                "background": ENTITY_COLORS.get(node_type, "#94a3b8"),
                "border": ENTITY_BORDER_COLORS.get(node_type, "#cbd5e1"),
                "highlight": {
                    "background": "#ffffff",
                    "border": ENTITY_COLORS.get(node_type, "#00f0ff"),
                },
                "hover": {
                    "background": "#ffffff",
                    "border": ENTITY_COLORS.get(node_type, "#00f0ff"),
                },
            },
            metadata=metadata,
        )

    def _prune_graph(self, max_nodes: int) -> None:
        """Prune graph to top entities ranked by degree and risk score."""
        scored_nodes = []
        for n, data in self.graph.nodes(data=True):
            deg = self.graph.degree(n)
            risk = data.get("risk_score", 0.0)
            # Weighted rank: connectivity (degree) and risk score
            rank_score = deg * 15.0 + risk
            scored_nodes.append((n, rank_score))

        scored_nodes.sort(key=lambda x: x[1], reverse=True)
        keep_nodes = set(n for n, _ in scored_nodes[:max_nodes])

        nodes_to_remove = [n for n in self.graph.nodes if n not in keep_nodes]
        self.graph.remove_nodes_from(nodes_to_remove)

    # -------------------------------------------------------------------------
    # Node Details Query
    # -------------------------------------------------------------------------
    def get_node_details(self, node_id: str) -> NodeDetails | None:
        """Retrieve detailed information and linked relationships for a node."""
        if not self.graph.has_node(node_id):
            return None

        data = self.graph.nodes[node_id]
        deg = self.graph.degree(node_id)
        camps = sorted(list(self._node_campaign_map.get(node_id, set())))

        connected = []
        for neighbor in self.graph.neighbors(node_id):
            n_data = self.graph.nodes[neighbor]
            edge_data = self.graph.get_edge_data(node_id, neighbor) or {}
            rel = edge_data.get("title") or "CONNECTED_TO"
            connected.append({
                "id": neighbor,
                "label": n_data.get("label", neighbor),
                "type": n_data.get("entity_type", "unknown"),
                "relationship": rel,
                "risk_score": n_data.get("risk_score", 0.0),
                "severity": n_data.get("severity", "LOW"),
            })

        return NodeDetails(
            node_id=node_id,
            entity_type=data.get("entity_type", "unknown"),
            label=data.get("label", node_id),
            value=data.get("value_full", node_id),
            risk_score=data.get("risk_score", 0.0),
            severity=data.get("severity", "LOW"),
            campaign_ids=camps,
            degree=deg,
            connected_nodes=connected,
            metadata=data.get("metadata", {}),
        )

    # -------------------------------------------------------------------------
    # Pyvis HTML Rendering
    # -------------------------------------------------------------------------
    def to_pyvis_network(self) -> Network:
        """Create and configure a Pyvis Network instance from the graph."""
        net = Network(
            height="100%",
            width="100%",
            bgcolor="#15181e",
            font_color="#f1f5f9",
            cdn_resources="in_line",
            directed=False,
        )
        net.from_nx(self.graph)

        options = {
            "nodes": {
                "borderWidth": 2,
                "borderWidthSelected": 4,
                "shape": "dot",
                "font": {
                    "color": "#f1f5f9",
                    "size": 13,
                    "face": "Inter, Segoe UI, sans-serif",
                },
            },
            "edges": {
                "color": {"color": "rgba(148, 163, 184, 0.35)", "highlight": "#00f0ff"},
                "smooth": {"type": "continuous", "roundness": 0.2},
                "width": 1.4,
                "hoverWidth": 2.5,
                "selectionWidth": 3.0,
            },
            "physics": {
                "forceAtlas2Based": {
                    "gravitationalConstant": -55,
                    "centralGravity": 0.015,
                    "springLength": 95,
                    "springConstant": 0.09,
                    "damping": 0.45,
                    "avoidOverlap": 0.5,
                },
                "solver": "forceAtlas2Based",
                "stabilization": {"enabled": True, "iterations": 150},
            },
            "interaction": {
                "hover": True,
                "tooltipDelay": 120,
                "hideEdgesOnDrag": False,
                "zoomView": True,
                "dragView": True,
            },
        }
        net.set_options(json.dumps(options))
        return net

    def generate_html(self) -> str:
        """Generate self-contained HTML with dark styling and click handlers."""
        net = self.to_pyvis_network()
        html = net.generate_html()

        # Custom JS hook for Qt WebEngine navigation handling
        # Intercepts selectNode and deselectNode events to update the details drawer
        qt_hook = """
        network.on("selectNode", function(params) {
            if (params.nodes && params.nodes.length > 0) {
                window.location.href = "mailintel://node/" + encodeURIComponent(params.nodes[0]);
            }
        });
        network.on("deselectNode", function(params) {
            window.location.href = "mailintel://deselect";
        });
        return network;
        """
        html = html.replace("return network;", qt_hook)

        # Inject dark UI styling for background and vis-network tooltips
        custom_style = """
        <style>
            html, body {
                margin: 0;
                padding: 0;
                width: 100%;
                height: 100%;
                background-color: #15181e !important;
                overflow: hidden !important;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            }
            #mynetwork {
                width: 100% !important;
                height: 100% !important;
                background-color: #15181e !important;
                border: none !important;
            }
            div.vis-tooltip {
                background-color: #1e222b !important;
                color: #f1f5f9 !important;
                border: 1px solid #334155 !important;
                box-shadow: 0 8px 24px rgba(0, 0, 0, 0.6) !important;
                border-radius: 8px !important;
                padding: 10px 14px !important;
                font-family: inherit !important;
                font-size: 12px !important;
                line-height: 1.5 !important;
                max-width: 320px !important;
                word-wrap: break-word !important;
            }
        </style>
        """
        html = html.replace("</head>", f"{custom_style}\n</head>")
        return html
