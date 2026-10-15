"""
core/correlation/models.py
Data models for campaign clustering and threat graph visualization.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Campaign:
    """Represents a threat campaign clustered from multiple correlated emails.

    Attributes
    ----------
    campaign_id : str
        Unique identifier (e.g. 'CMP-001').
    name : str
        Human-readable summary or title for the campaign.
    email_ids : list[int]
        List of email row IDs belonging to this campaign.
    shared_iocs : list[dict[str, Any]]
        IOC records that link emails within this campaign.
    shared_senders : list[str]
        Sender addresses associated with this campaign.
    shared_domains : list[str]
        Domains referenced across emails in this campaign.
    shared_ips : list[str]
        IP addresses seen across emails in this campaign.
    shared_hashes : list[str]
        Attachment hashes seen across emails in this campaign.
    subject_samples : list[str]
        Representative email subjects from the campaign.
    risk_score : float
        Overall risk score for the campaign (0.0 to 100.0).
    severity : str
        Qualitative severity ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
    """

    campaign_id: str
    name: str = ""
    email_ids: list[int] = field(default_factory=list)
    shared_iocs: list[dict[str, Any]] = field(default_factory=list)
    shared_senders: list[str] = field(default_factory=list)
    shared_domains: list[str] = field(default_factory=list)
    shared_ips: list[str] = field(default_factory=list)
    shared_hashes: list[str] = field(default_factory=list)
    subject_samples: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    severity: str = "LOW"


@dataclass
class NodeDetails:
    """Metadata and relationship details for a single graph node.

    Attributes
    ----------
    node_id : str
        Graph node identifier (e.g. 'email_1', 'ip_1.2.3.4').
    entity_type : str
        Entity type: 'email', 'sender', 'domain', 'ip', 'hash', 'url'.
    label : str
        Display label on the graph.
    value : str
        Full entity value (e.g. IP address, full URL, email subject).
    risk_score : float
        Risk score (0.0 to 100.0).
    severity : str
        Qualitative severity ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
    campaign_ids : list[str]
        Campaign IDs associated with this entity.
    degree : int
        Number of adjacent edges in the graph.
    connected_nodes : list[dict[str, Any]]
        List of connected entity dicts ({'id': ..., 'label': ..., 'type': ..., 'relationship': ...}).
    metadata : dict[str, Any]
        Additional context (first seen, filename, enrichments, headers, etc.).
    """

    node_id: str
    entity_type: str
    label: str
    value: str
    risk_score: float = 0.0
    severity: str = "LOW"
    campaign_ids: list[str] = field(default_factory=list)
    degree: int = 0
    connected_nodes: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
