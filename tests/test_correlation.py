"""
tests/test_correlation.py
Unit tests for core/correlation:
- Campaign clustering via shared IOCs, sender infrastructure, and TF-IDF subject similarity
- Threat graph builder with NetworkX and Pyvis HTML rendering
- Node color by type and size by risk score
- Node details query and Qt click interaction hooks
"""
import json

import pytest

from core.correlation import (
    ENTITY_COLORS,
    CampaignClusterer,
    NodeDetails,
    ThreatGraphBuilder,
)


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------
@pytest.fixture
def sample_emails():
    return [
        {
            "id": 1,
            "filename": "invoice_urgent.eml",
            "headers_json": json.dumps({
                "subject": "Urgent Invoice 9823 overdue payment",
                "from_addr": "billing@fake-finance.com",
                "reply_to": "attacker@darkweb.io",
            }),
            "first_hop_ip": "198.51.100.10",
            "first_seen": "2026-10-10T12:00:00Z",
        },
        {
            "id": 2,
            "filename": "invoice_reminder.eml",
            "headers_json": json.dumps({
                "subject": "Re: Urgent Invoice 9823 overdue payment required",
                "from_addr": "support@fake-finance.com",
                "reply_to": "attacker@darkweb.io",
            }),
            "first_hop_ip": "198.51.100.10",
            "first_seen": "2026-10-10T12:05:00Z",
        },
        {
            "id": 3,
            "filename": "payroll_update.eml",
            "headers_json": json.dumps({
                "subject": "Annual Employee Payroll Direct Deposit Verification",
                "from_addr": "hr@corporation-portal.com",
                "reply_to": "",
            }),
            "first_hop_ip": "203.0.113.5",
            "first_seen": "2026-10-10T12:10:00Z",
        },
    ]


@pytest.fixture
def sample_email_iocs_map():
    return {
        1: [
            {"id": 101, "type": "ipv4", "value": "198.51.100.10", "frequency": 5, "context": "first_hop"},
            {"id": 102, "type": "domain", "value": "fake-finance.com", "frequency": 4, "context": "sender"},
            {"id": 103, "type": "url", "value": "https://fake-finance.com/login", "frequency": 2, "context": "body_url"},
            {"id": 104, "type": "hash_sha256", "value": "a" * 64, "frequency": 2, "context": "attachment"},
        ],
        2: [
            {"id": 101, "type": "ipv4", "value": "198.51.100.10", "frequency": 5, "context": "first_hop"},
            {"id": 104, "type": "hash_sha256", "value": "a" * 64, "frequency": 2, "context": "attachment"},
        ],
        3: [
            {"id": 201, "type": "domain", "value": "corporation-portal.com", "frequency": 1, "context": "sender"},
            {"id": 202, "type": "url", "value": "https://corporation-portal.com/verify", "frequency": 1, "context": "body_url"},
        ],
    }


# -----------------------------------------------------------------------------
# CampaignClusterer Tests
# -----------------------------------------------------------------------------
class TestCampaignClusterer:
    def test_tfidf_cosine_similarity(self):
        clusterer = CampaignClusterer(tfidf_threshold=0.6)
        texts = [
            "Urgent invoice payment required immediately",
            "Re: Urgent invoice payment required immediately now",
            "Completely unrelated company meeting lunch notes",
        ]
        pairs = clusterer.compute_tfidf_similarities(texts)
        assert len(pairs) == 1
        i, j, sim = pairs[0]
        assert i == 0 and j == 1
        assert sim >= 0.6

    def test_tfidf_empty_or_short_texts(self):
        clusterer = CampaignClusterer(tfidf_threshold=0.7)
        assert clusterer.compute_tfidf_similarities([]) == []
        assert clusterer.compute_tfidf_similarities(["hello"]) == []
        assert clusterer.compute_tfidf_similarities(["", "   ", "a"]) == []

    def test_cluster_emails_shared_iocs_and_sender(self, sample_emails, sample_email_iocs_map):
        clusterer = CampaignClusterer(tfidf_threshold=0.6)
        campaigns = clusterer.cluster_emails(sample_emails, sample_email_iocs_map)

        assert len(campaigns) >= 2
        # Email 1 and 2 share IOCs (IP, hash), reply_to (attacker@darkweb.io), first_hop_ip, and subject TF-IDF
        camp1 = campaigns[0]
        assert 1 in camp1.email_ids
        assert 2 in camp1.email_ids
        assert 3 not in camp1.email_ids
        assert camp1.campaign_id == "CMP-001"
        assert len(camp1.shared_ips) >= 1
        assert "198.51.100.10" in camp1.shared_ips
        assert "a" * 64 in camp1.shared_hashes
        assert camp1.risk_score > 0

        # Email 3 is in its own campaign
        camp2 = campaigns[1]
        assert 3 in camp2.email_ids

    def test_cluster_empty_input(self):
        clusterer = CampaignClusterer()
        assert clusterer.cluster_emails([]) == []


# -----------------------------------------------------------------------------
# ThreatGraphBuilder Tests
# -----------------------------------------------------------------------------
class TestThreatGraphBuilder:
    def test_build_graph_nodes_and_edges(self, sample_emails, sample_email_iocs_map):
        clusterer = CampaignClusterer()
        campaigns = clusterer.cluster_emails(sample_emails, sample_email_iocs_map)

        builder = ThreatGraphBuilder()
        graph = builder.build_graph(sample_emails, sample_email_iocs_map, campaigns=campaigns)

        assert graph.number_of_nodes() > 0
        assert graph.number_of_edges() > 0

        # Verify email nodes
        assert graph.has_node("email_1")
        assert graph.has_node("email_2")
        assert graph.has_node("email_3")
        assert graph.nodes["email_1"]["entity_type"] == "email"

        # Verify sender nodes
        assert graph.has_node("sender_billing@fake-finance.com")
        assert graph.nodes["sender_billing@fake-finance.com"]["entity_type"] == "sender"

        # Verify IP nodes
        assert graph.has_node("ip_198.51.100.10")
        assert graph.nodes["ip_198.51.100.10"]["entity_type"] == "ip"

        # Verify domain nodes
        assert graph.has_node("domain_fake-finance.com")
        assert graph.nodes["domain_fake-finance.com"]["entity_type"] == "domain"

        # Verify hash nodes
        assert graph.has_node(f"hash_{'a' * 64}")
        assert graph.nodes[f"hash_{'a' * 64}"]["entity_type"] == "hash"

    def test_node_color_by_type(self, sample_emails, sample_email_iocs_map):
        builder = ThreatGraphBuilder()
        graph = builder.build_graph(sample_emails, sample_email_iocs_map)

        # Check entity colors match palette
        assert graph.nodes["email_1"]["color"]["background"] == ENTITY_COLORS["email"]
        assert graph.nodes["sender_billing@fake-finance.com"]["color"]["background"] == ENTITY_COLORS["sender"]
        assert graph.nodes["ip_198.51.100.10"]["color"]["background"] == ENTITY_COLORS["ip"]
        assert graph.nodes["domain_fake-finance.com"]["color"]["background"] == ENTITY_COLORS["domain"]
        assert graph.nodes[f"hash_{'a' * 64}"]["color"]["background"] == ENTITY_COLORS["hash"]

    def test_node_size_by_risk(self, sample_emails, sample_email_iocs_map):
        builder = ThreatGraphBuilder()
        graph = builder.build_graph(sample_emails, sample_email_iocs_map)

        for n, data in graph.nodes(data=True):
            size = data.get("size")
            risk = data.get("risk_score")
            assert size is not None
            assert 14.0 <= size <= 38.0
            # Higher risk score should have larger or equal size
            expected_size = round(14.0 + (risk / 100.0) * 24.0, 1)
            assert abs(size - expected_size) < 0.2

    def test_get_node_details(self, sample_emails, sample_email_iocs_map):
        clusterer = CampaignClusterer()
        campaigns = clusterer.cluster_emails(sample_emails, sample_email_iocs_map)

        builder = ThreatGraphBuilder()
        builder.build_graph(sample_emails, sample_email_iocs_map, campaigns=campaigns)

        details = builder.get_node_details("email_1")
        assert details is not None
        assert isinstance(details, NodeDetails)
        assert details.node_id == "email_1"
        assert details.entity_type == "email"
        assert details.degree > 0
        assert len(details.connected_nodes) > 0
        assert "CMP-001" in details.campaign_ids
        assert details.metadata.get("filename") == "invoice_urgent.eml"

        # Unknown node returns None
        assert builder.get_node_details("non_existent_node") is None

    def test_generate_html_pyvis_with_qt_hooks(self, sample_emails, sample_email_iocs_map):
        builder = ThreatGraphBuilder()
        builder.build_graph(sample_emails, sample_email_iocs_map)

        html = builder.generate_html()
        assert isinstance(html, str)
        assert len(html) > 1000
        # Check for Pyvis Network instantiation
        assert "new vis.Network" in html or "vis.Network" in html
        # Check for dark background
        assert "#15181e" in html
        # Check for Qt WebEngine navigation hook
        assert "mailintel://node/" in html
        assert "mailintel://deselect" in html

    def test_graph_pruning_max_nodes(self, sample_emails, sample_email_iocs_map):
        builder = ThreatGraphBuilder()
        # Build with low max_nodes limit
        graph = builder.build_graph(sample_emails, sample_email_iocs_map, max_nodes=5)
        assert graph.number_of_nodes() <= 5
