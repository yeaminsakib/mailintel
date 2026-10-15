"""
tests/test_export.py
Unit tests for STIX 2.1, MISP JSON, HTML, and PDF incident report exporters.
"""
from __future__ import annotations

import json

import pytest

from core.export import MispExporter, ReportExporter, StixExporter


@pytest.fixture
def sample_iocs():
    return [
        {"id": 1, "type": "ipv4", "value": "198.51.100.10", "frequency": 5, "first_seen": "2026-10-10T10:00:00Z", "last_seen": "2026-10-10T12:00:00Z"},
        {"id": 2, "type": "domain", "value": "phish-bank.com", "frequency": 3, "first_seen": "2026-10-10T10:00:00Z", "last_seen": "2026-10-10T12:00:00Z"},
        {"id": 3, "type": "url", "value": "https://phish-bank.com/login", "frequency": 2, "first_seen": "2026-10-10T10:00:00Z", "last_seen": "2026-10-10T12:00:00Z"},
        {"id": 4, "type": "email", "value": "attacker@evil.org", "frequency": 4, "first_seen": "2026-10-10T10:00:00Z", "last_seen": "2026-10-10T12:00:00Z"},
        {"id": 5, "type": "hash_sha256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "frequency": 1, "first_seen": "2026-10-10T10:00:00Z", "last_seen": "2026-10-10T12:00:00Z"},
    ]


@pytest.fixture
def sample_emails():
    return [
        {
            "id": 1,
            "filename": "urgent_invoice.eml",
            "filepath": "/evidence/urgent_invoice.eml",
            "file_sha256": "a" * 64,
            "headers_json": json.dumps({
                "subject": "Urgent Wire Transfer Overdue",
                "from_addr": "billing@phish-bank.com",
            }),
            "first_seen": "2026-10-10T10:00:00Z",
        }
    ]


class TestStixExporter:
    def test_build_bundle(self, sample_iocs, sample_emails):
        exporter = StixExporter()
        bundle = exporter.build_bundle(iocs=sample_iocs, emails=sample_emails)

        assert bundle.type == "bundle"
        raw_json = bundle.serialize()
        data = json.loads(raw_json)

        assert "objects" in data
        types = [obj["type"] for obj in data["objects"]]

        assert "identity" in types
        assert "indicator" in types
        assert "observed-data" in types
        assert "relationship" in types

        # Check Indicator patterns
        indicators = [obj for obj in data["objects"] if obj["type"] == "indicator"]
        assert len(indicators) == len(sample_iocs)
        patterns = [ind["pattern"] for ind in indicators]
        assert any("ipv4-addr:value = '198.51.100.10'" in p for p in patterns)
        assert any("domain-name:value = 'phish-bank.com'" in p for p in patterns)
        assert any("file:hashes.'SHA-256'" in p for p in patterns)

    def test_export_to_file(self, tmp_path, sample_iocs, sample_emails):
        exporter = StixExporter()
        out_file = tmp_path / "stix_bundle.json"
        res_path = exporter.export_to_file(out_file, iocs=sample_iocs, emails=sample_emails)

        assert res_path.is_file()
        content = json.loads(res_path.read_text(encoding="utf-8"))
        assert content["type"] == "bundle"


class TestMispExporter:
    def test_build_event(self, sample_iocs, sample_emails):
        exporter = MispExporter(org_name="SOC DFIR")
        misp_data = exporter.build_event(iocs=sample_iocs, emails=sample_emails, event_info="Phishing Campaign Alpha")

        assert "Event" in misp_data
        event = misp_data["Event"]
        assert event["info"] == "Phishing Campaign Alpha"
        assert event["Org"]["name"] == "SOC DFIR"

        attrs = event["Attribute"]
        assert len(attrs) >= len(sample_iocs)

        types = [a["type"] for a in attrs]
        values = [a["value"] for a in attrs]

        assert "ip-dst" in types
        assert "domain" in types
        assert "url" in types
        assert "sha256" in types
        assert "198.51.100.10" in values
        assert "phish-bank.com" in values

    def test_export_to_file(self, tmp_path, sample_iocs):
        exporter = MispExporter()
        out_file = tmp_path / "misp_event.json"
        res_path = exporter.export_to_file(out_file, iocs=sample_iocs)

        assert res_path.is_file()
        content = json.loads(res_path.read_text(encoding="utf-8"))
        assert "Event" in content


class TestReportExporter:
    def test_generate_html_report(self, sample_iocs, sample_emails):
        exporter = ReportExporter(analyst_name="Jane Doe", organization="Cyber Defense Corp")
        html_doc = exporter.generate_html_report(
            incident_title="Spearphishing BEC Investigation",
            emails=sample_emails,
            iocs=sample_iocs,
        )

        assert "<!DOCTYPE html>" in html_doc
        assert "Spearphishing BEC Investigation" in html_doc
        assert "Jane Doe" in html_doc
        assert "Cyber Defense Corp" in html_doc
        assert "Executive Summary" in html_doc
        assert "Indicators of Compromise" in html_doc
        assert "Explainable Risk Score Breakdowns" in html_doc
        assert "MITRE ATT&CK Enterprise Matrix" in html_doc
        assert "Chain of Custody" in html_doc
        assert "urgent_invoice.eml" in html_doc
        assert "a" * 64 in html_doc

    def test_export_html_file(self, tmp_path, sample_iocs, sample_emails):
        exporter = ReportExporter()
        out_file = tmp_path / "report.html"
        exporter.export_html(out_file, incident_title="Test Incident", emails=sample_emails, iocs=sample_iocs)
        assert out_file.is_file()
        assert out_file.stat().st_size > 1000

    def test_export_pdf_file(self, tmp_path, sample_iocs, sample_emails):
        exporter = ReportExporter(analyst_name="Forensic Custodian")
        out_file = tmp_path / "report.pdf"
        exporter.export_pdf(out_file, incident_title="PDF Investigation Test", emails=sample_emails, iocs=sample_iocs)
        assert out_file.is_file()
        assert out_file.stat().st_size > 500
        # Check PDF Magic Header %PDF-
        with open(out_file, "rb") as fh:
            magic = fh.read(4)
            assert magic == b"%PDF"
