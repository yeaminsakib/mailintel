"""
tests/test_cli.py
Tests for Typer CLI commands (scan, report, export options).
"""
from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "MailIntel" in result.stdout
    assert "scan" in result.stdout
    assert "report" in result.stdout


def test_cli_scan_help():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--enrich" in result.stdout
    assert "--export" in result.stdout


def test_cli_scan_sample_eml(tmp_path: Path):
    # Create sample eml file
    eml_file = tmp_path / "sample.eml"
    eml_file.write_text(
        "From: attacker@malicious-domain.com\n"
        "To: victim@company.com\n"
        "Subject: Urgent Invoice Required\n"
        "Date: Mon, 12 Oct 2026 10:00:00 +0000\n"
        "Message-ID: <test-123@malicious-domain.com>\n\n"
        "Please check this link: http://evil-phishing.org/login and download file.\n",
        encoding="utf-8",
    )

    db_file = tmp_path / "test_cli.db"
    out_dir = tmp_path / "exports"

    # Scan with STIX export
    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--db",
            str(db_file),
            "--export",
            "stix",
            "--output",
            str(out_dir),
            "--analyst",
            "Test Analyst",
        ],
    )
    assert result.exit_code == 0
    assert "Ingestion Complete" in result.stdout
    assert "Top Correlated Threat Indicators" in result.stdout

    # Verify stix file created
    exported_stix = out_dir / "mailintel_bundle_stix2.1.json"
    assert exported_stix.exists()
    content = exported_stix.read_text(encoding="utf-8")
    assert '"type": "bundle"' in content


def test_cli_scan_and_report_export(tmp_path: Path):
    eml_file = tmp_path / "urgent.eml"
    eml_file.write_text(
        "From: admin@spoofed.com\n"
        "To: user@company.com\n"
        "Subject: Security Notice\n\n"
        "Visit http://192.168.1.50/update immediately.\n",
        encoding="utf-8",
    )

    db_file = tmp_path / "test_report.db"
    out_html = tmp_path / "report.html"

    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--db",
            str(db_file),
            "--export",
            "html",
            "--output",
            str(out_html),
        ],
    )
    assert result.exit_code == 0
    assert out_html.exists()
    html_text = out_html.read_text(encoding="utf-8")
    assert "MailIntel DFIR Incident Investigation" in html_text or "MailIntel" in html_text


def test_cli_scan_empty_folder(tmp_path: Path):
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    result = runner.invoke(app, ["scan", str(empty_dir)])
    assert result.exit_code == 0
    assert "No .eml files found" in result.stdout


def test_cli_scan_limit_and_all_exports(tmp_path: Path):
    eml_file1 = tmp_path / "test1.eml"
    eml_file1.write_text("From: a@b.com\nTo: c@d.com\nSubject: Test 1\n\nLink: http://phish.net\n", encoding="utf-8")
    eml_file2 = tmp_path / "test2.eml"
    eml_file2.write_text("From: e@f.com\nTo: g@h.com\nSubject: Test 2\n\nLink: http://malware.org\n", encoding="utf-8")

    db_file = tmp_path / "limit_test.db"
    out_dir = tmp_path / "all_exports"

    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--db",
            str(db_file),
            "--limit",
            "1",
            "--export",
            "all",
            "--output",
            str(out_dir),
        ],
    )
    assert result.exit_code == 0
    assert (out_dir / "mailintel_bundle_stix2.1.json").exists()
    assert (out_dir / "mailintel_misp_event.json").exists()
    assert (out_dir / "incident_report.html").exists()
    assert (out_dir / "incident_report.pdf").exists()
    assert (out_dir / "mailintel_iocs.csv").exists()


def test_cli_scan_with_enrichment_mocked(tmp_path: Path):
    from unittest.mock import MagicMock, patch

    eml = tmp_path / "enrich_test.eml"
    eml.write_text("From: alert@phish.org\nSubject: test\n\nURL: https://bad-actor.org\n", encoding="utf-8")
    db_file = tmp_path / "enrich_test.db"

    with patch("cli.main.EnrichmentManager") as mock_mgr_cls:
        mock_instance = MagicMock()
        mock_instance.enrich_ioc.return_value = MagicMock()
        mock_mgr_cls.return_value = mock_instance

        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--db", str(db_file), "--enrich"],
        )
        assert result.exit_code == 0
        assert "Enriched" in result.stdout or "Running threat intelligence enrichment" in result.stdout


def test_cli_report_command(tmp_path: Path):
    from core.parser.eml_parser import parse_eml_file
    from core.storage.database import Database
    from core.storage.ingest import ingest_parsed_email

    eml = tmp_path / "report_sample.eml"
    eml.write_text("From: alert@bank.com\nSubject: Statement\n\nhttp://evil-bank.com\n", encoding="utf-8")
    db_file = tmp_path / "report_cli.db"

    db = Database(db_file)
    parsed = parse_eml_file(eml)
    ingest_parsed_email(parsed, db)
    db.close()

    html_out = tmp_path / "report_cmd.html"
    res_html = runner.invoke(app, ["report", "--db", str(db_file), "-f", "html", "-o", str(html_out)])
    assert res_html.exit_code == 0
    assert html_out.exists()

    pdf_out = tmp_path / "report_cmd.pdf"
    res_pdf = runner.invoke(app, ["report", "--db", str(db_file), "-f", "pdf", "-o", str(pdf_out)])
    assert res_pdf.exit_code == 0
    assert pdf_out.exists()
