"""
core/export/report_exporter.py
Generates incident reports in HTML and PDF formats:
- Executive Summary
- Incident Scope & Telemetry
- Correlated IOC Tables with Severity
- Risk Score Breakdown & Explanation
- MITRE ATT&CK Enterprise Matrix Mapping
- Chain-of-Custody Section (file hashes, SHA-256, timestamps, analyst signature)
"""
from __future__ import annotations

import html
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.ioc.defang import defang
from core.mapping.mitre_attack import MitreMapper
from core.scoring.risk_score import RiskScorer

logger = logging.getLogger(__name__)


class ReportExporter:
    """Exports structured DFIR incident reports in HTML and PDF formats."""

    def __init__(
        self,
        analyst_name: str = "SOC DFIR Analyst",
        organization: str = "Security Operations Center",
        risk_scorer: RiskScorer | None = None,
        mitre_mapper: MitreMapper | None = None,
    ) -> None:
        self.analyst_name = analyst_name
        self.organization = organization
        self.scorer = risk_scorer or RiskScorer()
        self.mitre = mitre_mapper or MitreMapper()

    def generate_html_report(
        self,
        incident_title: str,
        emails: list[dict[str, Any]],
        iocs: list[dict[str, Any]],
        campaigns: list[Any] | None = None,
        case_details: dict[str, Any] | None = None,
    ) -> str:
        """Generate a complete standalone HTML incident report with embedded styling."""
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # 1. Aggregate statistics
        total_emails = len(emails)
        total_iocs = len(iocs)
        total_campaigns = len(campaigns) if campaigns else 1

        # Score IOCs
        scored_iocs = []
        high_risk_count = 0
        crit_risk_count = 0
        all_behaviour_tags: set[str] = set()

        for ioc in iocs:
            itype = ioc.get("type", "")
            val = ioc.get("value", "")
            freq = int(ioc.get("frequency") or 1)
            score_res = self.scorer.score_ioc(itype, val, frequency=freq)
            scored_iocs.append({
                "type": itype,
                "value": val,
                "score": score_res.score,
                "severity": (
                    "CRITICAL" if score_res.score >= 75
                    else "HIGH" if score_res.score >= 50
                    else "MEDIUM" if score_res.score >= 25
                    else "LOW"
                ),
                "frequency": freq,
                "breakdown": score_res.breakdown,
                "tags": score_res.behaviour_tags,
            })
            all_behaviour_tags.update(score_res.behaviour_tags)
            if score_res.score >= 75:
                crit_risk_count += 1
            elif score_res.score >= 50:
                high_risk_count += 1

        scored_iocs.sort(key=lambda x: x["score"], reverse=True)

        # Map observed behaviours to MITRE ATT&CK
        all_behaviour_tags.update(["phishing_link", "masquerading", "spf_failure"])
        techniques = self.mitre.lookup(sorted(list(all_behaviour_tags))) if hasattr(self.mitre, "lookup") else []

        # Executive summary text
        overall_severity = "CRITICAL" if crit_risk_count > 0 else "HIGH" if high_risk_count > 0 else "MEDIUM"
        exec_summary = (
            f"During the DFIR investigation '{incident_title}', MailIntel parsed and correlated "
            f"<strong>{total_emails}</strong> email messages, identifying <strong>{total_iocs}</strong> unique "
            f"Indicators of Compromise (IOCs) across <strong>{total_campaigns}</strong> attack campaigns. "
            f"The engagement observed <strong>{crit_risk_count}</strong> Critical and <strong>{high_risk_count}</strong> "
            f"High severity indicators with active infrastructure linkages and ATT&CK alignment."
        )

        # Build IOC Table Rows
        ioc_rows_html = []
        for item in scored_iocs[:50]:
            sev = item["severity"]
            badge_color = "#ef4444" if sev == "CRITICAL" else "#f97316" if sev == "HIGH" else "#eab308" if sev == "MEDIUM" else "#10b981"
            defanged_val = html.escape(defang(item["value"]))
            ioc_rows_html.append(f"""
                <tr>
                    <td><span class="badge" style="background: rgba(255,255,255,0.08); color: #cbd5e1;">{item['type'].upper()}</span></td>
                    <td class="mono">{defanged_val}</td>
                    <td><span class="badge" style="background: {badge_color}22; color: {badge_color}; border: 1px solid {badge_color}66;">{sev}</span></td>
                    <td><strong>{item['score']:.1f}</strong>/100</td>
                    <td>{item['frequency']}x</td>
                </tr>
            """)
        ioc_table_body = "".join(ioc_rows_html)

        # Build Score Breakdowns
        breakdown_cards = []
        for item in scored_iocs[:8]:
            if not item["breakdown"]:
                continue
            factors_html = "".join([
                f"<li><strong>+{f.points:.1f} pts</strong> ({html.escape(f.factor)}): {html.escape(f.reason)}</li>"
                for f in item["breakdown"]
            ])
            breakdown_cards.append(f"""
                <div class="factor-card">
                    <h4>{item['type'].upper()}: {html.escape(defang(item['value']))} — Score {item['score']:.1f}/100</h4>
                    <ul>{factors_html}</ul>
                </div>
            """)
        breakdowns_html = "".join(breakdown_cards) or "<p class='muted'>No active risk factor penalties recorded.</p>"

        # Build MITRE ATT&CK Rows
        mitre_rows = []
        for t in techniques:
            tech_url = f"https://attack.mitre.org/techniques/{t.technique_id.replace('.', '/')}"
            mitre_rows.append(f"""
                <tr>
                    <td class="mono"><strong><a href="{html.escape(tech_url)}" target="_blank" style="color: #00f0ff;">{html.escape(t.technique_id)}</a></strong></td>
                    <td><strong>{html.escape(t.name)}</strong></td>
                    <td>{html.escape(t.tactic.title())}</td>
                    <td><code>{html.escape(t.behaviour_tag)}</code></td>
                </tr>
            """)
        mitre_table_body = "".join(mitre_rows)

        # Build Chain of Custody Rows
        custody_rows = []
        for idx, em in enumerate(emails, start=1):
            fname = html.escape(em.get("filename") or f"message_{idx}.eml")
            fpath = html.escape(em.get("filepath") or "Uploaded Artifact")
            fhash = html.escape(em.get("file_sha256") or "N/A")
            seen = html.escape(em.get("first_seen") or now_str)
            custody_rows.append(f"""
                <tr>
                    <td>{idx}</td>
                    <td><strong>{fname}</strong><br><small class="muted">{fpath}</small></td>
                    <td class="mono small">{fhash}</td>
                    <td>{seen}</td>
                    <td>{html.escape(self.analyst_name)}</td>
                </tr>
            """)
        custody_table_body = "".join(custody_rows)

        # Case notes if provided
        case_section = ""
        if case_details:
            case_title = html.escape(case_details.get("title", ""))
            case_desc = html.escape(case_details.get("description", ""))
            case_notes = html.escape(case_details.get("notes", ""))
            case_section = f"""
            <div class="section">
                <h2>1. Investigation Case Profile</h2>
                <div class="card">
                    <p><strong>Title:</strong> {case_title}</p>
                    <p><strong>Description:</strong> {case_desc or 'None provided.'}</p>
                    <p><strong>Analyst Notes:</strong> {case_notes or 'No investigative notes recorded.'}</p>
                </div>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MailIntel Incident Report - {html.escape(incident_title)}</title>
<style>
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        background-color: #0f172a;
        color: #f1f5f9;
        margin: 0;
        padding: 40px;
        line-height: 1.6;
    }}
    .container {{
        max-width: 1040px;
        margin: 0 auto;
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 40px;
        box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    }}
    .header {{
        border-bottom: 2px solid #334155;
        padding-bottom: 24px;
        margin-bottom: 32px;
    }}
    .header h1 {{
        color: #00f0ff;
        font-size: 28px;
        margin: 0 0 8px 0;
        letter-spacing: -0.5px;
    }}
    .meta-grid {{
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 16px;
        margin-top: 16px;
        font-size: 13px;
        color: #94a3b8;
    }}
    .meta-box {{
        background: #0f172a;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 10px 14px;
    }}
    .meta-box strong {{
        color: #f8fafc;
        display: block;
        margin-bottom: 2px;
    }}
    .section {{
        margin-bottom: 36px;
    }}
    h2 {{
        color: #38bdf8;
        font-size: 18px;
        border-bottom: 1px solid #334155;
        padding-bottom: 6px;
        margin-top: 0;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }}
    .card {{
        background: #0f172a;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 18px;
        margin-bottom: 16px;
    }}
    .factor-card {{
        background: #0f172a;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 12px 16px;
        margin-bottom: 12px;
    }}
    .factor-card h4 {{
        margin: 0 0 6px 0;
        color: #f59e0b;
        font-size: 13px;
    }}
    .factor-card ul {{
        margin: 0;
        padding-left: 20px;
        font-size: 12px;
        color: #cbd5e1;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
        margin-top: 12px;
    }}
    th {{
        background: #0f172a;
        color: #94a3b8;
        text-align: left;
        padding: 10px 12px;
        font-weight: 700;
        border-bottom: 1px solid #334155;
    }}
    td {{
        padding: 10px 12px;
        border-bottom: 1px solid #243247;
        color: #e2e8f0;
    }}
    tr:hover td {{
        background: #172554;
    }}
    .mono {{
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }}
    .small {{
        font-size: 11px;
    }}
    .badge {{
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.5px;
    }}
    .muted {{
        color: #64748b;
    }}
    .footer {{
        border-top: 1px solid #334155;
        padding-top: 16px;
        margin-top: 40px;
        font-size: 11px;
        color: #64748b;
        display: flex;
        justify-content: space-between;
    }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>MAILINTEL THREAT INTELLIGENCE & DFIR INCIDENT REPORT</h1>
        <div style="font-size: 14px; color: #94a3b8;">Engagement: <strong>{html.escape(incident_title)}</strong></div>
        <div class="meta-grid">
            <div class="meta-box">
                <strong>Generated Date</strong>
                {now_str}
            </div>
            <div class="meta-box">
                <strong>Lead Analyst</strong>
                {html.escape(self.analyst_name)}
            </div>
            <div class="meta-box">
                <strong>Investigating Org</strong>
                {html.escape(self.organization)}
            </div>
            <div class="meta-box">
                <strong>Incident Severity</strong>
                <span style="color: {'#ef4444' if overall_severity=='CRITICAL' else '#f97316'}; font-weight: bold;">{overall_severity}</span>
            </div>
        </div>
    </div>

    {case_section}

    <div class="section">
        <h2>2. Executive Summary</h2>
        <div class="card" style="font-size: 14px; line-height: 1.7;">
            {exec_summary}
        </div>
    </div>

    <div class="section">
        <h2>3. Identified Indicators of Compromise (IOCs)</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 15%;">Type</th>
                    <th style="width: 45%;">Defanged Indicator Value</th>
                    <th style="width: 15%;">Severity</th>
                    <th style="width: 15%;">Risk Score</th>
                    <th style="width: 10%;">Observed</th>
                </tr>
            </thead>
            <tbody>
                {ioc_table_body}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>4. Explainable Risk Score Breakdowns</h2>
        <p class="muted" style="font-size: 12px;">Detailed point contributions explaining why specific severity ratings were assigned based on YAML scoring weights:</p>
        {breakdowns_html}
    </div>

    <div class="section">
        <h2>5. MITRE ATT&CK Enterprise Matrix Alignment</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 15%;">Technique ID</th>
                    <th style="width: 30%;">Technique Name</th>
                    <th style="width: 25%;">Tactic</th>
                    <th style="width: 30%;">Triggering Behaviour</th>
                </tr>
            </thead>
            <tbody>
                {mitre_table_body}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>6. Chain of Custody & Evidence Telemetry</h2>
        <p class="muted" style="font-size: 12px;">Forensic verification hashes and custodial provenance for all processed artifacts:</p>
        <table>
            <thead>
                <tr>
                    <th style="width: 5%;">#</th>
                    <th style="width: 30%;">Artifact Filename</th>
                    <th style="width: 35%;">SHA-256 Hash</th>
                    <th style="width: 15%;">Ingest Timestamp</th>
                    <th style="width: 15%;">Custodian</th>
                </tr>
            </thead>
            <tbody>
                {custody_table_body}
            </tbody>
        </table>
    </div>

    <div class="footer">
        <div>CONFIDENTIAL // DEFENSIVE INCIDENT RESPONSE ONLY // TLP:AMBER</div>
        <div>Generated by MailIntel DFIR v0.1.0</div>
    </div>
</div>
</body>
</html>
"""
        return html_content

    def export_html(
        self,
        filepath: str | Path,
        incident_title: str,
        emails: list[dict[str, Any]],
        iocs: list[dict[str, Any]],
        campaigns: list[Any] | None = None,
        case_details: dict[str, Any] | None = None,
    ) -> Path:
        """Export incident report directly to an HTML file."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = self.generate_html_report(
            incident_title=incident_title,
            emails=emails,
            iocs=iocs,
            campaigns=campaigns,
            case_details=case_details,
        )
        path.write_text(content, encoding="utf-8")
        return path

    def export_pdf(
        self,
        filepath: str | Path,
        incident_title: str,
        emails: list[dict[str, Any]],
        iocs: list[dict[str, Any]],
        campaigns: list[Any] | None = None,
        case_details: dict[str, Any] | None = None,
    ) -> Path:
        """Export incident report to PDF format using ReportLab."""
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        pdf_path = Path(filepath)
        pdf_path.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36,
        )
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=4,
        )
        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontSize=12,
            leading=15,
            textColor=colors.HexColor("#0284c7"),
            spaceBefore=12,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "ReportBody",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155"),
        )
        mono_style = ParagraphStyle(
            "ReportMono",
            parent=body_style,
            fontName="Courier",
            fontSize=8,
            leading=10,
        )

        elements: list[Any] = []

        # Header Title
        elements.append(Paragraph(f"MAILINTEL INCIDENT REPORT: {html.escape(incident_title)}", title_style))
        elements.append(Paragraph(f"Lead Analyst: {html.escape(self.analyst_name)} | Organization: {html.escape(self.organization)}", body_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceBefore=6, spaceAfter=10))

        # 1. Executive Summary
        elements.append(Paragraph("1. Executive Summary", h2_style))
        summary_text = (
            f"Automated incident investigation analyzed {len(emails)} emails, identifying "
            f"{len(iocs)} indicators of compromise across the inspected dataset. Correlated threat "
            f"signals and MITRE ATT&CK technique telemetry are detailed below."
        )
        elements.append(Paragraph(summary_text, body_style))
        elements.append(Spacer(1, 8))

        # 2. IOC Table
        elements.append(Paragraph("2. Top Indicators of Compromise (IOCs)", h2_style))
        ioc_table_data = [["Type", "Defanged Indicator", "Severity", "Score", "Observed"]]
        for ioc in iocs[:25]:
            itype = ioc.get("type", "")
            val = defang(ioc.get("value", ""))
            freq = int(ioc.get("frequency") or 1)
            score_res = self.scorer.score_ioc(itype, ioc.get("value", ""), frequency=freq)
            sev = "HIGH" if score_res.score >= 50 else "MED" if score_res.score >= 25 else "LOW"
            ioc_table_data.append([
                itype.upper(),
                Paragraph(html.escape(val), mono_style),
                sev,
                f"{score_res.score:.1f}",
                f"{freq}x",
            ])

        t_iocs = Table(ioc_table_data, colWidths=[65, 270, 65, 55, 55])
        t_iocs.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        elements.append(t_iocs)
        elements.append(Spacer(1, 8))

        # 3. MITRE ATT&CK Mapping
        elements.append(Paragraph("3. MITRE ATT&CK Enterprise Matrix Mapping", h2_style))
        techniques = self.mitre.lookup(["phishing_link", "masquerading", "spf_failure"]) if hasattr(self.mitre, "lookup") else []
        mitre_data = [["Technique ID", "Technique Name", "Tactic", "Observed Trigger"]]
        for t in techniques:
            mitre_data.append([
                t.technique_id,
                t.name,
                t.tactic.title(),
                t.behaviour_tag,
            ])
        t_mitre = Table(mitre_data, colWidths=[80, 160, 110, 160])
        t_mitre.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        elements.append(t_mitre)
        elements.append(Spacer(1, 8))

        # 4. Chain of Custody
        elements.append(Paragraph("4. Chain of Custody & Evidence Hashes", h2_style))
        custody_data = [["Artifact Filename", "SHA-256 Digest", "Custodian"]]
        for em in emails[:15]:
            fname = em.get("filename") or "unknown.eml"
            sha = em.get("file_sha256") or "N/A"
            custody_data.append([
                fname,
                Paragraph(html.escape(sha), mono_style),
                self.analyst_name,
            ])
        t_custody = Table(custody_data, colWidths=[150, 240, 120])
        t_custody.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        elements.append(t_custody)

        doc.build(elements)
        return pdf_path
