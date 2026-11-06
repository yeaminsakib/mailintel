"""
cli/main.py
Typer-based CLI for MailIntel.
Provides headless operations for scanning email folders, enriching indicators,
and exporting intelligence in STIX 2.1, MISP, CSV, JSON, HTML, and PDF formats.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

# Ensure UTF-8 output encoding on Windows consoles
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from core.correlation.campaign_clustering import CampaignClusterer
from core.enrichment.manager import EnrichmentManager
from core.export.misp_exporter import MispExporter
from core.export.report_exporter import ReportExporter
from core.export.stix_exporter import StixExporter
from core.ioc.defang import defang
from core.scoring.risk_score import RiskScorer
from core.storage.database import Database
from core.storage.export import export_csv_all
from core.storage.scan import MAX_EML_BYTES, FileProblem, discover_eml_files, scan_folder

app = typer.Typer(
    name="mailintel",
    help="MailIntel - Email DFIR & Threat Intelligence Command-Line Interface",
    add_completion=False,
)
console = Console()
logger = logging.getLogger("mailintel.cli")


def _print_problems(problems: list[FileProblem], *, skipped: int = 0, failed: int = 0, show: int = 10) -> None:
    """Print which files were not ingested and why (nothing is dropped silently)."""
    if not problems:
        return
    table = Table(title=f"Files not ingested ({len(problems)})", border_style="yellow")
    table.add_column("Kind", style="yellow", no_wrap=True)
    table.add_column("File")
    table.add_column("Reason")
    for problem in problems[:show]:
        table.add_row(problem.kind, problem.name, problem.reason)
    console.print(table)
    if len(problems) > show:
        console.print(f"[dim]... and {len(problems) - show} more[/dim]")
    if skipped or failed:
        console.print(f"[yellow]{skipped} skipped (empty / too large), {failed} failed.[/yellow]")


@app.command()
def scan(
    folder: Path = typer.Argument(
        ...,
        help="Path to folder containing .eml files to analyze",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
    ),
    enrich: bool = typer.Option(
        False,
        "--enrich",
        "-e",
        help="Run live threat intelligence enrichment on extracted indicators",
    ),
    export: str | None = typer.Option(
        None,
        "--export",
        "-x",
        help="Export format: 'stix', 'misp', 'html', 'pdf', 'csv', 'all'",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output destination file or directory for exported artifacts",
    ),
    db_path: Path | None = typer.Option(
        None,
        "--db",
        help="Custom SQLite database file path (defaults to mailintel.db)",
    ),
    analyst: str = typer.Option(
        "SOC Analyst",
        "--analyst",
        "-a",
        help="Analyst custodian name for chain-of-custody and reports",
    ),
    limit: int = typer.Option(
        0,
        "--limit",
        "-l",
        help="Limit number of .eml files to scan (0 = all)",
    ),
    recursive: bool = typer.Option(
        True,
        "--recursive/--no-recursive",
        help="Also scan sub-folders (default) or only the given folder",
    ),
    max_size_mb: float = typer.Option(
        MAX_EML_BYTES / 1_048_576,
        "--max-size-mb",
        min=0.001,
        help="Skip .eml files larger than this many MB (protects memory)",
    ),
) -> None:
    """Scan and parse a directory of .eml email messages for threat intelligence."""
    console.print(
        Panel.fit(
            "[bold cyan]MailIntel[/bold cyan] [bold white]DFIR & Threat Intelligence Engine[/bold white]\n"
            f"[dim]Analyzing target folder: {folder}[/dim]",
            border_style="cyan",
        )
    )

    # 1. Discover .eml files (recursive by default, case-insensitive, symlinks not followed)
    problems: list[FileProblem] = []
    eml_files = discover_eml_files(folder, recursive=recursive, limit=limit, problems=problems)

    total_files = len(eml_files)
    if total_files == 0:
        console.print(f"[yellow]No .eml files found in {folder}[/yellow]")
        _print_problems(problems)
        return

    console.print(f"[green]Found {total_files:,} .eml files to process.[/green]")

    # 2. Database connection (batched commits: one fsync per 100 files)
    target_db = Database(db_path, commit_interval=100) if db_path else Database(commit_interval=100)

    # 3. Scan & Ingest
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total})"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Ingesting emails...", total=total_files)
        report = scan_folder(
            folder,
            target_db,
            files=eml_files,
            max_file_bytes=int(max_size_mb * 1024 * 1024),
            progress=lambda current, total, name: progress.update(task, completed=current),
        )
        progress.update(task, completed=total_files)

    report.problems = problems + report.problems
    processed_email_ids = report.email_ids
    scanned_count = report.emails_read

    # 4. Fetch IOCs and summary metrics
    iocs_map = target_db.get_iocs_for_emails(processed_email_ids)
    all_iocs_dict: dict[str, dict] = {}
    for ioc_list in iocs_map.values():
        for ioc in ioc_list:
            key = f"{ioc['type']}:{ioc['value']}"
            all_iocs_dict[key] = ioc
    iocs_list = list(all_iocs_dict.values())

    console.print(
        f"[bold green]✓ Ingestion Complete:[/bold green] {scanned_count:,} emails processed "
        f"({report.new_emails:,} new, {report.duplicates:,} already stored), "
        f"{len(iocs_list):,} unique IOCs extracted."
    )
    if report.problems:
        _print_problems(report.problems, skipped=report.skipped, failed=report.failed)

    # 5. Enrichment (Optional)
    if enrich and iocs_list:
        console.print("[cyan]Running threat intelligence enrichment...[/cyan]")
        manager = EnrichmentManager(target_db)
        enriched_count = 0
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
        ) as progress:
            task_enr = progress.add_task("[cyan]Querying feeds...", total=len(iocs_list))
            for ioc in iocs_list:
                try:
                    ioc_id = int(ioc.get("id") or 0)
                    res = manager.enrich_ioc(ioc_id, ioc["type"], ioc["value"])
                    if res:
                        enriched_count += 1
                except Exception:
                    pass
                progress.update(task_enr, advance=1)
        console.print(f"[bold green]✓ Enriched {enriched_count:,} indicators across feeds.[/bold green]")

    # 6. Campaign Clustering
    scorer = RiskScorer()
    clusterer = CampaignClusterer(risk_scorer=scorer)
    db_emails = [target_db.get_email_with_iocs(eid) for eid in processed_email_ids if eid]
    campaigns = clusterer.cluster_emails(db_emails, iocs_map)
    if clusterer.last_truncated:
        console.print(
            f"[yellow]Clustering covered the {clusterer.max_emails:,} most recent emails; "
            f"{clusterer.last_truncated:,} older ones were left out (memory cap).[/yellow]"
        )

    # 7. Print Terminal Summary Table
    table = Table(title="Top Correlated Threat Indicators", border_style="cyan")
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Defanged Indicator", style="white")
    table.add_column("Risk Score", justify="right", style="bold")
    table.add_column("Severity", style="bold")
    table.add_column("Frequency", justify="right")

    for ioc in sorted(iocs_list, key=lambda x: int(x.get("frequency") or 1), reverse=True)[:15]:
        itype = ioc.get("type", "")
        val = ioc.get("value", "")
        freq = int(ioc.get("frequency") or 1)
        score_res = scorer.score_ioc(itype, val, frequency=freq)
        sev = (
            "CRITICAL" if score_res.score >= 75
            else "HIGH" if score_res.score >= 50
            else "MEDIUM" if score_res.score >= 25
            else "LOW"
        )
        sev_color = "red" if sev == "CRITICAL" else "yellow" if sev == "HIGH" else "green"
        table.add_row(
            itype.upper(),
            defang(val),
            f"{score_res.score:.1f}",
            f"[{sev_color}]{sev}[/{sev_color}]",
            f"{freq}x",
        )
    console.print(table)
    console.print(f"[dim]Total Campaigns Clustered: {len(campaigns)}[/dim]\n")

    # 8. Export Handling
    if export:
        export_fmt = export.lower().strip()
        out_dest = output or Path("exports")
        _perform_export(
            export_fmt=export_fmt,
            output_path=out_dest,
            iocs=iocs_list,
            emails=db_emails,
            campaigns=campaigns,
            analyst=analyst,
            db=target_db,
        )

    target_db.close()


def _perform_export(
    export_fmt: str,
    output_path: Path,
    iocs: list[dict],
    emails: list[dict],
    campaigns: list,
    analyst: str,
    db: Database,
) -> None:
    """Helper to route and execute export format requests."""
    out_dir = output_path if output_path.suffix == "" else output_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    incident_title = f"MailIntel DFIR Scan ({len(emails)} emails)"

    if export_fmt in ("stix", "stix2", "all"):
        stix_file = output_path if output_path.suffix == ".json" else out_dir / "mailintel_bundle_stix2.1.json"
        stix_exp = StixExporter()
        stix_exp.export_to_file(stix_file, iocs=iocs, emails=emails)
        console.print(f"[bold green]✓ Exported STIX 2.1 Bundle:[/bold green] {stix_file}")

    if export_fmt in ("misp", "all"):
        misp_file = output_path if output_path.suffix == ".json" else out_dir / "mailintel_misp_event.json"
        misp_exp = MispExporter()
        misp_exp.export_to_file(misp_file, iocs=iocs, emails=emails, event_info=incident_title)
        console.print(f"[bold green]✓ Exported MISP Event JSON:[/bold green] {misp_file}")

    if export_fmt in ("html", "all"):
        html_file = output_path if output_path.suffix == ".html" else out_dir / "incident_report.html"
        rep_exp = ReportExporter(analyst_name=analyst)
        rep_exp.export_html(html_file, incident_title=incident_title, emails=emails, iocs=iocs, campaigns=campaigns)
        console.print(f"[bold green]✓ Exported HTML Incident Report:[/bold green] {html_file}")

    if export_fmt in ("pdf", "all"):
        pdf_file = output_path if output_path.suffix == ".pdf" else out_dir / "incident_report.pdf"
        rep_exp = ReportExporter(analyst_name=analyst)
        rep_exp.export_pdf(pdf_file, incident_title=incident_title, emails=emails, iocs=iocs, campaigns=campaigns)
        console.print(f"[bold green]✓ Exported PDF Incident Report:[/bold green] {pdf_file}")

    if export_fmt in ("csv", "all"):
        csv_file = output_path if output_path.suffix == ".csv" else out_dir / "mailintel_iocs.csv"
        export_csv_all(db, str(csv_file))
        console.print(f"[bold green]✓ Exported CSV Indicators:[/bold green] {csv_file}")


@app.command()
def report(
    format: str = typer.Option("html", "--format", "-f", help="Report format: 'html' or 'pdf'"),
    output: Path = typer.Option(Path("incident_report.html"), "--output", "-o", help="Output path"),
    title: str = typer.Option("MailIntel DFIR Incident Investigation", "--title", "-t", help="Report title"),
    analyst: str = typer.Option("SOC DFIR Analyst", "--analyst", "-a", help="Lead analyst name"),
    db_path: Path | None = typer.Option(None, "--db", help="Database file path"),
) -> None:
    """Generate an incident report directly from the existing database."""
    target_db = Database(db_path) if db_path else Database()
    emails = target_db.get_recent_emails(limit=50)
    eids = [e["id"] for e in emails]
    iocs_map = target_db.get_iocs_for_emails(eids)

    all_iocs = {}
    for i_list in iocs_map.values():
        for i in i_list:
            all_iocs[f"{i['type']}:{i['value']}"] = i

    clusterer = CampaignClusterer()
    campaigns = clusterer.cluster_emails(emails, iocs_map)
    if clusterer.last_truncated:
        console.print(
            f"[yellow]Clustering covered the {clusterer.max_emails:,} most recent emails; "
            f"{clusterer.last_truncated:,} older ones were left out (memory cap).[/yellow]"
        )

    rep_exp = ReportExporter(analyst_name=analyst)
    if format.lower() == "pdf":
        out = rep_exp.export_pdf(output, incident_title=title, emails=emails, iocs=list(all_iocs.values()), campaigns=campaigns)
        console.print(f"[bold green]✓ Generated PDF Report:[/bold green] {out}")
    else:
        out = rep_exp.export_html(output, incident_title=title, emails=emails, iocs=list(all_iocs.values()), campaigns=campaigns)
        console.print(f"[bold green]✓ Generated HTML Report:[/bold green] {out}")

    target_db.close()


@app.command()
def evaluate(
    size: int = typer.Option(100, "--size", "-s", help="Corpus sample size"),
    output: Path = typer.Option(Path("evaluation/output"), "--output", "-o", help="Output directory for reports and plots"),
    plots: bool = typer.Option(True, "--plots/--no-plots", help="Generate publication-grade Matplotlib plots"),
) -> None:
    """Run empirical evaluation harness over labelled corpus (phishing_pot vs SpamAssassin ham)."""
    from evaluation.run_evaluation import run_pipeline
    run_pipeline(corpus_size=size, output_dir=output, generate_plots=plots)


if __name__ == "__main__":
    app()
