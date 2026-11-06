"""
tests/test_scan.py
Folder scanning shared by the GUI worker and the CLI (core/storage/scan.py),
plus the places that use it: ScanWorker, the CLI and the clustering cap.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from app.workers import ScanWorker
from cli.main import app as cli_app
from core.correlation import CampaignClusterer
from core.parser.models import ParsedEmail
from core.storage import scan as scan_module
from core.storage.database import Database
from core.storage.scan import (
    EMPTY,
    ERROR,
    TOO_LARGE,
    UNREADABLE,
    discover_eml_files,
    scan_folder,
)


def _eml(path: Path, n: int = 1, body: str | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = body if body is not None else f"Visit http://evil{n}.org/login now"
    path.write_text(
        f"From: sender{n}@evil{n}.org\nTo: victim@corp.com\nSubject: Test {n}\n\n{text}\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def db() -> Database:
    database = Database(":memory:")
    yield database
    database.close()


# ---------------------------------------------------------------------------
# discover_eml_files
# ---------------------------------------------------------------------------

class TestDiscover:
    def test_recursive_by_default_and_sorted(self, tmp_path: Path) -> None:
        _eml(tmp_path / "b.eml", 1)
        _eml(tmp_path / "sub" / "a.eml", 2)
        _eml(tmp_path / "sub" / "deep" / "c.eml", 3)
        found = discover_eml_files(tmp_path)
        assert len(found) == 3
        assert found == sorted(found, key=lambda p: str(p).lower())

    def test_non_recursive_only_top_level(self, tmp_path: Path) -> None:
        _eml(tmp_path / "top.eml", 1)
        _eml(tmp_path / "sub" / "nested.eml", 2)
        assert [p.name for p in discover_eml_files(tmp_path, recursive=False)] == ["top.eml"]

    def test_extension_match_is_case_insensitive_and_exact(self, tmp_path: Path) -> None:
        _eml(tmp_path / "UPPER.EML", 1)
        _eml(tmp_path / "Mixed.Eml", 2)
        (tmp_path / "notes.txt").write_text("x", encoding="utf-8")
        (tmp_path / "mail.eml.bak").write_text("x", encoding="utf-8")
        (tmp_path / "eml").write_text("x", encoding="utf-8")
        assert sorted(p.name for p in discover_eml_files(tmp_path)) == ["Mixed.Eml", "UPPER.EML"]

    def test_limit(self, tmp_path: Path) -> None:
        for i in range(5):
            _eml(tmp_path / f"m{i}.eml", i)
        assert len(discover_eml_files(tmp_path, limit=2)) == 2

    def test_missing_folder_is_reported_not_raised(self, tmp_path: Path) -> None:
        problems: list = []
        assert discover_eml_files(tmp_path / "nope", problems=problems) == []
        assert problems and problems[0].kind == UNREADABLE

    def test_symlinked_folders_are_not_followed(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        _eml(real / "a.eml", 1)
        link = tmp_path / "scan" / "link"
        link.parent.mkdir()
        try:
            os.symlink(real, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not available on this system")
        assert discover_eml_files(tmp_path / "scan") == []


# ---------------------------------------------------------------------------
# scan_folder
# ---------------------------------------------------------------------------

class TestScanFolder:
    def test_new_then_duplicate_on_rescan(self, tmp_path: Path, db: Database) -> None:
        _eml(tmp_path / "a.eml", 1)
        _eml(tmp_path / "sub" / "b.eml", 2)
        first = scan_folder(tmp_path, db)
        assert (first.files_found, first.new_emails, first.duplicates) == (2, 2, 0)
        second = scan_folder(tmp_path, db)
        assert (second.new_emails, second.duplicates) == (0, 2)
        assert db.get_email_count() == 2
        assert all(i["frequency"] == 1 for i in db.get_all_iocs())   # rescan does not inflate counts

    def test_identical_content_under_two_names_is_a_duplicate(self, tmp_path: Path, db: Database) -> None:
        _eml(tmp_path / "a.eml", 1)
        _eml(tmp_path / "copy_of_a.eml", 1)
        report = scan_folder(tmp_path, db)
        assert (report.new_emails, report.duplicates) == (1, 1)
        assert db.get_email_count() == 1

    def test_empty_file_is_skipped_and_reported(self, tmp_path: Path, db: Database) -> None:
        _eml(tmp_path / "ok.eml", 1)
        (tmp_path / "empty.eml").write_bytes(b"")
        report = scan_folder(tmp_path, db)
        assert (report.new_emails, report.skipped, report.failed) == (1, 1, 0)
        assert [p.kind for p in report.problems] == [EMPTY]
        assert report.problems[0].name == "empty.eml"

    def test_oversized_file_is_skipped_without_being_read(self, tmp_path: Path, db: Database, monkeypatch) -> None:
        big = _eml(tmp_path / "big.eml", 1, body="x" * 5000)
        _eml(tmp_path / "small.eml", 2)
        read_paths: list[str] = []
        real_parse = scan_module.parse_eml_file

        def spy(path):
            read_paths.append(Path(path).name)
            return real_parse(path)

        monkeypatch.setattr(scan_module, "parse_eml_file", spy)
        report = scan_folder(tmp_path, db, max_file_bytes=1000)
        assert report.skipped == 1 and report.new_emails == 1
        assert report.problems[0].kind == TOO_LARGE and "limit" in report.problems[0].reason
        assert big.name not in read_paths           # never opened
        assert read_paths == ["small.eml"]

    def test_unreadable_file_is_a_failure(self, tmp_path: Path, db: Database, monkeypatch) -> None:
        _eml(tmp_path / "a.eml", 1)
        monkeypatch.setattr(scan_module, "parse_eml_file", lambda p: ParsedEmail(filepath=str(p)))
        report = scan_folder(tmp_path, db)
        assert (report.failed, report.new_emails) == (1, 0)
        assert report.problems[0].kind == UNREADABLE

    def test_one_failing_file_does_not_stop_the_scan(self, tmp_path: Path, db: Database, monkeypatch) -> None:
        for i in (1, 2, 3):
            _eml(tmp_path / f"m{i}.eml", i)
        real_ingest = scan_module.ingest_parsed_email

        def flaky(parsed, database, whitelist=None):
            if parsed.filepath.endswith("m2.eml"):
                raise RuntimeError("boom")
            return real_ingest(parsed, database, whitelist)

        monkeypatch.setattr(scan_module, "ingest_parsed_email", flaky)
        report = scan_folder(tmp_path, db)
        assert (report.new_emails, report.failed) == (2, 1)
        problem = report.problems[0]
        assert problem.kind == ERROR and "boom" in problem.reason and problem.name == "m2.eml"

    def test_progress_and_cancel(self, tmp_path: Path, db: Database) -> None:
        for i in range(4):
            _eml(tmp_path / f"m{i}.eml", i)
        seen: list[tuple[int, int, str]] = []
        report = scan_folder(
            tmp_path, db,
            progress=lambda cur, tot, name: seen.append((cur, tot, name)),
            should_cancel=lambda: len(seen) >= 2,
        )
        assert report.cancelled
        assert [s[0] for s in seen] == [1, 2] and all(s[1] == 4 for s in seen)
        assert report.new_emails == 2          # what was processed is kept

    def test_report_counts_add_up_and_serialise(self, tmp_path: Path, db: Database) -> None:
        _eml(tmp_path / "a.eml", 1)
        (tmp_path / "z.eml").write_bytes(b"")
        report = scan_folder(tmp_path, db)
        assert report.files_processed == report.files_found == 2
        data = report.to_dict()
        assert data["emails_new"] == 1 and data["files_skipped"] == 1 and data["problems_total"] == 1
        assert data["problems"][0]["kind"] == EMPTY

    def test_problem_list_in_dict_is_capped_but_total_is_kept(self, tmp_path: Path, db: Database) -> None:
        for i in range(5):
            (tmp_path / f"e{i}.eml").write_bytes(b"")
        data = scan_folder(tmp_path, db).to_dict(max_problems=2)
        assert len(data["problems"]) == 2 and data["problems_total"] == 5

    def test_real_fixtures(self, db: Database) -> None:
        fixtures = Path(__file__).parent / "fixtures"
        report = scan_folder(fixtures, db)
        assert report.files_found >= 11
        assert report.new_emails + report.duplicates + report.skipped + report.failed == report.files_found
        assert any(p.kind == EMPTY for p in report.problems)        # 11_empty.eml


# ---------------------------------------------------------------------------
# ScanWorker (GUI thread wrapper)
# ---------------------------------------------------------------------------

class TestScanWorker:
    def _run(self, folder: Path, db_path: Path, **kw) -> dict:
        worker = ScanWorker(str(folder), db_path=str(db_path), **kw)
        results: list[dict] = []
        worker.finished.connect(results.append)
        worker.run()
        assert len(results) == 1
        return results[0]

    def test_scans_subfolders_and_reports_problems(self, tmp_path: Path) -> None:
        scan_dir = tmp_path / "mail"
        _eml(scan_dir / "top.eml", 1)
        _eml(scan_dir / "inbox" / "nested.eml", 2)
        (scan_dir / "inbox" / "empty.eml").write_bytes(b"")
        result = self._run(scan_dir, tmp_path / "w.db")
        assert result["emails_new"] == 2
        assert result["files_skipped"] == 1 and result["files_failed"] == 0
        assert result["problems_total"] == 1 and result["problems"][0]["name"] == "empty.eml"
        assert result["iocs_found"] > 0

    def test_non_recursive_option(self, tmp_path: Path) -> None:
        scan_dir = tmp_path / "mail"
        _eml(scan_dir / "top.eml", 1)
        _eml(scan_dir / "inbox" / "nested.eml", 2)
        assert self._run(scan_dir, tmp_path / "w.db", recursive=False)["emails_new"] == 1

    def test_rescan_reports_duplicates(self, tmp_path: Path) -> None:
        scan_dir = tmp_path / "mail"
        _eml(scan_dir / "a.eml", 1)
        db_path = tmp_path / "w.db"
        self._run(scan_dir, db_path)
        second = self._run(scan_dir, db_path)
        assert (second["emails_new"], second["emails_duplicate"], second["iocs_found"]) == (0, 1, 0)

    def test_size_limit_option(self, tmp_path: Path) -> None:
        scan_dir = tmp_path / "mail"
        _eml(scan_dir / "a.eml", 1, body="y" * 4000)
        result = self._run(scan_dir, tmp_path / "w.db", max_file_bytes=500)
        assert result["files_skipped"] == 1 and result["emails_new"] == 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestCliScan:
    runner = CliRunner()

    def _invoke(self, folder: Path, db_file: Path, *extra: str):
        return self.runner.invoke(cli_app, ["scan", str(folder), "--db", str(db_file), *extra])

    def test_recursive_by_default_and_counts_new_vs_duplicate(self, tmp_path: Path) -> None:
        mail = tmp_path / "mail"
        _eml(mail / "a.eml", 1)
        _eml(mail / "sub" / "b.eml", 2)
        db_file = tmp_path / "c.db"
        first = self._invoke(mail, db_file)
        assert first.exit_code == 0
        assert "Found 2 .eml files" in first.stdout and "2 new, 0 already stored" in first.stdout
        second = self._invoke(mail, db_file)
        assert "0 new, 2 already stored" in second.stdout

    def test_no_recursive_flag(self, tmp_path: Path) -> None:
        mail = tmp_path / "mail"
        _eml(mail / "a.eml", 1)
        _eml(mail / "sub" / "b.eml", 2)
        result = self._invoke(mail, tmp_path / "c.db", "--no-recursive")
        assert "Found 1 .eml files" in result.stdout

    def test_problem_table_is_printed(self, tmp_path: Path) -> None:
        mail = tmp_path / "mail"
        _eml(mail / "a.eml", 1)
        (mail / "empty.eml").write_bytes(b"")
        result = self._invoke(mail, tmp_path / "c.db")
        assert result.exit_code == 0
        assert "Files not ingested" in result.stdout and "empty.eml" in result.stdout
        assert "1 skipped" in result.stdout

    def test_max_size_option(self, tmp_path: Path) -> None:
        mail = tmp_path / "mail"
        _eml(mail / "a.eml", 1, body="z" * 5000)
        result = self._invoke(mail, tmp_path / "c.db", "--max-size-mb", "0.001")
        assert "too_large" in result.stdout


# ---------------------------------------------------------------------------
# Clustering cap
# ---------------------------------------------------------------------------

class TestClusteringCap:
    def _emails(self, n: int) -> list[dict]:
        return [
            {"id": i, "filename": f"{i}.eml",
             "headers_json": {"subject": "Same subject for all", "from_addr": "a@x.org"},
             "first_hop_ip": "198.51.100.7"}
            for i in range(1, n + 1)
        ]

    def test_only_most_recent_emails_are_clustered(self) -> None:
        clusterer = CampaignClusterer(max_emails=3)
        campaigns = clusterer.cluster_emails(self._emails(5), {})
        assert clusterer.last_truncated == 2
        clustered = {eid for c in campaigns for eid in c.email_ids}
        assert clustered <= {3, 4, 5}

    def test_no_truncation_below_the_cap_and_cap_can_be_disabled(self) -> None:
        small = CampaignClusterer(max_emails=10)
        small.cluster_emails(self._emails(5), {})
        assert small.last_truncated == 0
        unlimited = CampaignClusterer(max_emails=0)
        unlimited.cluster_emails(self._emails(5), {})
        assert unlimited.last_truncated == 0

    def test_default_cap_is_2000(self) -> None:
        assert CampaignClusterer().max_emails == 2000
