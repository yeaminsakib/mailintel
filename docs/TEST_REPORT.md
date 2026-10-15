# MailIntel Comprehensive QA & Verification Test Report

## 1. Test Environment
- **Operating System**: Microsoft Windows 11 (64-bit)
- **Shell**: PowerShell 7 / Windows PowerShell
- **Python**: 3.14.7 (Virtual environment `.venv` located at `S:\Computer\Project\MailIntel\.venv`)
- **UI Framework**: PyQt6 (6.11.0) & PyQt6-WebEngine (6.11.0), Qt Runtime 6.11.2
- **Testing Tools**: `pytest` 9.1.1, `pytest-cov` 7.1.0, `pytest-qt` 4.5.0, `responses` 0.26.3
- **Project Location**: `S:\Computer\Project\MailIntel`

---

## 2. Test Execution & Results Summary

| Check / Requirement | Status | Details |
|---|:---:|---|
| **PEP 621 / Setuptools Packaging** | **FIXED** | Configured `license = "MIT"` as string and explicit `[tool.setuptools.packages.find]` (include `app*`, `core*`; exclude test/evaluation/data dirs; py-modules `cli`, `main`). |
| **Clean Virtual Environment & Editable Install** | **PASS** | Created fresh `.venv`, executed `pip install -e .[dev]` with zero build errors. Generated `requirements.txt`. |
| **Full Module Imports Resolution** | **PASS** | Verified dynamic import across all 48 modules in `app`, `core`, `cli`, and root entry points with 0 failures. |
| **.gitignore Protections** | **FIXED** | Verified `case_log/`, `test_emails/`, `*.db`, `.env`, `keys`, `keys/`, `*.key`, `__pycache__`, and `*.egg-info/` are strictly ignored. |
| **Automated Test Suite (pytest)** | **PASS** | 308 automated tests executed, **308 passed, 0 failed** in 14.38s. |
| **Code Coverage Target (>= 70%)** | **PASS** | Total repository code coverage: **87%** (all modules >= 71%, including `app/theme.py` 100%, `app/workers.py` 94%, `cli/main.py` 95%, `core/enrichment/keys.py` 100%, `core/enrichment/rdap.py` 97%). |
| **Safe Synthetic Fixtures Generation** | **PASS** | Generated 12 synthetic test `.eml` files in `tests/fixtures/` covering phishing link, base64, QP, HTML hrefs, attachment with verified hashes, auth failures, reply-to mismatch, multi-hop Received chain, lookalikes, malformed, empty, and duplicate files. |
| **CLI Scan & Indicator Extraction** | **PASS** | Successfully extracted IPs, domains, URLs, and attachment hashes (`dbfd9305...`, `822c8388...`, `86064fc9...`) matching expected decoded bytes. |
| **Deduplication on Rescan** | **PASS** | Rescanning folder leaves DB row count unchanged at 11 records (duplicate email properly deduplicated). |
| **Private IP & Whitelist Filtering** | **PASS** | Filtered internal RFC 1918 hops (`10.0.1.5`, `192.168.1.10`) while accurately identifying the oldest external hop (`89.160.20.156`). |
| **Auth Results (SPF/DKIM/DMARC) Parsing** | **PASS** | Correctly parsed `spf=fail`, `dkim=fail`, `dmarc=fail` from `Authentication-Results` into structured fields. |
| **Malformed & Empty File Resilience** | **PASS** | Zero crashes when scanning 0-byte (`11_empty.eml`) and malformed binary (`10_corrupted_malformed.eml`) files. |
| **Multi-Format Intelligence Export** | **PASS** | Verified cumulative export for STIX 2.1 bundle, MISP event JSON, HTML report, PDF report, and CSV indicators. |
| **Risk Scoring & Lookalike Detection** | **FIXED** | Risk scorer produces explainable factor breakdown. Updated lookalike detector to check URL hostnames, correctly flagging `paypa1.com` as masquerading PayPal. |
| **Enrichment Resilience (HTTP Mocked)** | **PASS** | Tested 200 OK success, 404 not found, 429 rate limit (exponential backoff), timeout, and invalid/missing API keys. Cache hits verified; no unhandled crashes. |
| **GUI Dashboard Launch & Empty State** | **PASS** | `DashboardWindow` starts with real empty counts (`0` emails, `0` IOCs, `0` high risk, `0` cases), no placeholder mock numbers. |
| **GUI Scan & Live Progress Feedback** | **PASS** | `ScanWorker` runs in a background `QThread`, updates progress bar, keeps UI responsive, supports cancellation, and updates SQLite tables. |
| **GUI Search & Table Filtering** | **PASS** | Dynamic text filtering in `search_bar` queries SQLite and updates displayed table rows in real-time. |
| **GUI Config Connectivity Test** | **PASS** | "Test" button makes real HTTP request to provider API and displays real result (verified error reporting with deliberately invalid API key). |

---

## 3. Bugs Discovered & Root Cause Fixes

### Bug 1: Setuptools Flat-Layout Auto-Discovery Failure & TOML Deprecation
- **Symptom**: `pip install -e .` failed with `Multiple top-level packages discovered in a flat-layout: ['app', 'cli', 'core', 'data', 'Project', 'scratch', 'case_log', 'evaluation', 'test_emails']` and deprecation warning on `project.license`.
- **Root Cause**: Flat folder layout lacked explicit package discovery rules in `pyproject.toml`, and `license` was defined as a table `{text = "MIT"}` instead of an SPDX string.
- **Fix**: Configured `license = "MIT"` as string and added:
  ```toml
  [tool.setuptools.packages.find]
  where = ["."]
  include = ["app*", "core*"]
  exclude = ["tests*", "evaluation*", "data*", "case_log*", "test_emails*", "scratch*", "Project*"]

  [tool.setuptools]
  py-modules = ["cli", "main"]
  ```
- **Files Modified**: `pyproject.toml`, created `cli.py`.

### Bug 2: Missing Root CLI Entry Point
- **Symptom**: Invoking `python cli.py scan ...` failed because `cli` existed only as a directory with `main.py`, without a root module.
- **Root Cause**: `pyproject.toml` declared `py-modules = ["cli", "main"]`, but `cli.py` was absent.
- **Fix**: Created `cli.py` in root delegating directly to `cli.main.app`.
- **Files Modified**: `cli.py`.

### Bug 3: Windows Console Unicode Encoding Crash (`\u2713`)
- **Symptom**: Running `python cli.py scan ...` on Windows PowerShell crashed with `UnicodeEncodeError: 'charmap' codec can't encode character '\u2713'`.
- **Root Cause**: Default Windows console stdout uses code page cp1252, which cannot encode unicode checkmarks (`✓`) printed by Rich console output.
- **Fix**: Added Windows standard stream reconfiguration (`sys.stdout.reconfigure(encoding="utf-8", errors="replace")`) upon CLI startup.
- **Files Modified**: `cli/main.py`.

### Bug 4: Lookalike Domain Detection Restricted to Bare Domain IOCs
- **Symptom**: Phishing emails containing lookalike URLs (e.g. `http://paypa1.com/restore-access`) were not scored for typosquatting/homoglyph attack because the extracted IOC was type `url`, and `_score_lookalike` only checked `ioc_type == "domain"`.
- **Root Cause**: Hostname extraction was omitted in `score_ioc` for `url` IOC types.
- **Fix**: Extended `score_ioc` to extract the domain component when `ioc_type == "url"` and apply brand lookalike / typosquat analysis.
- **Files Modified**: `core/scoring/risk_score.py`.

### Bug 5: Incomplete Git Exclusions
- **Symptom**: Build artifacts (`*.egg-info/`, `build/`, `dist/`) and credential/key files (`keys/`, `*.key`, `*.pem`) were not excluded from git.
- **Root Cause**: Missing entries in `.gitignore`.
- **Fix**: Appended rules to `.gitignore` and verified via `git check-ignore`.
- **Files Modified**: `.gitignore`.

---

## 4. Remaining Known Items & Manual Steps to Verify

1. **Live Threat Intelligence Provider API Keys**:
   - The test suite verified provider handling using mocked responses and deliberate invalid keys.
   - **Manual step**: In the GUI **Config** tab, input genuine API keys (for VirusTotal, AbuseIPDB, AlienVault OTX) and click **Save Key** then **Test** to test live external network connectivity against your specific provider account quotas.
2. **Interactive GUI Exploration**:
   - Run `python main.py`.
   - Click **Select .eml Folder & Analyze** and pick `tests\fixtures`.
   - Observe live progress bar, table population, and navigate across **Cases**, **Graph** (interactive PyVis network), **Intel**, and **Config** tabs.
