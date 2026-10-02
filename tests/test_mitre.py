"""
tests/test_mitre.py
Unit tests for core/mapping/mitre_attack.py.

Tests cover:
- Loading the YAML mapping file
- Single tag lookup
- Multi-tag lookup with deduplication
- Unknown tags return empty
- All techniques enumeration
- Missing / empty YAML file handling
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from core.mapping.mitre_attack import MitreMapper, Technique


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mitre_yaml(tmp_path: Path) -> Path:
    """Write a small test MITRE map YAML and return the path."""
    yaml_file = tmp_path / "mitre_map.yaml"
    yaml_file.write_text(textwrap.dedent("""\
        phishing_attachment:
          technique_id: "T1566.001"
          name: "Phishing: Spear-phishing Attachment"
          tactic: "Initial Access"
          description: "Email contains a malicious attachment."

        phishing_link:
          technique_id: "T1566.002"
          name: "Phishing: Spear-phishing Link"
          tactic: "Initial Access"
          description: "Email contains a suspicious URL."

        macro_execution:
          technique_id: "T1059.005"
          name: "Command and Scripting Interpreter: Visual Basic"
          tactic: "Execution"
          description: "Macro-enabled document."

        spf_failure:
          technique_id: "T1586.002"
          name: "Compromise Accounts: Email Accounts"
          tactic: "Resource Development"
          description: "SPF check failed."

        masquerading:
          technique_id: "T1036"
          name: "Masquerading"
          tactic: "Defence Evasion"
          description: "Sender impersonation detected."
    """))
    return yaml_file


@pytest.fixture
def mapper(mitre_yaml: Path) -> MitreMapper:
    return MitreMapper(yaml_path=mitre_yaml)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestMitreMapper:
    def test_lookup_single_tag(self, mapper: MitreMapper) -> None:
        results = mapper.lookup(["phishing_attachment"])
        assert len(results) == 1
        t = results[0]
        assert t.technique_id == "T1566.001"
        assert t.tactic == "Initial Access"
        assert t.behaviour_tag == "phishing_attachment"

    def test_lookup_multiple_tags(self, mapper: MitreMapper) -> None:
        results = mapper.lookup(["phishing_attachment", "macro_execution", "spf_failure"])
        assert len(results) == 3
        ids = {t.technique_id for t in results}
        assert "T1566.001" in ids
        assert "T1059.005" in ids
        assert "T1586.002" in ids

    def test_lookup_unknown_tag(self, mapper: MitreMapper) -> None:
        results = mapper.lookup(["unknown_tag"])
        assert len(results) == 0

    def test_lookup_mixed_known_unknown(self, mapper: MitreMapper) -> None:
        results = mapper.lookup(["phishing_link", "nonexistent_tag"])
        assert len(results) == 1
        assert results[0].technique_id == "T1566.002"

    def test_lookup_deduplicates_same_tag(self, mapper: MitreMapper) -> None:
        results = mapper.lookup(["masquerading", "masquerading"])
        assert len(results) == 1

    def test_lookup_empty_tags(self, mapper: MitreMapper) -> None:
        results = mapper.lookup([])
        assert len(results) == 0

    def test_lookup_single_method(self, mapper: MitreMapper) -> None:
        t = mapper.lookup_single("macro_execution")
        assert t is not None
        assert t.technique_id == "T1059.005"

    def test_lookup_single_missing(self, mapper: MitreMapper) -> None:
        assert mapper.lookup_single("nope") is None

    def test_all_techniques(self, mapper: MitreMapper) -> None:
        all_t = mapper.all_techniques()
        assert len(all_t) == 5

    def test_all_tags(self, mapper: MitreMapper) -> None:
        tags = mapper.all_tags()
        assert "phishing_attachment" in tags
        assert "masquerading" in tags

    def test_missing_yaml(self, tmp_path: Path) -> None:
        mapper = MitreMapper(yaml_path=tmp_path / "nonexistent.yaml")
        assert mapper.lookup(["phishing_attachment"]) == []

    def test_empty_yaml(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.yaml"
        empty.write_text("")
        mapper = MitreMapper(yaml_path=empty)
        assert mapper.all_techniques() == []


class TestTechniqueModel:
    def test_frozen(self) -> None:
        t = Technique(
            technique_id="T1234",
            name="Test",
            tactic="Test Tactic",
            description="desc",
            behaviour_tag="tag",
        )
        assert t.technique_id == "T1234"
        with pytest.raises(AttributeError):
            t.technique_id = "T9999"  # type: ignore[misc]


class TestRealMitreMap:
    """Test against the actual data/mitre_map.yaml file."""

    def test_loads_real_file(self) -> None:
        mapper = MitreMapper()  # uses default data/ path
        real_map = Path(__file__).resolve().parent.parent / "data" / "mitre_map.yaml"
        if not real_map.exists():
            pytest.skip("data/mitre_map.yaml not present")

        tags = mapper.all_tags()
        assert len(tags) > 0, "Real mitre_map.yaml should have tags"

        # Spot check a few expected tags
        assert "phishing_attachment" in tags
        assert "spf_failure" in tags

        # Spot check a lookup
        results = mapper.lookup(["phishing_attachment"])
        assert len(results) == 1
        assert results[0].technique_id == "T1566.001"
